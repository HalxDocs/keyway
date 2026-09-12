package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"

	"keyway/internal/connection"
	"keyway/internal/normalize"
)

// Adapter verifies OIDC ID tokens for one connection and maps them to Identity.
//
// WHY this struct exists: verification must bind the issuer, audience, and
// attribute map from the same connection.Connection, so a token minted for
// tenant A can never be accepted or misread through tenant B's config. The
// struct holds the already-discovered provider and verifier because both
// are expensive to build and safe to reuse across logins.
type Adapter struct {
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	issuer     string
	clientID   string
	attributes connection.AttributeMap
}

// NewAdapter builds an Adapter for one OIDC connection.
//
// WHY a constructor instead of a bare struct literal: a half-configured
// adapter (wrong protocol type, missing issuer, no email mapping) must fail
// here, before serving logins, rather than returning empty identities at
// login time. The verifier is built with full issuer/audience/expiry/
// signature checks and nothing skipped.
func NewAdapter(ctx context.Context, conn connection.Connection, discover ProviderFunc) (*Adapter, error) {
	if conn.Type != connection.ConnectionTypeOIDC {
		return nil, fmt.Errorf("oidc: new adapter: connection %q is type %q, not oidc", conn.ID, conn.Type)
	}
	if conn.OIDC == nil {
		return nil, fmt.Errorf("oidc: new adapter: connection %q has no OIDC config", conn.ID)
	}
	if conn.OIDC.IssuerURL == "" || conn.OIDC.ClientID == "" {
		return nil, fmt.Errorf("oidc: new adapter: connection %q needs issuer URL and client ID", conn.ID)
	}
	if conn.AttributeMap.EmailClaim == "" {
		return nil, fmt.Errorf("oidc: new adapter: connection %q needs an email claim mapping", conn.ID)
	}
	provider, err := DiscoverProvider(ctx, conn.OIDC.IssuerURL, discover)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: conn.OIDC.ClientID})
	return &Adapter{
		provider:   provider,
		verifier:   verifier,
		issuer:     conn.OIDC.IssuerURL,
		clientID:   conn.OIDC.ClientID,
		attributes: conn.AttributeMap,
	}, nil
}

// VerifyToken verifies a raw ID token and maps it to a normalized Identity.
//
// WHY this method exists: it is the single seam where untrusted IdP output
// becomes trusted application input. Signature, issuer, audience, and expiry
// are checked by the verifier; nonce is checked strictly here because the
// library deliberately leaves nonce validation to the caller. Claims are
// read from the raw map by the connection's configured claim names, because
// IdPs never agree on field names and only the per-connection AttributeMap
// knows where this IdP puts email, name, and groups. The nonce rule is
// absolute: expectedNonce must be the non-empty value the authorize flow
// generated and stored, and any mismatch (including empty on either side)
// rejects, so a missing nonce can never degrade into an unchecked login.
func (a *Adapter) VerifyToken(ctx context.Context, rawIDToken string, expectedNonce string) (normalize.Identity, error) {
	if rawIDToken == "" {
		return normalize.Identity{}, fmt.Errorf("oidc: verify token: empty ID token")
	}
	if expectedNonce == "" {
		return normalize.Identity{}, fmt.Errorf("oidc: verify token: empty expected nonce")
	}
	token, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return normalize.Identity{}, fmt.Errorf("oidc: verify token: %w", err)
	}
	if token.Nonce != expectedNonce {
		return normalize.Identity{}, fmt.Errorf("oidc: verify token: nonce mismatch")
	}
	var raw map[string]any
	if err := token.Claims(&raw); err != nil {
		return normalize.Identity{}, fmt.Errorf("oidc: verify token: decode claims: %w", err)
	}
	email, err := claimString(raw, a.attributes.EmailClaim)
	if err != nil || email == "" {
		return normalize.Identity{}, fmt.Errorf("oidc: verify token: email claim %q missing or empty", a.attributes.EmailClaim)
	}
	name := ""
	if a.attributes.NameClaim != "" {
		name, _ = claimString(raw, a.attributes.NameClaim)
	}
	groups, err := claimGroups(raw, a.attributes.GroupsClaim)
	if err != nil {
		return normalize.Identity{}, fmt.Errorf("oidc: verify token: %w", err)
	}
	return normalize.Identity{
		Email:     email,
		Name:      name,
		Groups:    groups,
		RawClaims: normalize.RawClaims(raw),
	}, nil
}

// claimString reads one string claim by dynamic key. Missing keys yield "".
func claimString(raw map[string]any, key string) (string, error) {
	if key == "" {
		return "", nil
	}
	value, ok := raw[key]
	if !ok || value == nil {
		return "", nil
	}
	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("claim %q is not a string", key)
	}
	return str, nil
}

// claimGroups reads a groups claim that IdPs encode as array, single
// string, or absent. Absent yields nil; any non-string member fails closed.
func claimGroups(raw map[string]any, key string) ([]string, error) {
	if key == "" {
		return nil, nil
	}
	value, ok := raw[key]
	if !ok || value == nil {
		return nil, nil
	}
	switch members := value.(type) {
	case string:
		return []string{members}, nil
	case []string:
		return members, nil
	case []any:
		groups := make([]string, 0, len(members))
		for _, member := range members {
			str, ok := member.(string)
			if !ok {
				return nil, fmt.Errorf("claim %q contains a non-string group", key)
			}
			groups = append(groups, str)
		}
		return groups, nil
	default:
		return nil, fmt.Errorf("claim %q is not a string or string array", key)
	}
}
