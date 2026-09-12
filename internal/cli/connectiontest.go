package cli

import (
	"context"
	"fmt"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/oidc"
	"keyway/internal/saml"
)

// SPTestParams carries the SP identity a SAML dry-run validates against.
// Every field is required for SAML: the test must use the exact identity
// the running server presents, so an ephemeral substitute is refused rather
// than silently validating against a throwaway.
type SPTestParams struct {
	EntityID string
	ACSURL   string
	KeyPath  string
	CertPath string
}

// ConnectionTest dry-runs one stored connection: SAML metadata parses under
// the given SP identity, OIDC discovery reaches the live issuer.
func ConnectionTest(store flow.Storage, id string, sp SPTestParams) (string, error) {
	ctx := context.Background()
	conn, err := store.GetConnection(ctx, id)
	if err != nil {
		return "", fmt.Errorf("cli: connection test: %w", err)
	}
	switch conn.Type {
	case connection.ConnectionTypeOIDC:
		if _, err := oidc.NewAdapter(ctx, conn, oidc.DefaultDiscover); err != nil {
			return "", fmt.Errorf("cli: connection test: %w", err)
		}
		return fmt.Sprintf("connection %q: OIDC discovery ok", id), nil
	case connection.ConnectionTypeSAML:
		pair, err := spIdentity(sp)
		if err != nil {
			return "", err
		}
		if _, err := saml.NewAdapter(conn, saml.SPConfig{
			EntityID:    sp.EntityID,
			MetadataURL: sp.EntityID + "/metadata",
			ACSURL:      sp.ACSURL,
			Key:         pair.Key,
			Certificate: pair.Certificate,
		}); err != nil {
			return "", fmt.Errorf("cli: connection test: %w", err)
		}
		return fmt.Sprintf("connection %q: SAML metadata ok", id), nil
	default:
		return "", fmt.Errorf("cli: connection test: connection %q has unknown type %q", id, conn.Type)
	}
}

// spIdentity resolves the SP identity for a SAML dry-run, refusing anything
// but the operator's real files: an ephemeral key here would validate
// metadata against an identity the server never presents, letting the test
// pass while the real login fails.
func spIdentity(sp SPTestParams) (KeyPair, error) {
	if sp.EntityID == "" || sp.ACSURL == "" || sp.KeyPath == "" || sp.CertPath == "" {
		return KeyPair{}, fmt.Errorf("cli: connection test: SAML tests require --sp-entity-id, --sp-acs-url, --sp-key, and --sp-cert matching the running server")
	}
	pair, err := LoadKeyPair(sp.KeyPath, sp.CertPath)
	if err != nil {
		return KeyPair{}, err
	}
	if pair.Ephemeral {
		return KeyPair{}, fmt.Errorf("cli: connection test: refusing ephemeral SP identity for a SAML test")
	}
	return pair, nil
}
