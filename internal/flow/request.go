// Package flow owns the unified login flow's ephemeral records.
//
// WHY this package exists: between /authorize and /token, Keyway must
// remember what each pending login demands back (the OIDC nonce or the SAML
// request ID and relay state) and what each issued code already proved (the
// verified Identity). One home for those records — and later the
// orchestration over them — keeps internal/api as thin HTTP glue.
package flow

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"keyway/internal/connection"
)

// RequestTTL bounds how long a pending login waits for the IdP callback.
const RequestTTL = 10 * time.Minute

// AuthRequest records one login Keyway started and is waiting to finish.
//
// WHY this struct exists: the callback must prove the returning response
// answers this exact request. The Protocol tag selects which check runs —
// nonce for OIDC, request ID plus relay state for SAML — so an empty field
// can never silently excuse a missing check the way "empty means N/A" would.
type AuthRequest struct {
	// ID is the internal handle for this pending login.
	ID string

	// TenantID and ConnectionID pin the login to one customer's IdP config.
	TenantID     string
	ConnectionID string

	// Protocol selects which replay-protection fields apply: saml or oidc.
	Protocol connection.ConnectionType

	// State is the opaque value sent through the IdP and back: RelayState
	// for SAML, the OAuth state parameter for OIDC.
	State string

	// Nonce is the OIDC nonce for this login. Required when Protocol is
	// oidc; an accidentally-empty nonce fails validation at creation.
	Nonce string

	// SAMLRequestID is the outgoing authentication request ID. Required
	// when Protocol is saml.
	SAMLRequestID string

	// RedirectURI is the application's callback that receives the code.
	RedirectURI string

	// ExpiresAt bounds the wait; CreatedAt anchors audit trails.
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewAuthRequest builds a validated pending login: the ID is generated, the
// expiry is derived from now plus RequestTTL, and the protocol's required
// replay-protection fields must be present or construction fails loudly.
func NewAuthRequest(tenantID, connectionID string, protocol connection.ConnectionType, state, nonce, samlRequestID, redirectURI string, now time.Time) (AuthRequest, error) {
	if tenantID == "" || connectionID == "" {
		return AuthRequest{}, fmt.Errorf("flow: new auth request: tenant and connection are required")
	}
	if protocol != connection.ConnectionTypeSAML && protocol != connection.ConnectionTypeOIDC {
		return AuthRequest{}, fmt.Errorf("flow: new auth request: unknown protocol %q", protocol)
	}
	if state == "" || redirectURI == "" {
		return AuthRequest{}, fmt.Errorf("flow: new auth request: state and redirect URI are required")
	}
	if protocol == connection.ConnectionTypeOIDC && nonce == "" {
		return AuthRequest{}, fmt.Errorf("flow: new auth request: OIDC logins require a nonce")
	}
	if protocol == connection.ConnectionTypeSAML && samlRequestID == "" {
		return AuthRequest{}, fmt.Errorf("flow: new auth request: SAML logins require a request ID")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return AuthRequest{}, fmt.Errorf("flow: new auth request: %w", err)
	}
	return AuthRequest{
		ID:            hex.EncodeToString(id),
		TenantID:      tenantID,
		ConnectionID:  connectionID,
		Protocol:      protocol,
		State:         state,
		Nonce:         nonce,
		SAMLRequestID: samlRequestID,
		RedirectURI:   redirectURI,
		ExpiresAt:     now.Add(RequestTTL),
		CreatedAt:     now,
	}, nil
}
