package flow

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"keyway/internal/normalize"
)

// CodeTTL bounds how long an issued code waits for the /token exchange.
const CodeTTL = 60 * time.Second

// AuthCode is the single-use proof that one login completed.
//
// WHY this struct exists: it carries the already-verified Identity from the
// callback to the /token exchange, so the exchange never re-contacts the
// IdP. The code itself is 32 random bytes; knowledge of it is the only
// credential, which is why consumption must be atomic and exactly once.
type AuthCode struct {
	// Code is the random redemption secret handed to the application.
	Code string

	// TenantID scopes the code to the customer it was issued for.
	TenantID string

	// Identity is the verified, normalized user this login proved.
	Identity normalize.Identity

	// RedirectURI binds redemption to the callback the login started with.
	RedirectURI string

	// ExpiresAt enforces the short redemption window; CreatedAt anchors audits.
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewAuthCode mints a single-use code for one completed login, expiring
// now plus CodeTTL.
func NewAuthCode(tenantID string, identity normalize.Identity, redirectURI string, now time.Time) (AuthCode, error) {
	if tenantID == "" || redirectURI == "" {
		return AuthCode{}, fmt.Errorf("flow: new auth code: tenant and redirect URI are required")
	}
	if identity.Email == "" {
		return AuthCode{}, fmt.Errorf("flow: new auth code: identity has no email")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return AuthCode{}, fmt.Errorf("flow: new auth code: %w", err)
	}
	return AuthCode{
		Code:        hex.EncodeToString(raw),
		TenantID:    tenantID,
		Identity:    identity,
		RedirectURI: redirectURI,
		ExpiresAt:   now.Add(CodeTTL),
		CreatedAt:   now,
	}, nil
}
