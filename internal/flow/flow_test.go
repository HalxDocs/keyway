package flow

import (
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/normalize"
)

func TestNewAuthRequestValidation(t *testing.T) {
	now := time.Now()
	if _, err := NewAuthRequest("acme", "conn-1", connection.ConnectionTypeOIDC, "state-1", "", "", "https://app/cb", now); err == nil {
		t.Errorf("OIDC without nonce: expected rejection, got nil error")
	}
	if _, err := NewAuthRequest("acme", "conn-1", connection.ConnectionTypeSAML, "relay-1", "", "", "https://app/cb", now); err == nil {
		t.Errorf("SAML without request ID: expected rejection, got nil error")
	}
	if _, err := NewAuthRequest("acme", "conn-1", "kerberos", "s", "", "", "https://app/cb", now); err == nil {
		t.Errorf("unknown protocol: expected rejection, got nil error")
	}

	oidc, err := NewAuthRequest("acme", "conn-1", connection.ConnectionTypeOIDC, "state-1", "nonce-1", "", "https://app/cb", now)
	if err != nil {
		t.Fatalf("valid OIDC request: %v", err)
	}
	if oidc.ID == "" || !oidc.ExpiresAt.After(now) {
		t.Errorf("OIDC request missing ID or expiry: %+v", oidc)
	}

	saml, err := NewAuthRequest("acme", "conn-1", connection.ConnectionTypeSAML, "relay-1", "", "req-1", "https://app/cb", now)
	if err != nil {
		t.Fatalf("valid SAML request: %v", err)
	}
	if saml.SAMLRequestID != "req-1" {
		t.Errorf("SAML request ID = %q, want req-1", saml.SAMLRequestID)
	}
}

func TestNewAuthCodeValidation(t *testing.T) {
	now := time.Now()
	identity := normalize.Identity{Email: "ada@example.com", Name: "Ada"}
	code, err := NewAuthCode("acme", identity, "https://app/cb", now)
	if err != nil {
		t.Fatalf("valid code: %v", err)
	}
	if len(code.Code) != 64 || !code.ExpiresAt.Equal(now.Add(CodeTTL)) {
		t.Errorf("code malformed: %+v", code)
	}
	if _, err := NewAuthCode("acme", normalize.Identity{}, "https://app/cb", now); err == nil {
		t.Errorf("empty identity: expected rejection, got nil error")
	}
}
