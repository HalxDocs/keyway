package flow_test

import (
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/normalize"
)

func TestNewAuthRequestValidation(t *testing.T) {
	now := time.Now()
	oidcParams := flow.NewAuthRequestParams{TenantID: "acme", ConnectionID: "conn-1",
		Protocol: connection.ConnectionTypeOIDC, State: "state-1", RedirectURI: "https://app/cb", Now: now}
	if _, err := flow.NewAuthRequest(oidcParams); err == nil {
		t.Errorf("OIDC without nonce: expected rejection, got nil error")
	}
	samlParams := flow.NewAuthRequestParams{TenantID: "acme", ConnectionID: "conn-1",
		Protocol: connection.ConnectionTypeSAML, State: "relay-1", RedirectURI: "https://app/cb", Now: now}
	if _, err := flow.NewAuthRequest(samlParams); err == nil {
		t.Errorf("SAML without request ID: expected rejection, got nil error")
	}
	badProtocol := samlParams
	badProtocol.Protocol = "kerberos"
	if _, err := flow.NewAuthRequest(badProtocol); err == nil {
		t.Errorf("unknown protocol: expected rejection, got nil error")
	}

	oidcParams.Nonce = "nonce-1"
	oidcParams.AppState = "app-1"
	oidc, err := flow.NewAuthRequest(oidcParams)
	if err != nil {
		t.Fatalf("valid OIDC request: %v", err)
	}
	if oidc.ID == "" || !oidc.ExpiresAt.After(now) {
		t.Errorf("OIDC request missing ID or expiry: %+v", oidc)
	}

	samlParams.SAMLRequestID = "req-1"
	saml, err := flow.NewAuthRequest(samlParams)
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
	code, err := flow.NewAuthCode("acme", identity, "https://app/cb", now)
	if err != nil {
		t.Fatalf("valid code: %v", err)
	}
	if len(code.Code) != 64 || !code.ExpiresAt.Equal(now.Add(flow.CodeTTL)) {
		t.Errorf("code malformed: %+v", code)
	}
	if _, err := flow.NewAuthCode("acme", normalize.Identity{}, "https://app/cb", now); err == nil {
		t.Errorf("empty identity: expected rejection, got nil error")
	}
}
