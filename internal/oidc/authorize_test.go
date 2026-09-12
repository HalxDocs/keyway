package oidc

import (
	"context"
	"net/url"
	"testing"
)

func TestAuthCodeURLCarriesStateAndNonce(t *testing.T) {
	_, issuer, _ := testIssuer(t)
	ctx := context.Background()
	adapter := testAdapter(t, ctx, issuer, "keyway-test-client")

	loginURL := adapter.AuthCodeURL("state-1", "nonce-1", "https://keyway.test/callback/oidc/conn-1")
	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	query := parsed.Query()
	if query.Get("state") != "state-1" {
		t.Errorf("state = %q, want state-1", query.Get("state"))
	}
	if query.Get("nonce") != "nonce-1" {
		t.Errorf("nonce = %q, want nonce-1", query.Get("nonce"))
	}
	if query.Get("client_id") != "keyway-test-client" {
		t.Errorf("client_id = %q, want keyway-test-client", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://keyway.test/callback/oidc/conn-1" {
		t.Errorf("redirect_uri = %q", query.Get("redirect_uri"))
	}
}

func TestExchangeCodeRejects(t *testing.T) {
	_, issuer, _ := testIssuer(t)
	ctx := context.Background()
	adapter := testAdapter(t, ctx, issuer, "keyway-test-client")

	incomplete := TokenRequest{Code: "some-code"}
	if _, err := adapter.ExchangeCode(ctx, incomplete); err == nil {
		t.Errorf("incomplete request: expected rejection, got nil error")
	}

	full := TokenRequest{
		Code: "bogus-code", ClientID: "keyway-test-client",
		RedirectURL: "https://keyway.test/callback/oidc/conn-1", ClientSecret: "secret",
	}
	if _, err := adapter.ExchangeCode(ctx, full); err == nil {
		t.Errorf("bogus code: expected rejection, got nil error")
	}
}
