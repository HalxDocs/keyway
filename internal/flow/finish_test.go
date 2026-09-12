package flow_test

import (
	"context"
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
)

func TestFinishRejectsBeforeAdapters(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	seedTenant(t, store)
	seedOIDC(t, store, "conn-oidc", testOIDCIssuer(t))
	seedSAML(t, store, "conn-saml", testMetadata(t))
	svc := testService(t, store)

	now := time.Now()
	oidcReq, err := flow.NewAuthRequest(flow.NewAuthRequestParams{TenantID: "acme",
		ConnectionID: "conn-oidc", Protocol: connection.ConnectionTypeOIDC,
		State: "state-1", Nonce: "nonce-1", RedirectURI: "https://app.example/callback", Now: now})
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	if err := store.SaveAuthRequest(ctx, oidcReq); err != nil {
		t.Fatalf("SaveAuthRequest: %v", err)
	}
	samlReq, err := flow.NewAuthRequest(flow.NewAuthRequestParams{TenantID: "acme",
		ConnectionID: "conn-saml", Protocol: connection.ConnectionTypeSAML,
		State: "relay-1", SAMLRequestID: "req-1", RedirectURI: "https://app.example/callback", Now: now})
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	if err := store.SaveAuthRequest(ctx, samlReq); err != nil {
		t.Fatalf("SaveAuthRequest: %v", err)
	}

	if _, err := svc.FinishOIDC(ctx, "conn-oidc", "code", "no-such-state"); err == nil {
		t.Errorf("unknown state: expected rejection, got nil error")
	}
	if _, err := svc.FinishOIDC(ctx, "conn-oidc", "code", "relay-1"); err == nil {
		t.Errorf("SAML record on OIDC endpoint: expected rejection, got nil error")
	}
	if _, err := svc.FinishSAML(ctx, "conn-saml", "resp", "state-1"); err == nil {
		t.Errorf("OIDC record on SAML endpoint: expected rejection, got nil error")
	}
	if _, err := svc.FinishOIDC(ctx, "conn-saml", "code", "state-1"); err == nil {
		t.Errorf("cross-connection state: expected rejection, got nil error")
	}
	expired, err := flow.NewAuthRequest(flow.NewAuthRequestParams{TenantID: "acme",
		ConnectionID: "conn-oidc", Protocol: connection.ConnectionTypeOIDC,
		State: "state-old", Nonce: "nonce-old", RedirectURI: "https://app.example/callback",
		Now: now.Add(-11 * time.Minute)})
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	if err := store.SaveAuthRequest(ctx, expired); err != nil {
		t.Fatalf("SaveAuthRequest: %v", err)
	}
	if _, err := svc.FinishOIDC(ctx, "conn-oidc", "code", "state-old"); err == nil {
		t.Errorf("expired request: expected rejection, got nil error")
	}
}
