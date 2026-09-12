package flow_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/tenant"
)

func TestStartLoginRoutesByProtocol(t *testing.T) {
	ctx := context.Background()

	oidcStore := testStore(t)
	seedTenant(t, oidcStore)
	issuer := testOIDCIssuer(t)
	seedOIDC(t, oidcStore, "conn-oidc", issuer)
	oidcSvc := testService(t, oidcStore)
	loginURL, err := oidcSvc.StartLogin(ctx, "acme", "https://app.example/callback", "", "app-state")
	if err != nil {
		t.Fatalf("OIDC StartLogin: %v", err)
	}
	if !strings.Contains(loginURL, "state=") {
		t.Errorf("OIDC login URL missing state: %s", loginURL)
	}

	samlStore := testStore(t)
	seedTenant(t, samlStore)
	seedSAML(t, samlStore, "conn-saml", testMetadata(t))
	samlSvc := testService(t, samlStore)
	samlURL, err := samlSvc.StartLogin(ctx, "acme", "https://app.example/callback", "", "")
	if err != nil {
		t.Fatalf("SAML StartLogin: %v", err)
	}
	if !strings.Contains(samlURL, "idp.test") || !strings.Contains(samlURL, "SAMLRequest=") {
		t.Errorf("SAML login URL looks wrong: %s", samlURL)
	}
}

func TestStartLoginRejects(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	seedTenant(t, store)
	seedOIDC(t, store, "conn-1", testOIDCIssuer(t))
	svc := testService(t, store)

	cases := map[string]func() error{
		"unknown tenant": func() error {
			_, err := svc.StartLogin(ctx, "nope", "https://app.example/callback", "", "")
			return err
		},
		"unlisted redirect": func() error {
			_, err := svc.StartLogin(ctx, "acme", "https://evil.example/callback", "", "")
			return err
		},
		"unknown connection": func() error {
			_, err := svc.StartLogin(ctx, "acme", "https://app.example/callback", "nope", "")
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Errorf("%s: expected rejection, got nil error", name)
		}
	}

	other := tenant.Tenant{ID: "other", Name: "Other",
		AllowedRedirectURIs: []string{"https://app.example/callback"}, CreatedAt: time.Now()}
	if err := store.CreateTenant(ctx, other); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if _, err := svc.StartLogin(ctx, "other", "https://app.example/callback", "", ""); err == nil {
		t.Errorf("zero connections: expected rejection, got nil error")
	}

	seedOIDC(t, store, "conn-2", testOIDCIssuer(t))
	if _, err := svc.StartLogin(ctx, "acme", "https://app.example/callback", "", ""); err == nil {
		t.Errorf("ambiguous connections: expected rejection, got nil error")
	}

	disabled := connection.Connection{ID: "conn-off", TenantID: "other",
		Type:   connection.ConnectionTypeOIDC,
		OIDC:   &connection.OIDCConnectionConfig{IssuerURL: testOIDCIssuer(t), ClientID: "c"},
		Status: connection.ConnectionStatusDisabled, CreatedAt: time.Now()}
	if err := store.CreateConnection(ctx, disabled); err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	if _, err := svc.StartLogin(ctx, "other", "https://app.example/callback", "conn-off", ""); err == nil {
		t.Errorf("disabled connection: expected rejection, got nil error")
	}
}
