package cli

// Connection dry-run tests live here: OIDC discovery against a test issuer
// passes without SP material, while SAML refuses to run without the exact
// SP identity the server presents.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"keyway/internal/connection"
	"keyway/internal/tenant"
)

func TestConnectionTestPaths(t *testing.T) {
	store := testCLIStore(t)
	ctx := context.Background()
	if err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	discovery := &oidctest.Server{PublicKeys: []oidctest.PublicKey{
		{PublicKey: priv.Public(), KeyID: "k", Algorithm: gooidc.RS256},
	}}
	httpSrv := httptest.NewServer(discovery)
	t.Cleanup(httpSrv.Close)
	discovery.SetIssuer(httpSrv.URL)

	if _, err := ConnectionAdd(store, ConnectionAddParams{TenantID: "acme",
		Type: connection.ConnectionTypeOIDC, IssuerURL: httpSrv.URL,
		ClientID: "c1", EmailClaim: "email"}); err != nil {
		t.Fatalf("ConnectionAdd: %v", err)
	}
	conns, err := ConnectionList(store, "acme")
	if err != nil || !strings.Contains(conns, "oidc") {
		t.Fatalf("ConnectionList = %q, %v", conns, err)
	}
	var id string
	for _, line := range strings.Split(conns, "\n") {
		id = strings.SplitN(line, "\t", 2)[0]
	}
	if out, err := ConnectionTest(store, id, SPTestParams{}); err != nil {
		t.Fatalf("OIDC test: %v", err)
	} else if !strings.Contains(out, "discovery ok") {
		t.Errorf("output = %q", out)
	}

	if _, err := ConnectionTest(store, "nope", SPTestParams{}); err == nil {
		t.Errorf("unknown connection: expected rejection, got nil error")
	}
}

func TestSAMLTestRefusesWithoutSPIdentity(t *testing.T) {
	store := testCLIStore(t)
	ctx := context.Background()
	if err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if _, err := ConnectionAdd(store, ConnectionAddParams{TenantID: "acme",
		Type: connection.ConnectionTypeSAML, MetadataXML: "<EntityDescriptor/>", EmailClaim: "email"}); err != nil {
		t.Fatalf("ConnectionAdd: %v", err)
	}
	conns, _ := store.ListConnectionsByTenant(ctx, "acme")
	if _, err := ConnectionTest(store, conns[0].ID, SPTestParams{}); err == nil {
		t.Errorf("SAML without SP flags: expected rejection, got nil error")
	}
	if _, err := LoadKeyPair("/nonexistent-key", ""); err == nil {
		t.Errorf("half identity: expected rejection, got nil error")
	}
	pair, err := LoadKeyPair("", "")
	if err != nil {
		t.Fatalf("ephemeral: %v", err)
	}
	if !pair.Ephemeral {
		t.Errorf("blank paths: want ephemeral identity")
	}
}
