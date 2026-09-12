package flow_test

// Shared fixtures for flow tests live here: a temp-file store, a throwaway
// SP identity, and miniature IdPs per protocol. The OIDC issuer reuses the
// public oidctest server; the SAML metadata builder mirrors (not imports)
// the saml package's harness, which is intentionally not exported.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/secret"
	"keyway/internal/storage"
	"keyway/internal/tenant"
)

func testStore(t *testing.T) flow.Storage {
	t.Helper()
	key := make([]byte, secret.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	store, err := storage.NewSQLiteStore(filepath.Join(t.TempDir(), "flow.db"), box)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func testService(t *testing.T, store flow.Storage) *flow.Service {
	t.Helper()
	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate SP key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "flow-test-sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &spKey.PublicKey, spKey)
	if err != nil {
		t.Fatalf("create SP cert: %v", err)
	}
	spCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse SP cert: %v", err)
	}
	svc, err := flow.NewService(store, flow.Config{
		BaseURL: "https://keyway.test", SPEntityID: "https://keyway.test/sp",
		SPKey: spKey, SPCert: spCert,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// testOIDCIssuer spins the public oidctest discovery server.
func testOIDCIssuer(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := &oidctest.Server{PublicKeys: []oidctest.PublicKey{
		{PublicKey: priv.Public(), KeyID: "k", Algorithm: gooidc.RS256},
	}}
	httpSrv := httptest.NewServer(srv)
	t.Cleanup(httpSrv.Close)
	srv.SetIssuer(httpSrv.URL)
	return httpSrv.URL
}

// testMetadata renders IdP metadata for a fresh throwaway IdP key.
func testMetadata(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "flow-test-idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create IdP cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse IdP cert: %v", err)
	}
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.test/metadata">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		`<X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(cert.Raw) + `</X509Certificate></X509Data>` +
		`</KeyInfo></KeyDescriptor>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`
}

func seedTenant(t *testing.T, store flow.Storage) {
	t.Helper()
	ctx := context.Background()
	err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme",
		AllowedRedirectURIs: []string{"https://app.example/callback"}, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
}

func seedOIDC(t *testing.T, store flow.Storage, id, issuer string) {
	t.Helper()
	ctx := context.Background()
	err := store.CreateConnection(ctx, connection.Connection{ID: id, TenantID: "acme",
		Type:         connection.ConnectionTypeOIDC,
		OIDC:         &connection.OIDCConnectionConfig{IssuerURL: issuer, ClientID: "client-1", ClientSecretEncrypted: "secret-1"},
		AttributeMap: connection.AttributeMap{EmailClaim: "email"},
		Status:       connection.ConnectionStatusActive, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
}

func seedSAML(t *testing.T, store flow.Storage, id, metadata string) {
	t.Helper()
	ctx := context.Background()
	err := store.CreateConnection(ctx, connection.Connection{ID: id, TenantID: "acme",
		Type:         connection.ConnectionTypeSAML,
		SAML:         &connection.SAMLConnectionConfig{MetadataXML: metadata},
		AttributeMap: connection.AttributeMap{EmailClaim: "email"},
		Status:       connection.ConnectionStatusActive, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
}
