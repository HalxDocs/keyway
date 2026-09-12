package api

// Shared API-test fixtures: a live stack (temp-file store plus flow service
// plus routes) and request helpers. Signed-response minting lives in
// api_mint_test.go, beside its only consumer.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/secret"
	"keyway/internal/storage"
	"keyway/internal/tenant"
)

const (
	apiEntity = "https://keyway.test/sp"
	apiACS    = "https://keyway.test/callback/saml/conn-saml"
	apiIDP    = "https://idp.test/metadata"
	apiSSO    = "https://idp.test/sso"
	apiApp    = "https://app.example/callback"
)

func apiStack(t *testing.T) (*Server, flow.Storage, *flow.Service, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := make([]byte, secret.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	store, err := storage.NewSQLiteStore(filepath.Join(t.TempDir(), "api.db"), box)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate SP key: %v", err)
	}
	spCert := apiCert(t, spKey, "api-sp")
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	idpCert := apiCert(t, idpKey, "api-idp")

	ctx := context.Background()
	err = store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme",
		AllowedRedirectURIs: []string{apiApp}, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	metadata := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + apiIDP + `">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		`<X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(idpCert.Raw) + `</X509Certificate></X509Data>` +
		`</KeyInfo></KeyDescriptor>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + apiSSO + `"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`
	err = store.CreateConnection(ctx, connection.Connection{ID: "conn-saml", TenantID: "acme",
		Type:         connection.ConnectionTypeSAML,
		SAML:         &connection.SAMLConnectionConfig{MetadataXML: metadata},
		AttributeMap: connection.AttributeMap{EmailClaim: "email"},
		Status:       connection.ConnectionStatusActive, CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	svc, err := flow.NewService(store, flow.Config{
		BaseURL: "https://keyway.test", SPEntityID: apiEntity, SPKey: spKey, SPCert: spCert,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	server, err := NewServer(svc, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server, store, svc, idpKey, idpCert
}

func apiCert(t *testing.T, key *rsa.PrivateKey, name string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func apiGet(t *testing.T, handler http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func httptestNewPostForm(t *testing.T, target string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func httptestRecord(t *testing.T, handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
