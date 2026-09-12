package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

// TestAdminTestConnection probes the dry-run endpoint: live OIDC discovery
// against a test issuer passes, the seeded SAML connection passes with the
// server's SP identity, and garbage metadata fails.
func TestAdminTestConnection(t *testing.T) {
	server, _, _, _, _ := apiStack(t)
	routes := server.Routes()

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

	issuerJSON, err := json.Marshal(httpSrv.URL)
	if err != nil {
		t.Fatalf("marshal issuer: %v", err)
	}
	rec := doPost(t, routes, "/admin/tenants/acme/connections",
		`{"type":"oidc","issuer_url":`+string(issuerJSON)+`,"client_id":"c1","attribute_map":{"email":"email"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create OIDC status = %d: %s", rec.Code, rec.Body.String())
	}
	oidcID := connectionIDOf(t, rec.Body.String())
	if probe := doPost(t, routes, "/admin/connections/"+oidcID+"/test", ``); probe.Code != http.StatusOK {
		t.Errorf("OIDC probe status = %d, want 200: %s", probe.Code, probe.Body.String())
	}

	if probe := doPost(t, routes, "/admin/connections/conn-saml/test", ``); probe.Code != http.StatusOK {
		t.Errorf("SAML probe status = %d, want 200: %s", probe.Code, probe.Body.String())
	}

	bad := doPost(t, routes, "/admin/tenants/acme/connections",
		`{"type":"saml","metadata_xml":"<EntityDescriptor>not-really-metadata</EntityDescriptor>",`+
			`"attribute_map":{"email":"email"}}`)
	if bad.Code != http.StatusCreated {
		t.Fatalf("create garbage-SAML status = %d", bad.Code)
	}
	badID := connectionIDOf(t, bad.Body.String())
	if probe := doPost(t, routes, "/admin/connections/"+badID+"/test", ``); probe.Code != http.StatusBadRequest {
		t.Errorf("garbage metadata probe status = %d, want 400", probe.Code)
	}

	if probe := doPost(t, routes, "/admin/connections/nope/test", ``); probe.Code != http.StatusBadRequest {
		t.Errorf("unknown connection probe status = %d, want 400", probe.Code)
	}
}

func connectionIDOf(t *testing.T, body string) string {
	t.Helper()
	var created ConnectionResponse
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("decode created connection: %v: %s", err, body)
	}
	if created.ID == "" {
		t.Fatalf("no ID in body: %s", body)
	}
	return created.ID
}
