package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestAdminTenants(t *testing.T) {
	server, _, _, _, _ := apiStack(t)
	routes := server.Routes()

	rec := doPost(t, routes, "/admin/tenants",
		`{"id":"globex","name":"Globex","redirect_uris":["https://app.globex.example/cb"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", rec.Code, rec.Body.String())
	}
	if dup := doPost(t, routes, "/admin/tenants",
		`{"id":"globex","name":"Globex"}`); dup.Code != http.StatusConflict {
		t.Errorf("duplicate: status = %d, want 409", dup.Code)
	}
	if bad := doPost(t, routes, "/admin/tenants", `{"id":"","name":""}`); bad.Code != http.StatusBadRequest {
		t.Errorf("empty: status = %d, want 400", bad.Code)
	}

	list := apiGet(t, routes, "/admin/tenants")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "globex") {
		t.Errorf("list = %d %s, want globex", list.Code, list.Body.String())
	}
}

func TestAdminConnectionsValidateAndRedact(t *testing.T) {
	server, _, _, _, _ := apiStack(t)
	routes := server.Routes()

	rec := doPost(t, routes, "/admin/tenants/acme/connections",
		`{"type":"oidc","issuer_url":"https://issuer.test","client_id":"c1","client_secret":"super-secret-value",`+
			`"attribute_map":{"email":"email"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "super-secret-value") {
		t.Errorf("response leaks the client secret: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"has_secret":true`) {
		t.Errorf("response missing has_secret flag: %s", rec.Body.String())
	}

	for name, body := range map[string]string{
		"empty email claim":     `{"type":"oidc","issuer_url":"https://issuer.test","client_id":"c1","attribute_map":{}}`,
		"unknown type":          `{"type":"kerberos","attribute_map":{"email":"email"}}`,
		"SAML without metadata": `{"type":"saml","attribute_map":{"email":"email"}}`,
	} {
		if rec := doPost(t, routes, "/admin/tenants/acme/connections", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
	if rec := doPost(t, routes, "/admin/tenants/nope/connections",
		`{"type":"oidc","issuer_url":"https://issuer.test","client_id":"c1","attribute_map":{"email":"email"}}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown tenant: status = %d, want 404", rec.Code)
	}

	list := apiGet(t, routes, "/admin/tenants/acme/connections")
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d", list.Code)
	}
	var conns []ConnectionResponse
	if err := json.Unmarshal(list.Body.Bytes(), &conns); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	id := ""
	for _, c := range conns {
		if c.Type == "oidc" {
			id = c.ID
		}
	}
	if id == "" {
		t.Fatalf("no OIDC connection in list: %s", list.Body.String())
	}
	if rec := httptestRecord(t, routes, httptestNewDelete(t, "/admin/connections/"+id)); rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec.Code)
	}
	if rec := httptestRecord(t, routes, httptestNewDelete(t, "/admin/connections/"+id)); rec.Code != http.StatusNotFound {
		t.Errorf("second delete: status = %d, want 404", rec.Code)
	}
}
