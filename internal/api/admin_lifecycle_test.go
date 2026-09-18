package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestAdminLifecycle pins the activate/disable endpoints: untested flips to
// active, active flips to disabled and back, both repeat idempotently,
// untested refuses disable, and unknown IDs 404. The transitions themselves
// are unit-tested in the domain package; this test pins the HTTP shape
// (routes, codes, redacted response body) around them.
func TestAdminLifecycle(t *testing.T) {
	server, _, _, _, _ := apiStack(t)
	routes := server.Routes()

	rec := doPost(t, routes, "/admin/tenants/acme/connections",
		`{"type":"oidc","issuer_url":"https://issuer.test","client_id":"c1","attribute_map":{"email":"email"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", rec.Code, rec.Body.String())
	}
	id := connectionIDOf(t, rec.Body.String())

	activated := doPost(t, routes, "/admin/connections/"+id+"/activate", ``)
	if activated.Code != http.StatusOK {
		t.Fatalf("activate status = %d: %s", activated.Code, activated.Body.String())
	}
	if statusOf(t, activated.Body.String()) != "active" {
		t.Errorf("activate body = %s, want active", activated.Body.String())
	}
	if again := doPost(t, routes, "/admin/connections/"+id+"/activate", ``); again.Code != http.StatusOK {
		t.Errorf("re-activate status = %d, want 200", again.Code)
	}

	disabled := doPost(t, routes, "/admin/connections/"+id+"/disable", ``)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable status = %d: %s", disabled.Code, disabled.Body.String())
	}
	if statusOf(t, disabled.Body.String()) != "disabled" {
		t.Errorf("disable body = %s, want disabled", disabled.Body.String())
	}
	if again := doPost(t, routes, "/admin/connections/"+id+"/disable", ``); again.Code != http.StatusOK {
		t.Errorf("re-disable status = %d, want 200", again.Code)
	}

	fresh := doPost(t, routes, "/admin/tenants/acme/connections",
		`{"type":"oidc","issuer_url":"https://issuer.test","client_id":"c1","attribute_map":{"email":"email"}}`)
	freshID := connectionIDOf(t, fresh.Body.String())
	if rec := doPost(t, routes, "/admin/connections/"+freshID+"/disable", ``); rec.Code != http.StatusBadRequest {
		t.Errorf("disable untested status = %d, want 400", rec.Code)
	}

	if rec := doPost(t, routes, "/admin/connections/nope/activate", ``); rec.Code != http.StatusNotFound {
		t.Errorf("activate unknown status = %d, want 404", rec.Code)
	}
	if rec := doPost(t, routes, "/admin/connections/nope/disable", ``); rec.Code != http.StatusNotFound {
		t.Errorf("disable unknown status = %d, want 404", rec.Code)
	}
}

// TestAdminLifecycleRequiresToken pins the bearer gate on the new routes:
// without it they 401 exactly like the older admin routes.
func TestAdminLifecycleRequiresToken(t *testing.T) {
	_, store, svc, _, _ := apiStack(t)
	locked, err := NewServer(svc, store, nil, WithAdminToken("s3cret"))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	routes := locked.Routes()
	if rec := doPost(t, routes, "/admin/connections/conn-saml/activate", ``); rec.Code != http.StatusUnauthorized {
		t.Errorf("activate without token status = %d, want 401", rec.Code)
	}
	if rec := doPost(t, routes, "/admin/connections/conn-saml/disable", ``); rec.Code != http.StatusUnauthorized {
		t.Errorf("disable without token status = %d, want 401", rec.Code)
	}
}

func statusOf(t *testing.T, body string) string {
	t.Helper()
	var resp ConnectionResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode response: %v: %s", err, body)
	}
	return resp.Status
}
