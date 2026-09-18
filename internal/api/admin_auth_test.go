package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAdminAuth pins the admin gate: with a token configured, admin routes
// 401 without (or with a wrong) bearer token and serve with the right one;
// flow routes stay public; with no token configured, admin stays open for
// localhost dev. The last case documents a deliberate posture, not an
// oversight — production sets the token and Caddy blocks /admin/* anyway.
func TestAdminAuth(t *testing.T) {
	server, _, _, _, _ := apiStack(t)
	locked, err := NewServer(server.flow, server.store, nil, WithAdminToken("s3cret"))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	routes := locked.Routes()

	if rec := apiGet(t, routes, "/admin/tenants"); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", rec.Code)
	}
	req := apiGetRequest(t, routes, "/admin/tenants", "Bearer wrong")
	if req.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", req.Code)
	}
	ok := apiGetRequest(t, routes, "/admin/tenants", "Bearer s3cret")
	if ok.Code != http.StatusOK {
		t.Errorf("right token: status = %d, want 200", ok.Code)
	}
	if rec := apiGet(t, routes, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("flow route with token set: status = %d, want 200", rec.Code)
	}

	open := server.Routes()
	if rec := apiGet(t, open, "/admin/tenants"); rec.Code != http.StatusOK {
		t.Errorf("no token configured: status = %d, want 200 (dev open)", rec.Code)
	}
}

func apiGetRequest(t *testing.T, handler http.Handler, target, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", auth)
	return httptestRecord(t, handler, req)
}
