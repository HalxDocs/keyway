package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"keyway/pkg/client"
)

func testApp(t *testing.T) *App {
	t.Helper()
	sdk, err := client.New("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return &App{sdk: sdk, tenantID: "acme", redirectURI: "http://localhost:3000/callback"}
}

func TestHomeRendersLoginLink(t *testing.T) {
	app := testApp(t)
	rec := httptest.NewRecorder()
	app.handleHome(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/authorize?") || !strings.Contains(body, "tenant=acme") {
		t.Errorf("home page has no Keyway login link: %q", body)
	}
	cookies := res.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "keyway_state" && c.Value != "" && c.HttpOnly {
			found = true
		}
	}
	if !found {
		t.Errorf("home page sets no HttpOnly keyway_state cookie")
	}
}

func TestCallbackRejectsForgedState(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=evil", nil)
	req.AddCookie(&http.Cookie{Name: "keyway_state", Value: "honest"})
	rec := httptest.NewRecorder()
	app.handleCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackRejectsMissingCookie(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=abc", nil)
	rec := httptest.NewRecorder()
	app.handleCallback(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
