package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthURL(t *testing.T) {
	c, err := New("https://keyway.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u, err := c.AuthURL("acme", "https://app.example/callback", "csrf-123", "conn-1")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Path != "/authorize" {
		t.Errorf("path = %q, want /authorize", parsed.Path)
	}
	q := parsed.Query()
	if q.Get("tenant") != "acme" || q.Get("redirect_uri") != "https://app.example/callback" || q.Get("state") != "csrf-123" || q.Get("connection") != "conn-1" {
		t.Errorf("query = %v", q)
	}
	withoutConn, err := c.AuthURL("acme", "https://app.example/callback", "", "")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	if strings.Contains(withoutConn, "connection=") {
		t.Errorf("empty connectionID leaked into URL: %q", withoutConn)
	}
	if _, err := c.AuthURL("", "https://app.example/callback", "", ""); err == nil {
		t.Errorf("missing tenant: expected rejection, got nil error")
	}
}

func TestExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "code-1" || r.Form.Get("redirect_uri") != "https://app.example/callback" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "code mismatch"})
			return
		}
		_ = json.NewEncoder(w).Encode(Identity{Email: "ada@example.com", Name: "Ada", Groups: []string{"eng"}})
	}))
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ident, err := c.Exchange(t.Context(), "code-1", "https://app.example/callback")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ident.Email != "ada@example.com" || ident.Name != "Ada" || len(ident.Groups) != 1 {
		t.Errorf("identity = %+v", ident)
	}
	if _, err := c.Exchange(t.Context(), "bad-code", "https://app.example/callback"); err == nil {
		t.Errorf("bad code: expected rejection, got nil error")
	}
}

func TestNewValidatesURL(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Errorf("empty URL: expected rejection, got nil error")
	}
	if _, err := New("://bad"); err == nil {
		t.Errorf("malformed URL: expected rejection, got nil error")
	}
	c, err := New("https://keyway.example/")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u, err := c.AuthURL("acme", "https://app.example/callback", "", "")
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	if strings.Contains(u, "//authorize") {
		t.Errorf("double slash in URL: %q", u)
	}
}
