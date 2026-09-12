package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
)

// TestAuthorizeRedirects validates the happy path and every loud rejection.
func TestAuthorizeRedirects(t *testing.T) {
	server, _, _, _, _ := apiStack(t)
	routes := server.Routes()

	rec := apiGet(t, routes, "/authorize?tenant=acme&redirect_uri="+url.QueryEscape(apiApp))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.Contains(location, "idp.test") || !strings.Contains(location, "SAMLRequest=") {
		t.Errorf("redirect = %q, want IdP login URL", location)
	}

	for name, target := range map[string]string{
		"missing tenant":    "/authorize?redirect_uri=" + url.QueryEscape(apiApp),
		"missing redirect":  "/authorize?tenant=acme",
		"unknown tenant":    "/authorize?tenant=nope&redirect_uri=" + url.QueryEscape(apiApp),
		"unlisted redirect": "/authorize?tenant=acme&redirect_uri=" + url.QueryEscape("https://evil.example/"),
	} {
		if rec := apiGet(t, routes, target); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
}

// TestSAMLCallbackEndToEnd runs the full vertical slice. It fabricates the
// pending login directly (the authorize redirect itself points at a fake IdP
// no test can follow), then runs the real callback, follows the app
// redirect, and redeems the code for the identity.
func TestSAMLCallbackEndToEnd(t *testing.T) {
	server, store, _, idpKey, idpCert := apiStack(t)
	routes := server.Routes()
	ctx := context.Background()

	req, err := flow.NewAuthRequest(flow.NewAuthRequestParams{TenantID: "acme",
		ConnectionID: "conn-saml", Protocol: connection.ConnectionTypeSAML,
		State: "relay-e2e", AppState: "app-99", SAMLRequestID: "req-e2e",
		RedirectURI: apiApp, Now: time.Now()})
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	if err := store.SaveAuthRequest(ctx, req); err != nil {
		t.Fatalf("SaveAuthRequest: %v", err)
	}
	responseB64, relay := apiMint(t, idpKey, idpCert, "req-e2e", "relay-e2e")
	form := url.Values{"SAMLResponse": {responseB64}, "RelayState": {relay}}
	httpReq := httptestNewPostForm(t, "/callback/saml/conn-saml", form)
	rec := httptestRecord(t, routes, httpReq)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	appTarget, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse app redirect: %v", err)
	}
	if !strings.HasPrefix(appTarget.String(), apiApp) {
		t.Fatalf("redirect = %q, want app callback", appTarget.String())
	}
	appQuery := appTarget.Query()
	if appQuery.Get("code") == "" || appQuery.Get("state") != "app-99" {
		t.Fatalf("app redirect missing code/state round-trip: %q", appTarget.String())
	}

	tokenForm := url.Values{"code": {appQuery.Get("code")}, "redirect_uri": {apiApp}}
	tokenRec := httptestRecord(t, routes, httptestNewPostForm(t, "/token", tokenForm))
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status = %d, want 200: %s", tokenRec.Code, tokenRec.Body.String())
	}
	var identity struct {
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &identity); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if identity.Email != "ada@example.com" {
		t.Errorf("Email = %q", identity.Email)
	}

	replay := httptestRecord(t, routes, httptestNewPostForm(t, "/token", tokenForm))
	if replay.Code != http.StatusBadRequest {
		t.Errorf("code replay: status = %d, want 400", replay.Code)
	}
}

// TestCallbackAndTokenRejects covers wrong-callback, unknown state, and
// malformed token requests at the HTTP boundary.
func TestCallbackAndTokenRejects(t *testing.T) {
	server, _, _, _, _ := apiStack(t)
	routes := server.Routes()

	if rec := apiGet(t, routes, "/callback/oidc/conn-saml?code=x&state=y"); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown OIDC state: status = %d, want 400", rec.Code)
	}
	badForm := url.Values{"SAMLResponse": {"!!!"}, "RelayState": {"relay-e2e"}}
	if rec := httptestRecord(t, routes, httptestNewPostForm(t, "/callback/saml/conn-saml", badForm)); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed SAML response: status = %d, want 400", rec.Code)
	}
	emptyForm := url.Values{"code": {"nope"}, "redirect_uri": {apiApp}}
	if rec := httptestRecord(t, routes, httptestNewPostForm(t, "/token", emptyForm)); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown code: status = %d, want 400", rec.Code)
	}
	missing := url.Values{"code": {"x"}}
	if rec := httptestRecord(t, routes, httptestNewPostForm(t, "/token", missing)); rec.Code != http.StatusBadRequest {
		t.Errorf("missing redirect_uri: status = %d, want 400", rec.Code)
	}
}
