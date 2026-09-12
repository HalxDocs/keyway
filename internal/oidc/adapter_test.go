package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"keyway/internal/connection"
)

// testIssuer spins an oidctest server with one RSA key. It returns the
// server, its URL-as-issuer, and the private key for signing tokens.
func testIssuer(t *testing.T) (*httptest.Server, string, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	testServer := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: oidc.RS256},
		},
	}
	httpServer := httptest.NewServer(testServer)
	t.Cleanup(httpServer.Close)
	testServer.SetIssuer(httpServer.URL)
	return httpServer, httpServer.URL, priv
}

// signClaims mints a token from a raw JSON claims document.
func signClaims(priv *rsa.PrivateKey, claims string) string {
	return oidctest.SignIDToken(priv, "test-key", oidc.RS256, claims)
}

// testClaims renders the standard claims document with caller-chosen values.
func testClaims(issuer, clientID, nonce, emailExtra string) string {
	return `{` +
		`"iss":` + strconv.Quote(issuer) + `,` +
		`"aud":` + strconv.Quote(clientID) + `,` +
		`"sub":"user-1",` +
		`"exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,` +
		`"nonce":` + strconv.Quote(nonce) + emailExtra +
		`}`
}

// testAdapter builds an Adapter against the test issuer with custom claim names.
func testAdapter(t *testing.T, ctx context.Context, issuer, clientID string) *Adapter {
	t.Helper()
	conn := connection.Connection{
		ID:       "conn-1",
		TenantID: "acme",
		Type:     connection.ConnectionTypeOIDC,
		OIDC:     &connection.OIDCConnectionConfig{IssuerURL: issuer, ClientID: clientID},
		AttributeMap: connection.AttributeMap{
			EmailClaim:  "upn",
			NameClaim:   "display_name",
			GroupsClaim: "roles",
		},
		Status: connection.ConnectionStatusActive,
	}
	adapter, err := NewAdapter(ctx, conn, oidc.NewProvider)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	return adapter
}

// TestVerifyTokenHonorsCustomClaimNames is the regression test for the
// StandardClaims/AttributeMap conflict: the IdP uses upn/display_name/
// roles, never email/name/groups, and the Identity must still be populated.
func TestVerifyTokenHonorsCustomClaimNames(t *testing.T) {
	_, issuer, priv := testIssuer(t)
	ctx := context.Background()
	adapter := testAdapter(t, ctx, issuer, "keyway-test-client")

	raw := testClaims(issuer, "keyway-test-client", "nonce-1",
		`,"upn":"ada@example.com","display_name":"Ada","roles":["eng","sso"]`)
	identity, err := adapter.VerifyToken(ctx, signClaims(priv, raw), "nonce-1")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if identity.Email != "ada@example.com" {
		t.Errorf("Email = %q, want ada@example.com", identity.Email)
	}
	if identity.Name != "Ada" {
		t.Errorf("Name = %q, want Ada", identity.Name)
	}
	if len(identity.Groups) != 2 || identity.Groups[0] != "eng" {
		t.Errorf("Groups = %v, want [eng sso]", identity.Groups)
	}
}

// TestVerifyTokenRejects maps every security-critical failure to a rejection.
func TestVerifyTokenRejects(t *testing.T) {
	_, issuer, priv := testIssuer(t)
	ctx := context.Background()
	adapter := testAdapter(t, ctx, issuer, "keyway-test-client")
	good := func() string {
		return signClaims(priv, testClaims(issuer, "keyway-test-client", "nonce-1",
			`,"upn":"ada@example.com","display_name":"Ada","roles":["eng"]`))
	}

	cases := map[string]struct {
		token string
		nonce string
	}{
		"tampered signature": {token: good()[:len(good())-2] + "xx", nonce: "nonce-1"},
		"wrong audience": {token: signClaims(priv, testClaims(issuer, "other-client", "nonce-1",
			`,"upn":"ada@example.com"`)), nonce: "nonce-1"},
		"nonce mismatch":       {token: good(), nonce: "wrong-nonce"},
		"empty expected nonce": {token: good(), nonce: ""},
		"missing email claim": {token: signClaims(priv, testClaims(issuer, "keyway-test-client", "nonce-1", ``)),
			nonce: "nonce-1"},
	}
	for name, tc := range cases {
		if _, err := adapter.VerifyToken(ctx, tc.token, tc.nonce); err == nil {
			t.Errorf("%s: expected rejection, got nil error", name)
		}
	}

	expired := `{` +
		`"iss":` + strconv.Quote(issuer) + `,` +
		`"aud":"keyway-test-client",` +
		`"sub":"user-1",` +
		`"exp":` + strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10) + `,` +
		`"nonce":"nonce-1",` +
		`"upn":"ada@example.com"}`

	if _, err := adapter.VerifyToken(ctx, signClaims(priv, expired), "nonce-1"); err == nil {
		t.Errorf("expired token: expected rejection, got nil error")
	}
}
