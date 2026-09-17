// Command demo-sso is the smallest possible Keyway-integrated app: a home
// page with a login link and a callback that redeems the code for the
// normalized identity. It exists to prove the app side of lane C end to
// end against a local Keyway plus a real IdP, using only pkg/client.
//
//	go run ./examples/demo-sso
//	# open http://localhost:3000, click Log in, finish at the IdP,
//	# land back here showing your email.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"html"
	"net/http"
	"os"

	"keyway/pkg/client"
)

// App serves one tenant's login loop. The SDK client owns Keyway URL
// handling; tenantID and redirectURI must match the tenant's allowlist or
// Keyway refuses /authorize before any IdP is involved.
type App struct {
	sdk         *client.Client
	tenantID    string
	redirectURI string
}

func main() {
	keywayURL := flag.String("keyway", "http://127.0.0.1:8080", "Keyway base URL")
	addr := flag.String("addr", "127.0.0.1:3000", "listen address")
	tenantID := flag.String("tenant", "acme", "Keyway tenant handle")
	redirectURI := flag.String("redirect", "http://localhost:3000/callback", "app callback URL (must be allowlisted)")
	flag.Parse()

	sdk, err := client.New(*keywayURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo-sso:", err)
		os.Exit(1)
	}
	app := &App{sdk: sdk, tenantID: *tenantID, redirectURI: *redirectURI}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", app.handleHome)
	mux.HandleFunc("GET /callback", app.handleCallback)
	fmt.Printf("demo-sso listening on http://%s for tenant %q\n", *addr, *tenantID)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "demo-sso:", err)
		os.Exit(1)
	}
}

// handleHome renders the login link. The state token is minted per visit
// and stored in an HttpOnly cookie so /callback can verify the round-trip
// instead of trusting a ?state= the user could forge.
func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	state, err := newState()
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	loginURL, err := a.sdk.AuthURL(a.tenantID, a.redirectURI, state, "")
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "keyway_state", Value: state,
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>demo-sso</h1><p><a href=%q>Log in with SSO</a></p>", loginURL)
}

// handleCallback verifies the state round-trip first — before touching the
// code — then redeems the single-use code and shows the identity. Any
// mismatch fails closed: the code is never sent when CSRF is suspected.
func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	want, err := r.Cookie("keyway_state")
	if err != nil || want.Value == "" || query.Get("state") != want.Value {
		http.Error(w, "state mismatch: login did not start here", http.StatusBadRequest)
		return
	}
	ident, err := a.sdk.Exchange(r.Context(), query.Get("code"), a.redirectURI)
	if err != nil {
		http.Error(w, "exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>logged in</h1><p>email: %s</p><p>name: %s</p><p>groups: %v</p>",
		html.EscapeString(ident.Email), html.EscapeString(ident.Name), ident.Groups)
}

func newState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
