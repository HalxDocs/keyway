// Package client is the Go SDK your app uses to talk to Keyway.
//
// WHY this package exists: an app should not hand-assemble authorize URLs
// or token requests. One Client builds the authorize redirect and redeems
// the code with correct query encoding and error wrapping, keeping the
// AppState CSRF round-trip — a security property — from being lost in
// ad-hoc URL building.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Identity is the normalized user your app receives after SSO.
//
// WHY this struct exists: it is the app-facing projection of the internal
// flow identity. Raw IdP claims never cross this boundary, so the SDK does
// not leak debug data and stays stable when IdP claim shapes change.
type Identity struct {
	// Email is the verified login identifier for account matching.
	Email string `json:"email"`
	// Name is the human-readable display name, possibly empty.
	Name string `json:"name"`
	// Groups carries normalized group memberships, possibly empty.
	Groups []string `json:"groups"`
}

// Client talks to one Keyway deployment.
//
// WHY a struct holding base URL and http client instead of free functions:
// the deployment address and transport are deployment-wide configuration
// that must be validated once at construction, not on every call, and
// tests can inject an httptest server without global patching.
type Client struct {
	baseURL string
	http    *http.Client
}

// ClientOption customizes a Client. Only WithHTTPClient is exposed today
// to keep the surface small and obvious to a stranger reading one file.
type ClientOption func(*Client)

// WithHTTPClient overrides the transport, for example to use an
// httptest server or a custom timeout in tests.
func WithHTTPClient(h *http.Client) ClientOption {
	return func(c *Client) { c.http = h }
}

// New builds a Client for the deployment at baseURL, trimming any trailing
// slash so URL construction never double-slashes.
func New(baseURL string, opts ...ClientOption) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("client: new: base URL is required")
	}
	parsed, err := url.ParseRequestURI(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("client: new: invalid base URL: %w", err)
	}
	c := &Client{baseURL: parsed.String(), http: http.DefaultClient}
	for _, opt := range opts {
		opt(c)
	}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	return c, nil
}

// AuthURL builds the redirect your app sends the user to. The state
// parameter is your own CSRF token; Keyway echoes it back as ?state=
// alongside ?code= on the final redirect so you can verify the round-trip.
//
// WHY connectionID is a plain string with "" meaning unset: a variadic
// would permit multiple IDs with silent first-or-last behavior, hiding a
// bug at the call site. One value or none is the only honest shape.
func (c *Client) AuthURL(tenantID, redirectURI, state, connectionID string) (string, error) {
	if tenantID == "" || redirectURI == "" {
		return "", fmt.Errorf("client: auth url: tenant and redirect URI are required")
	}
	u, err := url.Parse(c.baseURL + "/authorize")
	if err != nil {
		return "", fmt.Errorf("client: auth url: %w", err)
	}
	q := u.Query()
	q.Set("tenant", tenantID)
	q.Set("redirect_uri", redirectURI)
	if state != "" {
		q.Set("state", state)
	}
	if connectionID != "" {
		q.Set("connection", connectionID)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange redeems one single-use code for its verified identity. The
// redirect URI must match the one used in AuthURL or redemption fails
// closed, burning the code.
func (c *Client) Exchange(ctx context.Context, code, redirectURI string) (Identity, error) {
	if code == "" || redirectURI == "" {
		return Identity{}, fmt.Errorf("client: exchange: code and redirect URI are required")
	}
	form := url.Values{"code": {code}, "redirect_uri": {redirectURI}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, fmt.Errorf("client: exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("client: exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var apiErr map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		msg := apiErr["error_description"]
		if msg == "" {
			msg = apiErr["error"]
		}
		if msg == "" {
			msg = resp.Status
		}
		return Identity{}, fmt.Errorf("client: exchange: %s", msg)
	}
	var ident Identity
	if err := json.NewDecoder(resp.Body).Decode(&ident); err != nil {
		return Identity{}, fmt.Errorf("client: exchange: decode identity: %w", err)
	}
	if ident.Email == "" {
		return Identity{}, fmt.Errorf("client: exchange: identity has no email")
	}
	return ident, nil
}
