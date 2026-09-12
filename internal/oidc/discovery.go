// Package oidc adapts any OIDC identity provider to Keyway's Identity.
//
// WHY this package exists: the auth flow must accept logins from OIDC
// issuers without learning OIDC wire details. This is the only place
// allowed to import the OIDC client library; everything above it deals
// solely in connection.Connection and normalize.Identity.
package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ProviderFunc builds an OIDC provider from an issuer URL.
//
// WHY a func type instead of calling oidc.NewProvider directly: discovery
// performs network I/O against the issuer's metadata document. Injecting
// the constructor lets tests substitute a local httptest issuer while
// production passes oidc.NewProvider, with no package-level mutable state.
type ProviderFunc func(ctx context.Context, issuer string) (*oidc.Provider, error)

// DefaultDiscover runs OIDC discovery against the live issuer.
//
// WHY a function declaration instead of a package variable holding
// oidc.NewProvider: a variable would be reassignable global mutable state.
// Callers above the normalize layer (which must never import the OIDC
// library per the package boundary) pass this function to NewAdapter to get
// production discovery without naming protocol types themselves.
func DefaultDiscover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	return DiscoverProvider(ctx, issuer, oidc.NewProvider)
}

// DiscoverProvider resolves an issuer URL to a Provider via OIDC discovery.
//
// WHY a separate choke point instead of inlining discovery in the adapter
// constructor: issuer-mismatch and transport failures need one consistent
// wrapping site so operators can tell "IdP unreachable" apart from "IdP
// misconfigured" without reading protocol internals.
func DiscoverProvider(ctx context.Context, issuer string, discover ProviderFunc) (*oidc.Provider, error) {
	if issuer == "" {
		return nil, fmt.Errorf("oidc: discover provider: empty issuer URL")
	}
	if discover == nil {
		return nil, fmt.Errorf("oidc: discover provider: nil discovery function")
	}
	provider, err := discover(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover provider %q: %w", issuer, err)
	}
	return provider, nil
}
