package oidc

import (
	"context"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// TokenRequest carries one authorization-code redemption.
//
// WHY a struct instead of positional strings: the exchange needs four
// values and misordering client ID and secret would fail opaquely at the
// issuer. Named fields make the call site self-checking, and ClientID is
// present because real issuers reject exchanges that do not identify the
// client — a gap unit tests against mocks would never catch.
type TokenRequest struct {
	// Code is the authorization code the issuer returned to the callback.
	Code string

	// ClientID identifies this relying party to the issuer at redemption.
	ClientID string

	// RedirectURL must repeat the callback URL from the authorize step.
	RedirectURL string

	// ClientSecret authenticates this relying party at the token endpoint.
	// It lives in memory only and is never logged.
	ClientSecret string
}

// AuthCodeURL builds the issuer redirect that starts one login.
//
// WHY this method exists: the authorize redirect must carry this
// connection's client ID, callback URL, scopes, and the stored nonce in
// exactly one construction site, so the values verified later cannot drift
// from the values sent.
func (a *Adapter) AuthCodeURL(state, nonce, redirectURL string) string {
	config := oauth2.Config{
		ClientID:    a.clientID,
		Endpoint:    a.provider.Endpoint(),
		RedirectURL: redirectURL,
		Scopes:      []string{gooidc.ScopeOpenID, gooidc.ScopeProfile, gooidc.ScopeEmail},
	}
	return config.AuthCodeURL(state, gooidc.Nonce(nonce))
}

// ExchangeCode redeems one authorization code for its raw ID token.
//
// WHY this method exists: only this package may speak OAuth2 wire details.
// The flow layer hands over redemption inputs and gets back an opaque token
// string for VerifyToken, keeping token-endpoint behavior (including the
// missing-id_token rejection) in one wrapped-error site.
func (a *Adapter) ExchangeCode(ctx context.Context, req TokenRequest) (string, error) {
	if req.Code == "" || req.ClientID == "" || req.RedirectURL == "" || req.ClientSecret == "" {
		return "", fmt.Errorf("oidc: exchange code: code, client ID, redirect URL, and secret are required")
	}
	config := oauth2.Config{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		Endpoint:     a.provider.Endpoint(),
		RedirectURL:  req.RedirectURL,
	}
	token, err := config.Exchange(ctx, req.Code)
	if err != nil {
		return "", fmt.Errorf("oidc: exchange code: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", fmt.Errorf("oidc: exchange code: token response carried no ID token")
	}
	return raw, nil
}
