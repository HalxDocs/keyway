package flow

import (
	"context"
	"fmt"

	"keyway/internal/connection"
	"keyway/internal/normalize"
)

// FinishResult hands the callback handler everything for the app redirect:
// the single-use code plus the values that must round-trip with it.
type FinishResult struct {
	// Code is the single-use redemption secret for /token.
	Code string

	// RedirectURI is the validated application callback from /authorize.
	RedirectURI string

	// AppState is the application's state parameter, returned verbatim.
	AppState string
}

// lookupRequest fetches the pending login for a callback and enforces the
// two checks every finish path shares: the record must belong to the
// connection in the callback URL, and its protocol must match the endpoint
// it arrived on. The protocol check runs before any adapter is touched, so
// a state value can never smuggle a record into the wrong flow's checks.
func (s *Service) lookupRequest(ctx context.Context, connectionID, state string, protocol connection.ConnectionType) (AuthRequest, error) {
	req, err := s.store.GetAuthRequestByState(ctx, state)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("flow: finish login: %w", err)
	}
	if req.Protocol != protocol {
		_ = s.store.DeleteAuthRequest(ctx, req.ID)
		return AuthRequest{}, fmt.Errorf("flow: finish login: pending login is %q, not %q", req.Protocol, protocol)
	}
	if req.ConnectionID != connectionID {
		_ = s.store.DeleteAuthRequest(ctx, req.ID)
		return AuthRequest{}, fmt.Errorf("flow: finish login: pending login belongs to another connection")
	}
	if !s.now().Before(req.ExpiresAt) {
		_ = s.store.DeleteAuthRequest(ctx, req.ID)
		return AuthRequest{}, fmt.Errorf("flow: finish login: pending login expired")
	}
	return req, nil
}

// finishIdentity issues the code for one verified identity and retires the
// pending login, so the same login can never mint a second code.
func (s *Service) finishIdentity(ctx context.Context, req AuthRequest, identity normalize.Identity) (FinishResult, error) {
	code, err := NewAuthCode(req.TenantID, identity, req.RedirectURI, s.now())
	if err != nil {
		return FinishResult{}, err
	}
	if err := s.store.IssueCode(ctx, code); err != nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: %w", err)
	}
	_ = s.store.DeleteAuthRequest(ctx, req.ID)
	return FinishResult{Code: code.Code, RedirectURI: req.RedirectURI, AppState: req.AppState}, nil
}

// Redeem exchanges one single-use code for its verified Identity. The
// redirect URI must match the callback the login started with; a mismatch
// burns the code (it is already consumed) and rejects, fail-closed.
func (s *Service) Redeem(ctx context.Context, code, redirectURI string) (normalize.Identity, error) {
	if code == "" || redirectURI == "" {
		return normalize.Identity{}, fmt.Errorf("flow: redeem: code and redirect URI are required")
	}
	consumed, err := s.store.ConsumeCode(ctx, code, s.now().Unix())
	if err != nil {
		return normalize.Identity{}, fmt.Errorf("flow: redeem: %w", err)
	}
	if consumed.RedirectURI != redirectURI {
		return normalize.Identity{}, fmt.Errorf("flow: redeem: redirect URI mismatch")
	}
	return consumed.Identity, nil
}
