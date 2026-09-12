package flow

import (
	"context"
	"fmt"

	"keyway/internal/connection"
	"keyway/internal/oidc"
)

// FinishOIDC completes one OIDC callback: code plus state in, single-use
// code out. The pending login's protocol is checked before any adapter is
// touched, so a state value can never smuggle a record into this flow.
func (s *Service) FinishOIDC(ctx context.Context, connectionID, code, state string) (FinishResult, error) {
	req, err := s.lookupRequest(ctx, connectionID, state, connection.ConnectionTypeOIDC)
	if err != nil {
		return FinishResult{}, err
	}
	conn, err := s.store.GetConnection(ctx, req.ConnectionID)
	if err != nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: %w", err)
	}
	if conn.Status != connection.ConnectionStatusActive {
		return FinishResult{}, fmt.Errorf("flow: finish login: connection %q is no longer active", conn.ID)
	}
	if conn.OIDC == nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: connection %q has no OIDC config", conn.ID)
	}
	adapter, err := s.getOIDCAdapter(ctx, conn)
	if err != nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: %w", err)
	}
	raw, err := adapter.ExchangeCode(ctx, oidc.TokenRequest{
		Code: code, ClientID: conn.OIDC.ClientID,
		RedirectURL:  s.oidcCallbackURL(conn.ID),
		ClientSecret: conn.OIDC.ClientSecretEncrypted,
	})
	if err != nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: %w", err)
	}
	identity, err := adapter.VerifyToken(ctx, raw, req.Nonce)
	if err != nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: %w", err)
	}
	return s.finishIdentity(ctx, req, identity)
}
