package flow

import (
	"context"
	"fmt"

	"keyway/internal/connection"
	"keyway/internal/saml"
)

// FinishSAML completes one SAML callback: posted response plus relay state
// in, single-use code out. The pending login's protocol is checked before
// any adapter is touched, so a relay value can never smuggle a record into
// this flow.
func (s *Service) FinishSAML(ctx context.Context, connectionID, responseB64, relayState string) (FinishResult, error) {
	req, err := s.lookupRequest(ctx, connectionID, relayState, connection.ConnectionTypeSAML)
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
	adapter, err := s.getSAMLAdapter(conn)
	if err != nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: %w", err)
	}
	identity, err := adapter.FinishLogin(ctx,
		saml.ReceivedResponse{SAMLResponseB64: responseB64, RelayState: relayState},
		saml.ExpectedResponse{RequestIDs: []string{req.SAMLRequestID}, RelayState: req.State})
	if err != nil {
		return FinishResult{}, fmt.Errorf("flow: finish login: %w", err)
	}
	return s.finishIdentity(ctx, req, identity)
}
