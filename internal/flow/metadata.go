package flow

import (
	"context"
	"fmt"

	"keyway/internal/connection"
)

// SPMetadata returns the SP metadata XML for one SAML connection.
//
// WHY a Service method instead of building XML in the handler: only the
// Service holds the deployment's base URL and SP identity, so only it can
// produce the exact ACS URL and entity ID the running instance advertises.
// Handlers receive opaque bytes, keeping protocol types confined.
func (s *Service) SPMetadata(ctx context.Context, connectionID string) ([]byte, error) {
	if connectionID == "" {
		return nil, fmt.Errorf("flow: sp metadata: connection ID is required")
	}
	conn, err := s.store.GetConnection(ctx, connectionID)
	if err != nil {
		return nil, fmt.Errorf("flow: sp metadata: %w", err)
	}
	if conn.Type != connection.ConnectionTypeSAML {
		return nil, fmt.Errorf("flow: sp metadata: connection %q is not SAML", connectionID)
	}
	adapter, err := s.getSAMLAdapter(conn)
	if err != nil {
		return nil, fmt.Errorf("flow: sp metadata: %w", err)
	}
	xmlBytes, err := adapter.Metadata()
	if err != nil {
		return nil, err
	}
	return xmlBytes, nil
}
