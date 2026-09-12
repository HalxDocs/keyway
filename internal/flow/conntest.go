package flow

import (
	"context"
	"fmt"

	"keyway/internal/connection"
)

// TestConnection dry-runs one stored connection: it builds the real protocol
// adapter, which parses SAML metadata or runs OIDC discovery against the
// live issuer.
//
// WHY a Service method instead of adapter construction in the admin handler:
// only the Service holds the deployment's SP identity, so only it can test
// a SAML connection with the exact entity ID, key, and ACS URL the running
// server will present at login. Any status may be tested — untested is the
// expected state before the first test passes.
func (s *Service) TestConnection(ctx context.Context, connectionID string) error {
	if connectionID == "" {
		return fmt.Errorf("flow: test connection: connection ID is required")
	}
	conn, err := s.store.GetConnection(ctx, connectionID)
	if err != nil {
		return fmt.Errorf("flow: test connection: %w", err)
	}
	switch conn.Type {
	case connection.ConnectionTypeOIDC:
		if _, err := s.getOIDCAdapter(ctx, conn); err != nil {
			return fmt.Errorf("flow: test connection: %w", err)
		}
		return nil
	case connection.ConnectionTypeSAML:
		if _, err := s.getSAMLAdapter(conn); err != nil {
			return fmt.Errorf("flow: test connection: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("flow: test connection: connection %q has unknown type %q", conn.ID, conn.Type)
	}
}
