package flow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"keyway/internal/connection"
	"keyway/internal/oidc"
	"keyway/internal/saml"
	"keyway/internal/tenant"
)

// randomHex returns n random bytes as hex for states, nonces, and relay values.
func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("flow: random: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func (s *Service) getOIDCAdapter(ctx context.Context, conn connection.Connection) (*oidc.Adapter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if adapter, ok := s.oidc[conn.ID]; ok {
		return adapter, nil
	}
	adapter, err := oidc.NewAdapter(ctx, conn, oidc.DefaultDiscover)
	if err != nil {
		return nil, err
	}
	s.oidc[conn.ID] = adapter
	return adapter, nil
}

func (s *Service) getSAMLAdapter(conn connection.Connection) (*saml.Adapter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if adapter, ok := s.samls[conn.ID]; ok {
		return adapter, nil
	}
	adapter, err := saml.NewAdapter(conn, saml.SPConfig{
		EntityID:    s.spEntityID,
		MetadataURL: s.baseURL + "/saml/metadata/" + conn.ID,
		ACSURL:      s.samlCallbackURL(conn.ID),
		Key:         s.spKey,
		Certificate: s.spCert,
	})
	if err != nil {
		return nil, err
	}
	s.samls[conn.ID] = adapter
	return adapter, nil
}

func (s *Service) startOIDC(ctx context.Context, t tenant.Tenant, conn connection.Connection, redirectURI, appState string) (string, error) {
	adapter, err := s.getOIDCAdapter(ctx, conn)
	if err != nil {
		return "", fmt.Errorf("flow: start login: %w", err)
	}
	state, err := randomHex(16)
	if err != nil {
		return "", err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return "", err
	}
	req, err := NewAuthRequest(NewAuthRequestParams{TenantID: t.ID,
		ConnectionID: conn.ID, Protocol: connection.ConnectionTypeOIDC,
		State: state, AppState: appState, Nonce: nonce,
		RedirectURI: redirectURI, Now: s.now()})
	if err != nil {
		return "", err
	}
	if err := s.store.SaveAuthRequest(ctx, req); err != nil {
		return "", fmt.Errorf("flow: start login: %w", err)
	}
	return adapter.AuthCodeURL(state, nonce, s.oidcCallbackURL(conn.ID)), nil
}

func (s *Service) startSAML(ctx context.Context, t tenant.Tenant, conn connection.Connection, redirectURI, appState string) (string, error) {
	adapter, err := s.getSAMLAdapter(conn)
	if err != nil {
		return "", fmt.Errorf("flow: start login: %w", err)
	}
	relay, err := randomHex(16)
	if err != nil {
		return "", err
	}
	challenge, err := adapter.StartLogin(relay)
	if err != nil {
		return "", fmt.Errorf("flow: start login: %w", err)
	}
	req, err := NewAuthRequest(NewAuthRequestParams{TenantID: t.ID,
		ConnectionID: conn.ID, Protocol: connection.ConnectionTypeSAML,
		State: relay, AppState: appState, SAMLRequestID: challenge.RequestID,
		RedirectURI: redirectURI, Now: s.now()})
	if err != nil {
		return "", err
	}
	if err := s.store.SaveAuthRequest(ctx, req); err != nil {
		return "", fmt.Errorf("flow: start login: %w", err)
	}
	return challenge.URL, nil
}
