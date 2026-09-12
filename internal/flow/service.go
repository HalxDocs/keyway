package flow

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net/url"
	"sync"
	"time"

	"keyway/internal/connection"
	"keyway/internal/oidc"
	"keyway/internal/saml"
	"keyway/internal/tenant"
)

// Config carries the deployment identity the Service needs.
//
// WHY this struct exists: callback URLs and the SAML SP identity derive
// from one base URL plus one keypair. Passing them explicitly (instead of
// reading env inside the package) keeps construction honest and tests free
// of environment coupling.
type Config struct {
	// BaseURL is Keyway's public address; callback URLs derive from it.
	BaseURL string

	// SPEntityID identifies Keyway to SAML identity providers.
	SPEntityID string

	// SPKey and SPCert sign SAML authentication requests.
	SPKey  crypto.Signer
	SPCert *x509.Certificate
}

// Service orchestrates the unified login flow across both protocols.
//
// WHY this struct exists: starting, finishing, and redeeming logins spans
// storage, both adapters, and replay-protection checks that must run in one
// order. Centralizing that order here (instead of spreading it across HTTP
// handlers) means the security sequence is reviewed once and reused by
// every entry point. Protocol libraries never appear here: OIDC discovery
// arrives as oidc.DefaultDiscover and SAML arrives through its adapter, so
// this package imports no protocol-specific library.
type Service struct {
	store      Storage
	baseURL    string
	spEntityID string
	spKey      crypto.Signer
	spCert     *x509.Certificate
	now        func() time.Time

	mu    sync.Mutex
	oidc  map[string]*oidc.Adapter
	samls map[string]*saml.Adapter
}

// NewService builds the orchestrator. A nil store, blank base URL, or
// missing SP identity fails fast: logins cannot work without them, so
// starting broken is worse than not starting.
func NewService(store Storage, cfg Config) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("flow: new service: storage is required")
	}
	if _, err := url.ParseRequestURI(cfg.BaseURL); err != nil {
		return nil, fmt.Errorf("flow: new service: invalid base URL: %w", err)
	}
	if cfg.SPEntityID == "" || cfg.SPKey == nil || cfg.SPCert == nil {
		return nil, fmt.Errorf("flow: new service: service provider identity is incomplete")
	}
	return &Service{
		store: store, baseURL: cfg.BaseURL, spEntityID: cfg.SPEntityID,
		spKey: cfg.SPKey, spCert: cfg.SPCert, now: time.Now,
		oidc: make(map[string]*oidc.Adapter), samls: make(map[string]*saml.Adapter),
	}, nil
}

// Invalidate drops cached adapters for one connection after its config
// changes, so the next login rediscovers instead of trusting stale trust
// material.
func (s *Service) Invalidate(connectionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oidc, connectionID)
	delete(s.samls, connectionID)
}

func (s *Service) oidcCallbackURL(connectionID string) string {
	return s.baseURL + "/callback/oidc/" + connectionID
}

func (s *Service) samlCallbackURL(connectionID string) string {
	return s.baseURL + "/callback/saml/" + connectionID
}

// resolveConnection picks the login's connection: explicit ?connection= or,
// when blank, the tenant's single active connection. Zero or many active
// without an explicit choice is a loud rejection, never a silent first-row
// pick.
func (s *Service) resolveConnection(ctx context.Context, t tenant.Tenant, connectionID string) (connection.Connection, error) {
	if connectionID != "" {
		conn, err := s.store.GetConnection(ctx, connectionID)
		if err != nil {
			return connection.Connection{}, fmt.Errorf("flow: resolve connection: %w", err)
		}
		if conn.TenantID != t.ID {
			return connection.Connection{}, fmt.Errorf("flow: resolve connection: connection %q belongs to another tenant", connectionID)
		}
		if conn.Status != connection.ConnectionStatusActive {
			return connection.Connection{}, fmt.Errorf("flow: resolve connection: connection %q is %q, not active", connectionID, conn.Status)
		}
		return conn, nil
	}
	conns, err := s.store.ListConnectionsByTenant(ctx, t.ID)
	if err != nil {
		return connection.Connection{}, fmt.Errorf("flow: resolve connection: %w", err)
	}
	var active []connection.Connection
	for _, conn := range conns {
		if conn.Status == connection.ConnectionStatusActive {
			active = append(active, conn)
		}
	}
	if len(active) != 1 {
		return connection.Connection{}, fmt.Errorf("flow: resolve connection: tenant %q has %d active connections, specify one", t.ID, len(active))
	}
	return active[0], nil
}

// StartLogin begins one login: it validates the tenant and redirect,
// resolves the connection, stores the pending login, and returns the IdP
// redirect URL the user must visit.
func (s *Service) StartLogin(ctx context.Context, tenantID, redirectURI, connectionID, appState string) (string, error) {
	t, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("flow: start login: %w", err)
	}
	if !t.IsRedirectAllowed(redirectURI) {
		return "", fmt.Errorf("flow: start login: redirect URI not allowlisted")
	}
	conn, err := s.resolveConnection(ctx, t, connectionID)
	if err != nil {
		return "", err
	}
	switch conn.Type {
	case connection.ConnectionTypeOIDC:
		return s.startOIDC(ctx, t, conn, redirectURI, appState)
	case connection.ConnectionTypeSAML:
		return s.startSAML(ctx, t, conn, redirectURI, appState)
	default:
		return "", fmt.Errorf("flow: start login: connection %q has unknown type %q", conn.ID, conn.Type)
	}
}
