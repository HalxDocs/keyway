// Package storage defines how Keyway persists tenants and connections.
//
// WHY this package exists: the auth flow needs tenant and connection
// records without caring whether they live in SQLite or Postgres. A narrow
// interface keeps the flow layer testable with a fake and lets the SQLite
// backend arrive after the protocol adapters prove themselves.
package storage

import (
	"context"

	"keyway/internal/connection"
	"keyway/internal/tenant"
)

// Storage persists tenants and their IdP connections.
//
// WHY an interface instead of a concrete store: Phase 1 must test the OIDC
// and SAML adapters against real IdPs before any database code exists. Code
// that depends on this interface (admin API, auth flow) can run against an
// in-memory fake now and a SQLite implementation later with no changes.
// Implementations receive their dependencies via constructors and keep no
// package-level mutable state.
type Storage interface {
	// CreateTenant records a new customer boundary. It fails when the ID
	// already exists so two tenants can never share one identity space.
	CreateTenant(ctx context.Context, t tenant.Tenant) error

	// GetTenant fetches one customer by ID for login-time allowlist and
	// connection lookups. Callers treat "not found" as an unknown tenant,
	// never as an empty tenant that would bypass checks.
	GetTenant(ctx context.Context, id string) (tenant.Tenant, error)

	// ListTenants enumerates customers for the admin API and status output.
	ListTenants(ctx context.Context) ([]tenant.Tenant, error)

	// CreateConnection records one IdP config under its owning tenant. It
	// fails when the ID already exists so callback URLs stay unambiguous.
	CreateConnection(ctx context.Context, c connection.Connection) error

	// GetConnection fetches one IdP config by ID for callback handling.
	GetConnection(ctx context.Context, id string) (connection.Connection, error)

	// ListConnectionsByTenant enumerates one tenant's IdP configs for the
	// admin API. It never returns connections belonging to other tenants.
	ListConnectionsByTenant(ctx context.Context, tenantID string) ([]connection.Connection, error)

	// DeleteConnection removes one IdP config so a decommissioned IdP can
	// no longer complete logins through its old callback URL.
	DeleteConnection(ctx context.Context, id string) error
}
