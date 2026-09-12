// Package storage defines how Keyway persists tenants, connections, and
// the ephemeral records of the unified login flow.
//
// WHY this package exists: the auth flow needs tenant, connection, pending
// login, and code records without caring whether they live in SQLite or
// Postgres. A narrow interface keeps the flow layer testable with a fake
// and lets backends change without touching login logic. Implementations
// receive their dependencies via constructors and keep no package-level
// mutable state.
package storage

import (
	"context"
	"errors"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/tenant"
)

// ErrNotFound signals a missing record. For auth codes it deliberately
// covers unknown, expired, and already-consumed codes alike, so callers
// cannot be used as an oracle for which codes ever existed.
var ErrNotFound = errors.New("storage: record not found")

// Storage persists tenants, their IdP connections, and flow records.
//
// WHY an interface instead of a concrete store: code that depends on this
// interface (admin API, auth flow) runs against SQLite in production and a
// fake or temp-file database in tests with no changes.
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

	// SaveAuthRequest records one pending login started by /authorize.
	// Lookup by State at callback time is how the response is bound to the
	// exact login that produced it.
	SaveAuthRequest(ctx context.Context, r flow.AuthRequest) error

	// GetAuthRequest fetches one pending login by ID. Expiry is enforced
	// by the flow layer, which owns the clock for login-time decisions.
	GetAuthRequest(ctx context.Context, id string) (flow.AuthRequest, error)

	// DeleteAuthRequest discards one pending login after it completes,
	// fails, or is superseded, so stale logins cannot accumulate.
	DeleteAuthRequest(ctx context.Context, id string) error

	// IssueCode stores one single-use code carrying its verified Identity.
	IssueCode(ctx context.Context, c flow.AuthCode) error

	// ConsumeCode atomically redeems one code: a single DELETE with a
	// RETURNING clause enforces exactly-once redemption and the expiry
	// window in one statement, regardless of connection pool size.
	// Unknown, expired, or already-consumed codes all report ErrNotFound.
	ConsumeCode(ctx context.Context, code string, nowUnix int64) (flow.AuthCode, error)

	// DeleteExpired removes pending logins and codes past their expiry so
	// the database cannot fill with abandoned login attempts. It reports
	// how many records were removed.
	DeleteExpired(ctx context.Context, nowUnix int64) (int64, error)
}
