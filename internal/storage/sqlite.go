package storage

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"

	"keyway/internal/secret"
)

// schemaV1 creates every table Keyway needs. A single versioned exec keeps
// v1 honest: there is exactly one schema, applied idempotently at open.
const schemaV1 = `
CREATE TABLE IF NOT EXISTS tenants(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connections(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  status TEXT NOT NULL,
  saml_metadata TEXT NOT NULL DEFAULT '',
  oidc_issuer TEXT NOT NULL DEFAULT '',
  oidc_client_id TEXT NOT NULL DEFAULT '',
  oidc_secret_sealed BLOB NOT NULL DEFAULT x'',
  attr_email TEXT NOT NULL DEFAULT '',
  attr_name TEXT NOT NULL DEFAULT '',
  attr_groups TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connections_tenant ON connections(tenant_id);
CREATE TABLE IF NOT EXISTS auth_requests(
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  protocol TEXT NOT NULL,
  state TEXT NOT NULL,
  app_state TEXT NOT NULL DEFAULT '',
  nonce TEXT NOT NULL DEFAULT '',
  saml_request_id TEXT NOT NULL DEFAULT '',
  redirect_uri TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_requests_state ON auth_requests(state);
CREATE TABLE IF NOT EXISTS auth_codes(
  code TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  identity_json TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
PRAGMA user_version = 1;
`

// SQLiteStore persists Keyway records in a single SQLite file.
//
// WHY this struct exists: self-hosters get zero-infrastructure storage —
// one file, no server — behind the same Storage interface Postgres will
// implement later. The secret box is required, never optional, so sealed
// OIDC secrets cannot degrade to plaintext by misconfiguration.
type SQLiteStore struct {
	db  *sql.DB
	box *secret.Box
}

// NewSQLiteStore opens (creating if needed) the database file and applies
// the schema. A nil secret box fails fast: storing connections without
// encryption is a misconfiguration, not a supported mode.
func NewSQLiteStore(path string, box *secret.Box) (*SQLiteStore, error) {
	if path == "" {
		return nil, fmt.Errorf("storage: open sqlite: empty database path")
	}
	if box == nil {
		return nil, fmt.Errorf("storage: open sqlite: secret box is required")
	}
	dsn := "file:" + path + "?_pragma=busy_timeout%3d5000&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: open sqlite: %w", err)
	}
	if _, err := db.Exec(schemaV1); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: open sqlite: apply schema: %w", err)
	}
	return &SQLiteStore{db: db, box: box}, nil
}

// Close releases the database file.
func (s *SQLiteStore) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("storage: close sqlite: %w", err)
	}
	return nil
}
