package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
)

// rowScanner abstracts *sql.Row and *sql.Rows so one mapping function
// serves single-row and multi-row queries without duplicating the column
// list or the unseal logic.
type rowScanner interface {
	Scan(dest ...any) error
}

// CreateConnection records one IdP config, sealing the OIDC secret first.
//
// WHY sealing happens here and not in the caller: the storage boundary is
// the last place plaintext may legally exist. Callers hand over the
// plaintext secret in OIDC.ClientSecretEncrypted (a courier field despite
// its name); only ciphertext ever reaches the database file.
func (s *SQLiteStore) CreateConnection(ctx context.Context, c connection.Connection) error {
	var samlMetadata, oidcIssuer, oidcClientID string
	// Empty (not nil) so the NOT NULL column never receives NULL for
	// connections without a sealable secret, e.g. secret-less clients.
	sealed := []byte{}
	if c.SAML != nil {
		samlMetadata = c.SAML.MetadataXML
	}
	if c.OIDC != nil {
		oidcIssuer = c.OIDC.IssuerURL
		oidcClientID = c.OIDC.ClientID
		if c.OIDC.ClientSecretEncrypted != "" {
			var err error
			sealed, err = s.box.Seal([]byte(c.OIDC.ClientSecretEncrypted))
			if err != nil {
				return fmt.Errorf("storage: create connection %q: %w", c.ID, err)
			}
		}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO connections(id, tenant_id, type, status, saml_metadata,
		 oidc_issuer, oidc_client_id, oidc_secret_sealed,
		 attr_email, attr_name, attr_groups, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, string(c.Type), string(c.Status), samlMetadata,
		oidcIssuer, oidcClientID, sealed,
		c.AttributeMap.EmailClaim, c.AttributeMap.NameClaim, c.AttributeMap.GroupsClaim,
		c.CreatedAt.Unix())
	if err != nil {
		return fmt.Errorf("storage: create connection %q: %w", c.ID, err)
	}
	return nil
}

// connectionFromRow maps one result row to a Connection, unsealing the OIDC
// secret for in-memory use. Plaintext exists only in the returned struct,
// never in logs or on disk.
func (s *SQLiteStore) connectionFromRow(row rowScanner) (connection.Connection, error) {
	var c connection.Connection
	var connType, status string
	var samlMetadata, oidcIssuer, oidcClientID string
	var sealed []byte
	var created int64
	err := row.Scan(&c.ID, &c.TenantID, &connType, &status, &samlMetadata,
		&oidcIssuer, &oidcClientID, &sealed, &c.AttributeMap.EmailClaim,
		&c.AttributeMap.NameClaim, &c.AttributeMap.GroupsClaim, &created)
	if err != nil {
		return connection.Connection{}, err
	}
	c.Type = connection.ConnectionType(connType)
	c.Status = connection.ConnectionStatus(status)
	c.CreatedAt = time.Unix(created, 0).UTC()
	if samlMetadata != "" {
		c.SAML = &connection.SAMLConnectionConfig{MetadataXML: samlMetadata}
	}
	if oidcIssuer != "" {
		c.OIDC = &connection.OIDCConnectionConfig{
			IssuerURL: oidcIssuer,
			ClientID:  oidcClientID,
		}
		if len(sealed) > 0 {
			plain, err := s.box.Unseal(sealed)
			if err != nil {
				return connection.Connection{}, fmt.Errorf("storage: unseal connection %q: %w", c.ID, err)
			}
			c.OIDC.ClientSecretEncrypted = string(plain)
		}
	}
	return c, nil
}

const connectionColumns = `id, tenant_id, type, status, saml_metadata, oidc_issuer,
	oidc_client_id, oidc_secret_sealed, attr_email, attr_name, attr_groups, created_at`

// GetConnection fetches one IdP config by ID.
func (s *SQLiteStore) GetConnection(ctx context.Context, id string) (connection.Connection, error) {
	c, err := s.connectionFromRow(s.db.QueryRowContext(ctx,
		`SELECT `+connectionColumns+` FROM connections WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return connection.Connection{}, flow.ErrNotFound
	}
	if err != nil {
		return connection.Connection{}, fmt.Errorf("storage: get connection %q: %w", id, err)
	}
	return c, nil
}

// ListConnectionsByTenant enumerates one tenant's IdP configs and no one else's.
func (s *SQLiteStore) ListConnectionsByTenant(ctx context.Context, tenantID string) ([]connection.Connection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+connectionColumns+` FROM connections WHERE tenant_id = ? ORDER BY id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("storage: list connections: %w", err)
	}
	defer rows.Close()
	var connections []connection.Connection
	for rows.Next() {
		c, err := s.connectionFromRow(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: list connections: %w", err)
		}
		connections = append(connections, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list connections: %w", err)
	}
	return connections, nil
}

// DeleteConnection removes one IdP config.
func (s *SQLiteStore) DeleteConnection(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM connections WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("storage: delete connection %q: %w", id, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: delete connection %q: %w", id, err)
	}
	if affected == 0 {
		return flow.ErrNotFound
	}
	return nil
}
