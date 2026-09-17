package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"keyway/internal/flow"
	"keyway/internal/tenant"
)

// CreateTenant records a new customer boundary.
func (s *SQLiteStore) CreateTenant(ctx context.Context, t tenant.Tenant) error {
	uris, err := json.Marshal(t.AllowedRedirectURIs)
	if err != nil {
		return fmt.Errorf("storage: create tenant %q: %w", t.ID, err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO tenants(id, name, redirect_uris, created_at) VALUES(?, ?, ?, ?)`,
		t.ID, t.Name, string(uris), t.CreatedAt.Unix())
	if err != nil {
		return fmt.Errorf("storage: create tenant %q: %w", t.ID, err)
	}
	return nil
}

// GetTenant fetches one customer by ID.
func (s *SQLiteStore) GetTenant(ctx context.Context, id string) (tenant.Tenant, error) {
	var t tenant.Tenant
	var uris string
	var created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, redirect_uris, created_at FROM tenants WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &uris, &created)
	if err == sql.ErrNoRows {
		return tenant.Tenant{}, flow.ErrNotFound
	}
	if err != nil {
		return tenant.Tenant{}, fmt.Errorf("storage: get tenant %q: %w", id, err)
	}
	if err := json.Unmarshal([]byte(uris), &t.AllowedRedirectURIs); err != nil {
		return tenant.Tenant{}, fmt.Errorf("storage: get tenant %q: %w", id, err)
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	return t, nil
}

// ListTenants enumerates customers for the admin API and status output.
func (s *SQLiteStore) ListTenants(ctx context.Context) ([]tenant.Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, redirect_uris, created_at FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("storage: list tenants: %w", err)
	}
	defer rows.Close()
	var tenants []tenant.Tenant
	for rows.Next() {
		var t tenant.Tenant
		var uris string
		var created int64
		if err := rows.Scan(&t.ID, &t.Name, &uris, &created); err != nil {
			return nil, fmt.Errorf("storage: list tenants: %w", err)
		}
		if err := json.Unmarshal([]byte(uris), &t.AllowedRedirectURIs); err != nil {
			return nil, fmt.Errorf("storage: list tenants: %w", err)
		}
		t.CreatedAt = time.Unix(created, 0).UTC()
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("storage: list tenants: %w", err)
	}
	return tenants, nil
}

// AddTenantRedirectURI appends one callback URL to a tenant's allowlist.
// The URI must be absolute (exact-match allowlist, same rule as login time)
// and duplicates are ignored: the allowlist is a set, not a log.
func (s *SQLiteStore) AddTenantRedirectURI(ctx context.Context, tenantID, uri string) error {
	if _, err := url.ParseRequestURI(uri); err != nil {
		return fmt.Errorf("storage: add redirect URI: invalid URI %q: %w", uri, err)
	}
	t, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, existing := range t.AllowedRedirectURIs {
		if existing == uri {
			return nil
		}
	}
	return s.setTenantRedirectURIs(ctx, tenantID, append(t.AllowedRedirectURIs, uri))
}

// RemoveTenantRedirectURI drops one callback URL from a tenant's allowlist.
func (s *SQLiteStore) RemoveTenantRedirectURI(ctx context.Context, tenantID, uri string) error {
	t, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	kept := t.AllowedRedirectURIs[:0]
	found := false
	for _, existing := range t.AllowedRedirectURIs {
		if existing == uri {
			found = true
			continue
		}
		kept = append(kept, existing)
	}
	if !found {
		return fmt.Errorf("storage: remove redirect URI: %q is not allowlisted for tenant %q", uri, tenantID)
	}
	if kept == nil {
		kept = []string{}
	}
	return s.setTenantRedirectURIs(ctx, tenantID, kept)
}

func (s *SQLiteStore) setTenantRedirectURIs(ctx context.Context, tenantID string, uris []string) error {
	raw, err := json.Marshal(uris)
	if err != nil {
		return fmt.Errorf("storage: set redirect URIs: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE tenants SET redirect_uris = ? WHERE id = ?`, string(raw), tenantID)
	if err != nil {
		return fmt.Errorf("storage: set redirect URIs for tenant %q: %w", tenantID, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: set redirect URIs for tenant %q: %w", tenantID, err)
	}
	if affected == 0 {
		return flow.ErrNotFound
	}
	return nil
}
