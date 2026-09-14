package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
)

// SaveAuthRequest records one pending login started by /authorize.
func (s *SQLiteStore) SaveAuthRequest(ctx context.Context, r flow.AuthRequest) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_requests(id, tenant_id, connection_id, protocol, state,
		 app_state, nonce, saml_request_id, redirect_uri, expires_at, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.TenantID, r.ConnectionID, string(r.Protocol), r.State,
		r.AppState, r.Nonce, r.SAMLRequestID, r.RedirectURI,
		r.ExpiresAt.Unix(), r.CreatedAt.Unix())
	if err != nil {
		return fmt.Errorf("storage: save auth request %q: %w", r.ID, err)
	}
	return nil
}

// GetAuthRequest fetches one pending login by ID.
func (s *SQLiteStore) GetAuthRequest(ctx context.Context, id string) (flow.AuthRequest, error) {
	var r flow.AuthRequest
	var protocol string
	var expires, created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, connection_id, protocol, state, app_state, nonce,
		 saml_request_id, redirect_uri, expires_at, created_at
		 FROM auth_requests WHERE id = ?`, id).
		Scan(&r.ID, &r.TenantID, &r.ConnectionID, &protocol, &r.State,
			&r.AppState, &r.Nonce, &r.SAMLRequestID, &r.RedirectURI, &expires, &created)
	if err == sql.ErrNoRows {
		return flow.AuthRequest{}, flow.ErrNotFound
	}
	if err != nil {
		return flow.AuthRequest{}, fmt.Errorf("storage: get auth request %q: %w", id, err)
	}
	r.Protocol = connection.ConnectionType(protocol)
	r.ExpiresAt = time.Unix(expires, 0).UTC()
	r.CreatedAt = time.Unix(created, 0).UTC()
	return r, nil
}

// GetAuthRequestByState fetches one pending login by its opaque state value.
func (s *SQLiteStore) GetAuthRequestByState(ctx context.Context, state string) (flow.AuthRequest, error) {
	var r flow.AuthRequest
	var protocol string
	var expires, created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, connection_id, protocol, state, app_state, nonce,
		 saml_request_id, redirect_uri, expires_at, created_at
		 FROM auth_requests WHERE state = ?`, state).
		Scan(&r.ID, &r.TenantID, &r.ConnectionID, &protocol, &r.State,
			&r.AppState, &r.Nonce, &r.SAMLRequestID, &r.RedirectURI, &expires, &created)
	if err == sql.ErrNoRows {
		return flow.AuthRequest{}, flow.ErrNotFound
	}
	if err != nil {
		return flow.AuthRequest{}, fmt.Errorf("storage: get auth request: %w", err)
	}
	r.Protocol = connection.ConnectionType(protocol)
	r.ExpiresAt = time.Unix(expires, 0).UTC()
	r.CreatedAt = time.Unix(created, 0).UTC()
	return r, nil
}

// DeleteAuthRequest discards one pending login.
func (s *SQLiteStore) DeleteAuthRequest(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM auth_requests WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("storage: delete auth request %q: %w", id, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: delete auth request %q: %w", id, err)
	}
	if affected == 0 {
		return flow.ErrNotFound
	}
	return nil
}

// DeleteExpired removes pending logins and codes past their expiry,
// reporting how many records were removed.
func (s *SQLiteStore) DeleteExpired(ctx context.Context, nowUnix int64) (int64, error) {
	requests, err := s.db.ExecContext(ctx, `DELETE FROM auth_requests WHERE expires_at <= ?`, nowUnix)
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired: %w", err)
	}
	codes, err := s.db.ExecContext(ctx, `DELETE FROM auth_codes WHERE expires_at <= ?`, nowUnix)
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired: %w", err)
	}
	removedRequests, err := requests.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired: %w", err)
	}
	removedCodes, err := codes.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("storage: delete expired: %w", err)
	}
	return removedRequests + removedCodes, nil
}
