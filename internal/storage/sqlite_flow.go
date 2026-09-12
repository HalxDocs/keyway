package storage

import (
	"context"
	"database/sql"
	"encoding/json"
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

// IssueCode stores one single-use code carrying its verified Identity.
func (s *SQLiteStore) IssueCode(ctx context.Context, c flow.AuthCode) error {
	identityJSON, err := json.Marshal(c.Identity)
	if err != nil {
		return fmt.Errorf("storage: issue code: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO auth_codes(code, tenant_id, identity_json, redirect_uri, expires_at, created_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		c.Code, c.TenantID, string(identityJSON), c.RedirectURI,
		c.ExpiresAt.Unix(), c.CreatedAt.Unix())
	if err != nil {
		return fmt.Errorf("storage: issue code: %w", err)
	}
	return nil
}

// ConsumeCode atomically redeems one code: a single DELETE with a RETURNING
// clause enforces exactly-once redemption and the expiry window in one
// statement, correct at any pool size. Unknown, expired, or already-consumed
// codes all report ErrNotFound, revealing nothing about which case applied.
func (s *SQLiteStore) ConsumeCode(ctx context.Context, code string, nowUnix int64) (flow.AuthCode, error) {
	var c flow.AuthCode
	var identityJSON string
	var expires, created int64
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM auth_codes WHERE code = ? AND expires_at > ?
		 RETURNING code, tenant_id, identity_json, redirect_uri, expires_at, created_at`,
		code, nowUnix).
		Scan(&c.Code, &c.TenantID, &identityJSON, &c.RedirectURI, &expires, &created)
	if err == sql.ErrNoRows {
		return flow.AuthCode{}, flow.ErrNotFound
	}
	if err != nil {
		return flow.AuthCode{}, fmt.Errorf("storage: consume code: %w", err)
	}
	if err := json.Unmarshal([]byte(identityJSON), &c.Identity); err != nil {
		return flow.AuthCode{}, fmt.Errorf("storage: consume code: %w", err)
	}
	c.ExpiresAt = time.Unix(expires, 0).UTC()
	c.CreatedAt = time.Unix(created, 0).UTC()
	return c, nil
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
