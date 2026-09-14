package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"keyway/internal/flow"
)

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
