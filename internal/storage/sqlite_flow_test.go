package storage

import (
	"context"
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/normalize"
	"keyway/internal/tenant"
)

func TestAuthRequestRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	want, err := flow.NewAuthRequest(flow.NewAuthRequestParams{TenantID: "acme",
		ConnectionID: "conn-1", Protocol: connection.ConnectionTypeOIDC,
		State: "state-1", Nonce: "nonce-1", RedirectURI: "https://app/cb", Now: now})
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	if err := store.SaveAuthRequest(ctx, want); err != nil {
		t.Fatalf("SaveAuthRequest: %v", err)
	}
	got, err := store.GetAuthRequest(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetAuthRequest: %v", err)
	}
	if got.Protocol != connection.ConnectionTypeOIDC || got.Nonce != "nonce-1" || got.State != "state-1" {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if err := store.DeleteAuthRequest(ctx, want.ID); err != nil {
		t.Fatalf("DeleteAuthRequest: %v", err)
	}
	if _, err := store.GetAuthRequest(ctx, want.ID); err != flow.ErrNotFound {
		t.Errorf("deleted request: want ErrNotFound, got %v", err)
	}
}

func TestConsumeCodeExactlyOnce(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	code, err := flow.NewAuthCode("acme", normalize.Identity{Email: "ada@example.com"}, "https://app/cb", now)
	if err != nil {
		t.Fatalf("NewAuthCode: %v", err)
	}
	if err := store.IssueCode(ctx, code); err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	got, err := store.ConsumeCode(ctx, code.Code, now.Unix())
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if got.Identity.Email != "ada@example.com" {
		t.Errorf("consumed identity = %+v", got.Identity)
	}
	if _, err := store.ConsumeCode(ctx, code.Code, now.Unix()); err != flow.ErrNotFound {
		t.Errorf("second redemption: want ErrNotFound, got %v", err)
	}
	if _, err := store.ConsumeCode(ctx, "no-such-code", now.Unix()); err != flow.ErrNotFound {
		t.Errorf("unknown code: want ErrNotFound, got %v", err)
	}
}

func TestExpiredRecordsRejectedAndSwept(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	past := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	expiredCode := flow.AuthCode{
		Code: "expired-code", TenantID: "acme",
		Identity:    normalize.Identity{Email: "ada@example.com"},
		RedirectURI: "https://app/cb", ExpiresAt: past, CreatedAt: past,
	}
	if err := store.IssueCode(ctx, expiredCode); err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	if _, err := store.ConsumeCode(ctx, "expired-code", time.Now().Unix()); err != flow.ErrNotFound {
		t.Errorf("expired code: want ErrNotFound, got %v", err)
	}
	expiredReq, err := flow.NewAuthRequest(flow.NewAuthRequestParams{TenantID: "acme",
		ConnectionID: "conn-1", Protocol: connection.ConnectionTypeSAML,
		State: "relay-1", SAMLRequestID: "req-1", RedirectURI: "https://app/cb",
		Now: past.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("NewAuthRequest: %v", err)
	}
	if err := store.SaveAuthRequest(ctx, expiredReq); err != nil {
		t.Fatalf("SaveAuthRequest: %v", err)
	}
	removed, err := store.DeleteExpired(ctx, time.Now().Unix())
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if removed != 2 {
		t.Errorf("DeleteExpired removed %d, want 2", removed)
	}
}
