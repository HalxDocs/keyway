package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/tenant"
)

func testCLIStore(t *testing.T) flow.Storage {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Setenv("KEYWAY_MASTER_KEY", hex.EncodeToString(raw))
	store, err := OpenStore(filepath.Join(t.TempDir(), "cli.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestKeygenAndOpenStore(t *testing.T) {
	key, err := Keygen()
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("key length = %d, want 64 hex chars", len(key))
	}
	t.Setenv("KEYWAY_MASTER_KEY", "")
	if _, err := OpenStore(filepath.Join(t.TempDir(), "x.db")); err == nil {
		t.Errorf("missing env: expected rejection, got nil error")
	}
}

func TestTenantCommands(t *testing.T) {
	store := testCLIStore(t)
	out, err := TenantCreate(store, "acme", "Acme", []string{"https://app.example/cb"})
	if err != nil {
		t.Fatalf("TenantCreate: %v", err)
	}
	if !strings.Contains(out, "acme") {
		t.Errorf("output = %q", out)
	}
	listed, err := TenantList(store)
	if err != nil {
		t.Fatalf("TenantList: %v", err)
	}
	if !strings.Contains(listed, "acme") {
		t.Errorf("list = %q", listed)
	}
	if _, err := TenantCreate(store, "", "", nil); err == nil {
		t.Errorf("empty tenant: expected rejection, got nil error")
	}
}

func TestConnectionAddValidates(t *testing.T) {
	store := testCLIStore(t)
	ctx := context.Background()
	if err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	_, err := ConnectionAdd(store, ConnectionAddParams{TenantID: "acme",
		Type: connection.ConnectionTypeOIDC, IssuerURL: "https://issuer.test", ClientID: "c1"})
	if err == nil {
		t.Errorf("empty email claim: expected rejection, got nil error")
	}
	out, err := ConnectionAdd(store, ConnectionAddParams{TenantID: "acme",
		Type: connection.ConnectionTypeOIDC, IssuerURL: "https://issuer.test",
		ClientID: "c1", EmailClaim: "email"})
	if err != nil {
		t.Fatalf("ConnectionAdd: %v", err)
	}
	if !strings.Contains(out, "untested") {
		t.Errorf("output = %q", out)
	}
	if _, err := ConnectionDelete(store, "nope"); err == nil {
		t.Errorf("delete unknown: expected rejection, got nil error")
	}
}

func TestConnectionActivate(t *testing.T) {
	store := testCLIStore(t)
	ctx := context.Background()
	if err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	out, err := ConnectionAdd(store, ConnectionAddParams{TenantID: "acme",
		Type: connection.ConnectionTypeOIDC, IssuerURL: "https://issuer.test",
		ClientID: "c1", EmailClaim: "email"})
	if err != nil {
		t.Fatalf("ConnectionAdd: %v", err)
	}
	if !strings.Contains(out, "untested") {
		t.Errorf("add output = %q", out)
	}
	conns, err := store.ListConnectionsByTenant(ctx, "acme")
	if err != nil || len(conns) != 1 {
		t.Fatalf("ListConnectionsByTenant = %v, %v; want 1 connection", conns, err)
	}
	connID := conns[0].ID
	activated, err := ConnectionActivate(store, connID)
	if err != nil {
		t.Fatalf("ConnectionActivate: %v", err)
	}
	if !strings.Contains(activated, "activated") {
		t.Errorf("output = %q", activated)
	}
	got, err := store.GetConnection(ctx, connID)
	if err != nil {
		t.Fatalf("GetConnection: %v", err)
	}
	if got.Status != connection.ConnectionStatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
	again, err := ConnectionActivate(store, connID)
	if err != nil {
		t.Fatalf("re-activate: %v", err)
	}
	if !strings.Contains(again, "already active") {
		t.Errorf("output = %q", again)
	}
	if _, err := ConnectionActivate(store, "nope"); err == nil {
		t.Errorf("activate unknown: expected rejection, got nil error")
	}
	if err := store.UpdateConnectionStatus(ctx, connID, connection.ConnectionStatusDisabled); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := ConnectionActivate(store, connID); err == nil {
		t.Errorf("activate disabled: expected rejection, got nil error")
	}
}
