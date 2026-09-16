package storage

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
	"keyway/internal/secret"
	"keyway/internal/tenant"
)

// newTestStore opens a temp-file database with a random master key.
func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	key := make([]byte, secret.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	box, err := secret.NewBox(key)
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "keyway.db"), box)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestOpenRequiresBox(t *testing.T) {
	if _, err := NewSQLiteStore(filepath.Join(t.TempDir(), "k.db"), nil); err == nil {
		t.Errorf("nil box: expected rejection, got nil error")
	}
	if _, err := NewSQLiteStore("", nil); err == nil {
		t.Errorf("empty path: expected rejection, got nil error")
	}
}

func TestTenantRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	want := tenant.Tenant{
		ID:                  "acme",
		Name:                "Acme",
		AllowedRedirectURIs: []string{"https://app.acme.example/callback"},
		CreatedAt:           time.Now().UTC().Truncate(time.Second),
	}
	if err := store.CreateTenant(ctx, want); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	got, err := store.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Name != want.Name || len(got.AllowedRedirectURIs) != 1 || got.AllowedRedirectURIs[0] != want.AllowedRedirectURIs[0] {
		t.Errorf("round trip mismatch: %+v", got)
	}
	tenants, err := store.ListTenants(ctx)
	if err != nil || len(tenants) != 1 {
		t.Fatalf("ListTenants = %v, %v; want 1 tenant", tenants, err)
	}
	if _, err := store.GetTenant(ctx, "unknown"); err != flow.ErrNotFound {
		t.Errorf("missing tenant: want ErrNotFound, got %v", err)
	}
}

func TestConnectionSecretSealed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	conn := connection.Connection{
		ID:       "conn-1",
		TenantID: "acme",
		Type:     connection.ConnectionTypeOIDC,
		OIDC: &connection.OIDCConnectionConfig{
			IssuerURL:             "https://issuer.test",
			ClientID:              "client-1",
			ClientSecretEncrypted: "super-secret-value",
		},
		AttributeMap: connection.AttributeMap{EmailClaim: "email"},
		Status:       connection.ConnectionStatusActive,
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
	}
	if err := store.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	var raw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT oidc_secret_sealed FROM connections WHERE id = ?`, "conn-1").Scan(&raw); err != nil {
		t.Fatalf("read raw secret: %v", err)
	}
	if strings.Contains(string(raw), "super-secret-value") {
		t.Errorf("secret stored in plaintext")
	}
	got, err := store.GetConnection(ctx, "conn-1")
	if err != nil {
		t.Fatalf("GetConnection: %v", err)
	}
	if got.OIDC == nil || got.OIDC.ClientSecretEncrypted != "super-secret-value" {
		t.Errorf("secret round trip failed: %+v", got.OIDC)
	}

	other := tenant.Tenant{ID: "other", Name: "Other", CreatedAt: time.Now()}
	if err := store.CreateTenant(ctx, other); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	conns, err := store.ListConnectionsByTenant(ctx, "other")
	if err != nil || len(conns) != 0 {
		t.Fatalf("isolation: other tenant sees %v, %v", conns, err)
	}
	if err := store.DeleteConnection(ctx, "conn-1"); err != nil {
		t.Fatalf("DeleteConnection: %v", err)
	}
	if _, err := store.GetConnection(ctx, "conn-1"); err != flow.ErrNotFound {
		t.Errorf("deleted connection: want ErrNotFound, got %v", err)
	}
}

func TestUpdateConnectionStatus(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if err := store.CreateTenant(ctx, tenant.Tenant{ID: "acme", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	conn := connection.Connection{
		ID:           "conn-1",
		TenantID:     "acme",
		Type:         connection.ConnectionTypeOIDC,
		OIDC:         &connection.OIDCConnectionConfig{IssuerURL: "https://issuer.test", ClientID: "c1"},
		AttributeMap: connection.AttributeMap{EmailClaim: "email"},
		Status:       connection.ConnectionStatusUntested,
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
	}
	if err := store.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	if err := store.UpdateConnectionStatus(ctx, "conn-1", connection.ConnectionStatusActive); err != nil {
		t.Fatalf("UpdateConnectionStatus to active: %v", err)
	}
	got, err := store.GetConnection(ctx, "conn-1")
	if err != nil {
		t.Fatalf("GetConnection: %v", err)
	}
	if got.Status != connection.ConnectionStatusActive {
		t.Errorf("status = %q, want %q", got.Status, connection.ConnectionStatusActive)
	}
	if err := store.UpdateConnectionStatus(ctx, "conn-1", connection.ConnectionStatusDisabled); err != nil {
		t.Fatalf("UpdateConnectionStatus to disabled: %v", err)
	}
	if err := store.UpdateConnectionStatus(ctx, "conn-1", connection.ConnectionStatusUntested); err == nil {
		t.Errorf("regress to untested: expected rejection, got nil error")
	}
	if err := store.UpdateConnectionStatus(ctx, "conn-1", "bogus"); err == nil {
		t.Errorf("bogus status: expected rejection, got nil error")
	}
	if err := store.UpdateConnectionStatus(ctx, "nope", connection.ConnectionStatusActive); err != flow.ErrNotFound {
		t.Errorf("missing connection: want ErrNotFound, got %v", err)
	}
}
