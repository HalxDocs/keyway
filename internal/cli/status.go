package cli

import (
	"context"
	"fmt"
	"os"

	"keyway/internal/flow"
)

// Status reports tenant and connection counts plus the database file size.
// Uptime and login counters need a running server's runtime metrics, which
// is Phase 2 observability — this reports what the file alone can prove.
func Status(store flow.Storage, dbPath string) (string, error) {
	tenants, err := store.ListTenants(context.Background())
	if err != nil {
		return "", fmt.Errorf("cli: status: %w", err)
	}
	connections := 0
	for _, t := range tenants {
		conns, err := store.ListConnectionsByTenant(context.Background(), t.ID)
		if err != nil {
			return "", fmt.Errorf("cli: status: %w", err)
		}
		connections += len(conns)
	}
	var size int64
	if info, err := os.Stat(dbPath); err == nil {
		size = info.Size()
	}
	return fmt.Sprintf("tenants: %d\nconnections: %d\nstorage: sqlite (%d bytes)", len(tenants), connections, size), nil
}
