package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"keyway/internal/flow"
	"keyway/internal/tenant"
)

// TenantCreate records one customer boundary on the database file.
func TenantCreate(store flow.Storage, id, name string, redirectURIs []string) (string, error) {
	if id == "" || name == "" {
		return "", fmt.Errorf("cli: tenant create: id and name are required")
	}
	t := tenant.Tenant{ID: id, Name: name,
		AllowedRedirectURIs: redirectURIs, CreatedAt: time.Now().UTC()}
	if err := store.CreateTenant(context.Background(), t); err != nil {
		return "", fmt.Errorf("cli: tenant create: %w", err)
	}
	return fmt.Sprintf("tenant %q created", id), nil
}

// TenantList prints one line per customer.
func TenantList(store flow.Storage) (string, error) {
	tenants, err := store.ListTenants(context.Background())
	if err != nil {
		return "", fmt.Errorf("cli: tenant list: %w", err)
	}
	if len(tenants) == 0 {
		return "no tenants", nil
	}
	var lines []string
	for _, t := range tenants {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%d redirect URIs", t.ID, t.Name, len(t.AllowedRedirectURIs)))
	}
	return strings.Join(lines, "\n"), nil
}
