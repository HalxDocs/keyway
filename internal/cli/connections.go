package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"keyway/internal/connection"
	"keyway/internal/flow"
)

// ConnectionAddParams carries one IdP registration. Only the fields for the
// chosen Type are read; the domain Validate call enforces the match.
type ConnectionAddParams struct {
	TenantID     string
	Type         connection.ConnectionType
	MetadataXML  string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	EmailClaim   string
	NameClaim    string
	GroupsClaim  string
}

// ConnectionAdd validates and stores one IdP config, reporting its handle.
// Email mapping is required up front so a bad config fails here, not at a
// user's first login.
func ConnectionAdd(store flow.Storage, p ConnectionAddParams) (string, error) {
	id, err := newConnID()
	if err != nil {
		return "", err
	}
	conn := connection.Connection{ID: "conn-" + id, TenantID: p.TenantID,
		Type: p.Type, Status: connection.ConnectionStatusUntested,
		AttributeMap: connection.AttributeMap{EmailClaim: p.EmailClaim,
			NameClaim: p.NameClaim, GroupsClaim: p.GroupsClaim},
		CreatedAt: time.Now().UTC()}
	switch p.Type {
	case connection.ConnectionTypeSAML:
		conn.SAML = &connection.SAMLConnectionConfig{MetadataXML: p.MetadataXML}
	case connection.ConnectionTypeOIDC:
		conn.OIDC = &connection.OIDCConnectionConfig{IssuerURL: p.IssuerURL,
			ClientID: p.ClientID, ClientSecretEncrypted: p.ClientSecret}
	}
	if err := conn.Validate(); err != nil {
		return "", fmt.Errorf("cli: connection add: %w", err)
	}
	if _, err := store.GetTenant(context.Background(), p.TenantID); err != nil {
		return "", fmt.Errorf("cli: connection add: unknown tenant %q", p.TenantID)
	}
	if err := store.CreateConnection(context.Background(), conn); err != nil {
		return "", fmt.Errorf("cli: connection add: %w", err)
	}
	return fmt.Sprintf("connection %q created (untested)", conn.ID), nil
}

// ConnectionList prints one line per IdP config of a tenant.
func ConnectionList(store flow.Storage, tenantID string) (string, error) {
	conns, err := store.ListConnectionsByTenant(context.Background(), tenantID)
	if err != nil {
		return "", fmt.Errorf("cli: connection list: %w", err)
	}
	if len(conns) == 0 {
		return "no connections", nil
	}
	var lines []string
	for _, c := range conns {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", c.ID, c.Type, c.Status))
	}
	return strings.Join(lines, "\n"), nil
}

// ConnectionDelete removes one IdP config.
func ConnectionDelete(store flow.Storage, id string) (string, error) {
	if err := store.DeleteConnection(context.Background(), id); err != nil {
		return "", fmt.Errorf("cli: connection delete: %w", err)
	}
	return fmt.Sprintf("connection %q deleted", id), nil
}
// ConnectionActivate approves one connection for logins. The legal states
// live on the domain transition; this function only fetches, persists, and
// reports, so its messages stay identical while the rules cannot drift from
// the admin API's.
func ConnectionActivate(store flow.Storage, id string) (string, error) {
	ctx := context.Background()
	conn, err := store.GetConnection(ctx, id)
	if err != nil {
		return "", fmt.Errorf("cli: connection activate: %w", err)
	}
	next, err := conn.Activate()
	if err != nil {
		return "", fmt.Errorf("cli: connection activate: %w", err)
	}
	if next.Status == conn.Status {
		return fmt.Sprintf("connection %q already active", id), nil
	}
	if err := store.UpdateConnectionStatus(ctx, id, next.Status); err != nil {
		return "", fmt.Errorf("cli: connection activate: %w", err)
	}
	return fmt.Sprintf("connection %q activated", id), nil
}

// ConnectionDisable takes one connection out of login service without
// deleting its config. Like activate, the legal states live on the domain
// transition; this function only fetches, persists, and reports.
func ConnectionDisable(store flow.Storage, id string) (string, error) {
	ctx := context.Background()
	conn, err := store.GetConnection(ctx, id)
	if err != nil {
		return "", fmt.Errorf("cli: connection disable: %w", err)
	}
	next, err := conn.Disable()
	if err != nil {
		return "", fmt.Errorf("cli: connection disable: %w", err)
	}
	if next.Status == conn.Status {
		return fmt.Sprintf("connection %q already disabled", id), nil
	}
	if err := store.UpdateConnectionStatus(ctx, id, next.Status); err != nil {
		return "", fmt.Errorf("cli: connection disable: %w", err)
	}
	return fmt.Sprintf("connection %q disabled", id), nil
}

func newConnID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cli: random ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
