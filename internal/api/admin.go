package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"keyway/internal/tenant"
)

// CreateTenantRequest creates one customer boundary.
type CreateTenantRequest struct {
	// ID is the tenant handle used in /authorize?tenant= and admin paths.
	ID string `json:"id"`
	// Name is the human-readable label.
	Name string `json:"name"`
	// AllowedRedirectURIs is the closed callback allowlist; empty denies all.
	AllowedRedirectURIs []string `json:"redirect_uris"`
}

// TenantResponse echoes one tenant. Timestamps render as RFC3339.
type TenantResponse struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	AllowedRedirectURIs []string `json:"redirect_uris"`
	CreatedAt           string   `json:"created_at"`
}

func toTenantResponse(t tenant.Tenant) TenantResponse {
	return TenantResponse{ID: t.ID, Name: t.Name,
		AllowedRedirectURIs: t.AllowedRedirectURIs, CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339)}
}

// genID mints one random hex handle for server-assigned records.
func genID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("api: random ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// handleAdminCreateTenant records one tenant. Duplicate IDs conflict.
func (s *Server) handleAdminCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable tenant document")
		return
	}
	if req.ID == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id and name are required")
		return
	}
	t := tenant.Tenant{ID: req.ID, Name: req.Name,
		AllowedRedirectURIs: req.AllowedRedirectURIs, CreatedAt: time.Now().UTC()}
	if err := s.store.CreateTenant(r.Context(), t); err != nil {
		s.log.Info("admin", "op", "create-tenant", "result", "error", "err", err)
		writeError(w, conflictOrBadRequest(err), "tenant_exists", err.Error())
		return
	}
	s.log.Info("admin", "op", "create-tenant", "result", "ok", "tenant", t.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toTenantResponse(t))
}

// handleAdminListTenants enumerates tenants.
func (s *Server) handleAdminListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.store.ListTenants(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
		return
	}
	out := make([]TenantResponse, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, toTenantResponse(t))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// conflictOrBadRequest maps duplicate-key storage errors to 409 so operators
// can tell "already exists, fetch it" apart from "your document is wrong".
func conflictOrBadRequest(err error) int {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return http.StatusConflict
	}
	return http.StatusBadRequest
}
