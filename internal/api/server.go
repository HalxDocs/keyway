// Package api exposes Keyway's HTTP surface over the unified flow.
//
// WHY this package exists: HTTP parsing, redirects, and status codes are a
// separate concern from login orchestration. Handlers here translate wire
// values into flow.Service calls and results back into responses, holding
// no login state and importing no protocol libraries themselves.
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"keyway/internal/flow"
)

// Server serves the unified SSO flow endpoints plus the admin API.
//
// WHY one server for both: self-hosters run a single binary on localhost.
// Flow handlers use the orchestrator; admin handlers use storage directly
// (records, not logins) plus the orchestrator for cache invalidation and
// connection testing.
type Server struct {
	flow  *flow.Service
	store flow.Storage
	log   *slog.Logger
}

// NewServer builds the HTTP server over one flow orchestrator and its store.
func NewServer(flowSvc *flow.Service, store flow.Storage, logger *slog.Logger) (*Server, error) {
	if flowSvc == nil {
		return nil, fmt.Errorf("api: new server: flow service is required")
	}
	if store == nil {
		return nil, fmt.Errorf("api: new server: storage is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{flow: flowSvc, store: store, log: logger}, nil
}

// Routes wires the flow and admin endpoints onto a stdlib multiplexer.
// Method-plus-pattern routing covers this surface with no framework: the day
// the endpoint count outgrows readability is the day to revisit that call.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /callback/oidc/{connectionID}", s.handleOIDCCallback)
	mux.HandleFunc("GET /callback/saml/{connectionID}", s.handleSAMLCallback)
	mux.HandleFunc("POST /callback/saml/{connectionID}", s.handleSAMLCallback)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /saml/metadata/{connectionID}", s.handleSPMetadata)
	mux.HandleFunc("POST /admin/tenants", s.handleAdminCreateTenant)
	mux.HandleFunc("GET /admin/tenants", s.handleAdminListTenants)
	mux.HandleFunc("POST /admin/tenants/{tenantID}/connections", s.handleAdminCreateConnection)
	mux.HandleFunc("GET /admin/tenants/{tenantID}/connections", s.handleAdminListConnections)
	mux.HandleFunc("DELETE /admin/connections/{connectionID}", s.handleAdminDeleteConnection)
	mux.HandleFunc("POST /admin/connections/{connectionID}/test", s.handleAdminTestConnection)
	return mux
}

// writeError renders one JSON error without leaking internals: the code is
// stable for clients to switch on, the description carries the safe detail.
func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
