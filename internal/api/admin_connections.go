package api

import (
	"encoding/json"
	"net/http"
	"time"

	"keyway/internal/connection"
)

// AttributeMapRequest declares which IdP claims feed normalized fields.
// EmailClaim is required: without it every login would fail closed later,
// so creation rejects it now instead.
type AttributeMapRequest struct {
	EmailClaim  string `json:"email"`
	NameClaim   string `json:"name"`
	GroupsClaim string `json:"groups"`
}

// CreateConnectionRequest registers one IdP config under a tenant. For SAML
// supply metadata_xml; for OIDC supply issuer_url, client_id, and
// client_secret (stored sealed, never returned).
type CreateConnectionRequest struct {
	Type         string              `json:"type"`
	MetadataXML  string              `json:"metadata_xml"`
	IssuerURL    string              `json:"issuer_url"`
	ClientID     string              `json:"client_id"`
	ClientSecret string              `json:"client_secret"`
	AttributeMap AttributeMapRequest `json:"attribute_map"`
}

// ConnectionResponse echoes one connection with the secret omitted entirely:
// no caller can mistake the response for a usable credential.
type ConnectionResponse struct {
	ID           string              `json:"id"`
	TenantID     string              `json:"tenant_id"`
	Type         string              `json:"type"`
	Status       string              `json:"status"`
	HasSecret    bool                `json:"has_secret"`
	AttributeMap AttributeMapRequest `json:"attribute_map"`
	CreatedAt    string              `json:"created_at"`
}

func toConnectionResponse(c connection.Connection) ConnectionResponse {
	return ConnectionResponse{ID: c.ID, TenantID: c.TenantID,
		Type: string(c.Type), Status: string(c.Status),
		HasSecret: c.OIDC != nil && c.OIDC.ClientSecretEncrypted != "",
		AttributeMap: AttributeMapRequest{EmailClaim: c.AttributeMap.EmailClaim,
			NameClaim: c.AttributeMap.NameClaim, GroupsClaim: c.AttributeMap.GroupsClaim},
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339)}
}

// handleAdminCreateConnection registers one IdP config. Domain validation
// rejects unknown types, mismatched configs, and empty email mappings with
// 400 before anything reaches storage.
func (s *Server) handleAdminCreateConnection(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenantID")
	var req CreateConnectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable connection document")
		return
	}
	if _, err := s.store.GetTenant(r.Context(), tenantID); err != nil {
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	}
	id, err := genID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	conn := connection.Connection{ID: "conn-" + id, TenantID: tenantID,
		Type: connection.ConnectionType(req.Type), Status: connection.ConnectionStatusUntested,
		AttributeMap: connection.AttributeMap{EmailClaim: req.AttributeMap.EmailClaim,
			NameClaim: req.AttributeMap.NameClaim, GroupsClaim: req.AttributeMap.GroupsClaim},
		CreatedAt: time.Now().UTC()}
	switch conn.Type {
	case connection.ConnectionTypeSAML:
		conn.SAML = &connection.SAMLConnectionConfig{MetadataXML: req.MetadataXML}
	case connection.ConnectionTypeOIDC:
		conn.OIDC = &connection.OIDCConnectionConfig{IssuerURL: req.IssuerURL,
			ClientID: req.ClientID, ClientSecretEncrypted: req.ClientSecret}
	}
	if err := conn.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.CreateConnection(r.Context(), conn); err != nil {
		s.log.Info("admin", "op", "create-connection", "result", "error", "err", err)
		writeError(w, conflictOrBadRequest(err), "connection_exists", err.Error())
		return
	}
	s.log.Info("admin", "op", "create-connection", "result", "ok", "tenant", tenantID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toConnectionResponse(conn))
}

// handleAdminListConnections enumerates one tenant's connections.
func (s *Server) handleAdminListConnections(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenantID")
	if _, err := s.store.GetTenant(r.Context(), tenantID); err != nil {
		writeError(w, http.StatusNotFound, "unknown_tenant", "no such tenant")
		return
	}
	conns, err := s.store.ListConnectionsByTenant(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
		return
	}
	out := make([]ConnectionResponse, 0, len(conns))
	for _, c := range conns {
		out = append(out, toConnectionResponse(c))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleAdminDeleteConnection removes one IdP config and drops any cached
// adapter, so a decommissioned IdP stops validating immediately.
func (s *Server) handleAdminDeleteConnection(w http.ResponseWriter, r *http.Request) {
	connectionID := r.PathValue("connectionID")
	if err := s.store.DeleteConnection(r.Context(), connectionID); err != nil {
		writeError(w, http.StatusNotFound, "unknown_connection", "no such connection")
		return
	}
	s.flow.Invalidate(connectionID)
	s.log.Info("admin", "op", "delete-connection", "result", "ok")
	w.WriteHeader(http.StatusNoContent)
}

// handleAdminTestConnection dry-runs one stored connection with the running
// server's exact SP identity: SAML metadata parses, OIDC discovery reaches
// the live issuer. Failures carry the wrapped detail for operators.
func (s *Server) handleAdminTestConnection(w http.ResponseWriter, r *http.Request) {
	connectionID := r.PathValue("connectionID")
	if err := s.flow.TestConnection(r.Context(), connectionID); err != nil {
		s.log.Info("admin", "op", "test-connection", "result", "error", "err", err)
		writeError(w, http.StatusBadRequest, "connection_invalid", err.Error())
		return
	}
	s.log.Info("admin", "op", "test-connection", "result", "ok")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleAdminActivateConnection approves one connection for logins. The
// legal transitions live on the domain type, shared with the CLI, so this
// handler only fetches, persists, and responds with the updated record.
func (s *Server) handleAdminActivateConnection(w http.ResponseWriter, r *http.Request) {
	s.changeConnectionStatus(w, r, "activate",
		func(c connection.Connection) (connection.Connection, error) { return c.Activate() })
}

// handleAdminDisableConnection takes one connection out of login service
// without deleting its config. Same shape as activate: domain decides,
// handler persists and responds.
func (s *Server) handleAdminDisableConnection(w http.ResponseWriter, r *http.Request) {
	s.changeConnectionStatus(w, r, "disable",
		func(c connection.Connection) (connection.Connection, error) { return c.Disable() })
}

func (s *Server) changeConnectionStatus(w http.ResponseWriter, r *http.Request, op string,
	transition func(connection.Connection) (connection.Connection, error)) {
	connectionID := r.PathValue("connectionID")
	conn, err := s.store.GetConnection(r.Context(), connectionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown_connection", "no such connection")
		return
	}
	next, err := transition(conn)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if next.Status != conn.Status {
		if err := s.store.UpdateConnectionStatus(r.Context(), connectionID, next.Status); err != nil {
			s.log.Info("admin", "op", op+"-connection", "result", "error", "err", err)
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		s.flow.Invalidate(connectionID)
	}
	s.log.Info("admin", "op", op+"-connection", "result", "ok")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toConnectionResponse(next))
}
