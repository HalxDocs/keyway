package api

import (
	"errors"
	"net/http"

	"keyway/internal/flow"
)

// handleSPMetadata serves the SP descriptor for one SAML connection.
//
// WHY per-connection: the ACS URL differs per connection, and IdPs pin it.
func (s *Server) handleSPMetadata(w http.ResponseWriter, r *http.Request) {
	connectionID := r.PathValue("connectionID")
	xmlBytes, err := s.flow.SPMetadata(r.Context(), connectionID)
	if err != nil {
		if errors.Is(err, flow.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown_connection", "no such connection")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_connection", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(xmlBytes)
}
