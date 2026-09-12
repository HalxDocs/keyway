package api

import (
	"net/http"
)

// handleAuthorize starts one login: it validates the tenant and redirect,
// stores the pending login, and redirects the user to their IdP.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	tenantID := query.Get("tenant")
	redirectURI := query.Get("redirect_uri")
	if tenantID == "" || redirectURI == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant and redirect_uri are required")
		return
	}
	loginURL, err := s.flow.StartLogin(r.Context(), tenantID, redirectURI, query.Get("connection"), query.Get("state"))
	if err != nil {
		s.log.Info("authorize", "result", "error", "tenant", tenantID, "err", err)
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.log.Info("authorize", "result", "redirect", "tenant", tenantID)
	http.Redirect(w, r, loginURL, http.StatusFound)
}
