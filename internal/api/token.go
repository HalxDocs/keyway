package api

import (
	"encoding/json"
	"net/http"
)

// tokenResponse is the normalized identity the application receives. It
// mirrors normalize.Identity minus the debug-only raw claims, which never
// cross this boundary.
type tokenResponse struct {
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

// handleToken redeems one single-use code for its verified identity. Form-
// encoded like any OAuth2 token endpoint; the redirect URI must match the
// callback the login started with or redemption fails.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable token request")
		return
	}
	code, redirectURI := r.Form.Get("code"), r.Form.Get("redirect_uri")
	if code == "" || redirectURI == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}
	identity, err := s.flow.Redeem(r.Context(), code, redirectURI)
	if err != nil {
		s.log.Info("token", "result", "error", "err", err)
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	s.log.Info("token", "result", "ok")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{Email: identity.Email, Name: identity.Name, Groups: identity.Groups})
}
