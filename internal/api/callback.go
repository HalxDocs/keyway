package api

import (
	"net/http"
	"net/url"

	"keyway/internal/flow"
)

// handleOIDCCallback completes one OIDC login: code plus state in,
// application redirect with a single-use code out.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	connectionID := r.PathValue("connectionID")
	query := r.URL.Query()
	code, state := query.Get("code"), query.Get("state")
	if connectionID == "" || code == "" || state == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "connection, code, and state are required")
		return
	}
	result, err := s.flow.FinishOIDC(r.Context(), connectionID, code, state)
	if err != nil {
		s.log.Info("callback", "protocol", "oidc", "result", "error", "err", err)
		writeError(w, http.StatusBadRequest, "login_failed", err.Error())
		return
	}
	s.redirectWithCode(w, r, result)
}

// handleSAMLCallback completes one SAML login: the posted response plus
// relay state in, application redirect with a single-use code out. Both GET
// and POST serve it because bindings vary by IdP; r.Form covers both.
func (s *Server) handleSAMLCallback(w http.ResponseWriter, r *http.Request) {
	connectionID := r.PathValue("connectionID")
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "unreadable callback request")
		return
	}
	responseB64, relayState := r.Form.Get("SAMLResponse"), r.Form.Get("RelayState")
	if connectionID == "" || responseB64 == "" || relayState == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "connection, SAMLResponse, and RelayState are required")
		return
	}
	result, err := s.flow.FinishSAML(r.Context(), connectionID, responseB64, relayState)
	if err != nil {
		s.log.Info("callback", "protocol", "saml", "result", "error", "err", err)
		writeError(w, http.StatusBadRequest, "login_failed", err.Error())
		return
	}
	s.redirectWithCode(w, r, result)
}

// redirectWithCode sends the user back to their application carrying the
// code (and the application's own state, verbatim when present).
func (s *Server) redirectWithCode(w http.ResponseWriter, r *http.Request, result flow.FinishResult) {
	target, err := url.ParseRequestURI(result.RedirectURI)
	if err != nil {
		writeError(w, http.StatusBadGateway, "login_failed", "stored redirect URI is invalid")
		return
	}
	params := target.Query()
	params.Set("code", result.Code)
	if result.AppState != "" {
		params.Set("state", result.AppState)
	}
	target.RawQuery = params.Encode()
	s.log.Info("callback", "result", "redirect")
	http.Redirect(w, r, target.String(), http.StatusFound)
}
