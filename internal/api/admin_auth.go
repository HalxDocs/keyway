package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// requireAdmin gates one admin handler behind the static bearer token when
// one is configured. Empty configured token means open: the deliberate
// localhost-dev posture, never the production one (see WithAdminToken).
// Comparison is constant-time so a wrong token reveals nothing about the
// right one beyond rejection.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			next(w, r)
			return
		}
		got, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || subtle.ConstantTimeCompare([]byte(got), []byte(s.adminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "admin token is missing or invalid")
			return
		}
		next(w, r)
	}
}
