package api

import (
	"encoding/json"
	"net/http"
)

// handleHealth is a pure liveness probe: it answers whether this process is
// up and serving HTTP, nothing more. It deliberately touches no storage,
// no adapters, and no IdP — a probe that fails during an Auth0 outage or a
// transient SQLite lock would report the container unhealthy for a problem
// that is not the container's, and orchestrators would restart a healthy
// process. Deeper readiness checks, if ever wanted, belong in a separate
// endpoint with their own failure semantics.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
