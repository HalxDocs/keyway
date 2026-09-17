package api

import (
	"encoding/json"
	"testing"
)

// TestHealthIsPureLiveness pins the /healthz contract: 200 with a fixed
// body, reachable without credentials, and — critically — servable with a
// nil store and nil flow service. If a future change threads storage or
// adapters into this handler, it cannot even construct the server, so the
// test fails at setup instead of letting coupling slip in silently.
func TestHealthIsPureLiveness(t *testing.T) {
	server := &Server{}
	rec := apiGet(t, server.Routes(), "/healthz")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("body = %v, want {status: ok}", body)
	}
}
