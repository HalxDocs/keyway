package tenant

import (
	"testing"
	"time"
)

// TestIsRedirectAllowedRejectsUnlistedURI proves the REJECT path.
//
// WHY this test exists: IsRedirectAllowed guards the end of the auth flow
// against open redirects. A passing happy-path test alone would hide a
// fail-open bug, so this test pins the deny behaviors: unknown URIs, empty
// input, empty allowlist entries, and prefix-match bypass attempts.
func TestIsRedirectAllowedRejectsUnlistedURI(t *testing.T) {
	tenant := Tenant{
		ID:                  "acme",
		Name:                "Acme",
		AllowedRedirectURIs: []string{"https://app.acme.example/callback", ""},
		CreatedAt:           time.Now(),
	}

	rejected := []string{
		"",
		"https://evil.example/callback",
		"https://app.acme.example/callback/extra",
		"https://app.acme.example",
		"https://app.acme.example/callbackevil",
	}

	for _, uri := range rejected {
		if tenant.IsRedirectAllowed(uri) {
			t.Errorf("IsRedirectAllowed(%q) = true, want false", uri)
		}
	}

	if !tenant.IsRedirectAllowed("https://app.acme.example/callback") {
		t.Errorf("IsRedirectAllowed(listed URI) = false, want true")
	}

	empty := Tenant{ID: "empty", Name: "Empty"}
	if empty.IsRedirectAllowed("https://app.acme.example/callback") {
		t.Errorf("IsRedirectAllowed on tenant with no allowlist = true, want false")
	}
}
