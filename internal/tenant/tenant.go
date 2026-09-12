// Package tenant owns the customer boundary for Keyway.
//
// WHY this package exists: every login, connection, and redirect decision
// must be attributable to exactly one customer. Keeping Tenant in its own
// package stops later code from treating tenant IDs as bare strings that
// can be mixed up across customers.
package tenant

import "time"

// Tenant isolates one customer's SSO configuration from every other
// customer's.
//
// WHY this struct exists: without an explicit customer record there is
// nowhere to anchor the per-tenant redirect_uri allowlist, so an attacker
// could reuse a valid code against another customer's callback URL.
type Tenant struct {
	// ID is the stable, unique handle used in admin API paths and storage keys.
	ID string

	// Name is the human-readable label shown in admin output and audit logs.
	Name string

	// AllowedRedirectURIs is the closed allowlist for this tenant's
	// application callback URLs. Empty means deny all, so a tenant with
	// no configured callbacks cannot complete a login.
	AllowedRedirectURIs []string

	// CreatedAt records when the tenant was provisioned, for audit trails.
	CreatedAt time.Time
}

// IsRedirectAllowed reports whether uri is an exact member of the tenant's
// allowlist.
//
// WHY this method exists: the unified auth flow ends with a redirect back
// to the customer's app, which is an open-redirect vector. Centralizing the
// check here (instead of ad-hoc string compares in handlers) guarantees one
// strict exact-match rule everywhere. Exact match is deliberate: prefix or
// substring matching would let evil-callback.example pass for a
// callback.example entry.
func (t Tenant) IsRedirectAllowed(uri string) bool {
	if uri == "" {
		return false
	}
	for _, allowed := range t.AllowedRedirectURIs {
		if allowed == "" {
			continue
		}
		if uri == allowed {
			return true
		}
	}
	return false
}
