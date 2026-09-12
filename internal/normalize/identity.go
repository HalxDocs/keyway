// Package normalize owns the protocol-agnostic identity contract.
//
// WHY this package exists: SAML assertions and OIDC ID tokens describe the
// same person in wildly different shapes. Converting both to one Identity
// here lets every layer above (auth flow, token endpoint, client SDK) work
// without ever knowing which protocol was spoken.
package normalize

// RawClaims preserves the unmodified IdP claims for debugging.
//
// WHY a named map type exists: IdP claim sets are genuinely schemaless, so
// no struct can faithfully hold them. This is the single permitted
// map[string]any in the domain (rule 3 exception): it is populated only by
// the protocol adapters during parsing, never used for authorization
// decisions, and never written to logs.
type RawClaims map[string]any

// Identity is the normalized user record Keyway hands to the application.
//
// WHY this struct exists: it is the stability promise of the whole product.
// Regardless of whether the upstream IdP spoke SAML or OIDC, the app sees
// these exact fields and nothing else, so adding a new IdP or protocol
// never forces app-side changes.
type Identity struct {
	// Email is the normalized login identifier used for account matching.
	Email string

	// Name is the normalized human-readable display name.
	Name string

	// Groups carries normalized group or role memberships, possibly empty.
	Groups []string

	// RawClaims carries the original IdP claims for admin debugging only.
	RawClaims RawClaims
}
