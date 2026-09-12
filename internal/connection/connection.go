// Package connection owns the per-tenant identity provider configuration.
//
// WHY this package exists: a Connection is the one place where Keyway
// records "this tenant trusts that IdP". Isolating it from storage and
// protocol code means a misconfigured tenant cannot leak trust material
// into another tenant's login path.
package connection

import "time"

// ConnectionType names the protocol a connection speaks.
//
// WHY a named type instead of a bare string: a typo like "smal" must fail
// at construction time, not silently route a login down the wrong adapter.
type ConnectionType string

const (
	// ConnectionTypeSAML routes logins through the SAML adapter.
	ConnectionTypeSAML ConnectionType = "saml"
	// ConnectionTypeOIDC routes logins through the OIDC adapter.
	ConnectionTypeOIDC ConnectionType = "oidc"
)

// ConnectionStatus tracks whether a connection is safe to use for logins.
//
// WHY a named type instead of a bare string: only "active" connections may
// start logins, so the set of legal states must be closed and grep-able.
type ConnectionStatus string

const (
	// ConnectionStatusUntested marks a newly created connection that has
	// never completed a test login and must not serve real users yet.
	ConnectionStatusUntested ConnectionStatus = "untested"
	// ConnectionStatusActive marks a tested connection approved for logins.
	ConnectionStatusActive ConnectionStatus = "active"
	// ConnectionStatusDisabled marks a connection that must refuse logins
	// until re-enabled, e.g. after a key rotation or incident.
	ConnectionStatusDisabled ConnectionStatus = "disabled"
)

// SAMLConnectionConfig holds the trust root for one SAML identity provider.
//
// WHY this struct exists: SAML trust derives entirely from the IdP's
// metadata XML. Storing the raw XML (rather than derived URLs/certs)
// preserves the signed source of truth so metadata parsing in
// internal/saml stays the single interpreter of that XML.
type SAMLConnectionConfig struct {
	// MetadataXML is the raw IdP metadata document the admin uploaded.
	MetadataXML string
}

// OIDCConnectionConfig holds the trust root for one OIDC identity provider.
//
// WHY this struct exists: OIDC trust derives from the issuer URL plus the
// client credentials registered at that issuer. Grouping them keeps the
// secret bound to the issuer and client it belongs to, instead of floating
// as loose columns that could be mismatched across connections.
type OIDCConnectionConfig struct {
	// IssuerURL is the OIDC discovery base URL, e.g. the provider's
	// https://host/tenant/v2.0 endpoint.
	IssuerURL string

	// ClientID is the relying-party identifier registered at the issuer.
	ClientID string

	// ClientSecretEncrypted is the client secret in encrypted-at-rest form.
	// Plaintext exists only in transit from the admin API to the storage
	// encryption boundary, and it is never written to logs.
	ClientSecretEncrypted string
}

// AttributeMap declares which IdP claim feeds each normalized field.
//
// WHY a struct instead of map[string]string: the application consumes
// exactly email, name, and groups, so the mapping surface must be closed
// to those three. An open map would let a typo silently drop identity
// fields instead of failing loudly at configuration time.
type AttributeMap struct {
	// EmailClaim is the IdP claim name carrying the user's email address.
	EmailClaim string

	// NameClaim is the IdP claim name carrying the user's display name.
	NameClaim string

	// GroupsClaim is the IdP claim name carrying group or role memberships.
	GroupsClaim string
}

// Connection binds one tenant to one upstream identity provider.
//
// WHY this struct exists: it is the single record the auth flow looks up to
// decide which protocol adapter handles a login. Exactly one of SAML or
// OIDC must be set, matching Type, so a connection can never ambiguously
// claim to be both protocols at once.
type Connection struct {
	// ID is the stable, unique handle used in callback paths and storage keys.
	ID string

	// TenantID is the owning tenant's ID. Every lookup filters on it so
	// one tenant's login can never resolve another tenant's IdP config.
	TenantID string

	// Type selects which adapter handles logins for this connection.
	Type ConnectionType

	// SAML holds the SAML trust material. Nil unless Type is saml.
	SAML *SAMLConnectionConfig

	// OIDC holds the OIDC trust material. Nil unless Type is oidc.
	OIDC *OIDCConnectionConfig

	// AttributeMap translates this IdP's claim names to normalized fields.
	AttributeMap AttributeMap

	// Status gates whether this connection may start or complete logins.
	Status ConnectionStatus

	// CreatedAt records when the connection was provisioned, for audit trails.
	CreatedAt time.Time
}
