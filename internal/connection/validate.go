package connection

import "fmt"

// Validate checks a Connection before it is stored.
//
// WHY a domain-level method instead of per-entry-point checks: both the
// admin API and the CLI create connections, and the adapters already reject
// bad configs again at login time. Validating here fails a misconfigured
// connection once, loudly, at creation — before it ever reaches storage —
// instead of once per entry point or, worse, at a user's login attempt. In
// particular the email mapping is required up front: an empty EmailClaim
// would otherwise store successfully and only fail closed later inside
// VerifyToken or FinishLogin.
func (c Connection) Validate() error {
	if c.ID == "" || c.TenantID == "" {
		return fmt.Errorf("connection: validate: ID and tenant ID are required")
	}
	switch c.Type {
	case ConnectionTypeSAML:
		if c.SAML == nil || c.SAML.MetadataXML == "" {
			return fmt.Errorf("connection: validate: SAML connections require IdP metadata")
		}
		if c.OIDC != nil {
			return fmt.Errorf("connection: validate: SAML connections must not carry OIDC config")
		}
	case ConnectionTypeOIDC:
		if c.OIDC == nil || c.OIDC.IssuerURL == "" || c.OIDC.ClientID == "" {
			return fmt.Errorf("connection: validate: OIDC connections require issuer URL and client ID")
		}
		if c.SAML != nil {
			return fmt.Errorf("connection: validate: OIDC connections must not carry SAML config")
		}
	default:
		return fmt.Errorf("connection: validate: unknown type %q", c.Type)
	}
	if c.AttributeMap.EmailClaim == "" {
		return fmt.Errorf("connection: validate: email claim mapping is required")
	}
	return nil
}
