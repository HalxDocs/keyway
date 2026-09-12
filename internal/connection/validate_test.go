package connection

import "testing"

func TestValidate(t *testing.T) {
	validSAML := Connection{ID: "c1", TenantID: "acme", Type: ConnectionTypeSAML,
		SAML:         &SAMLConnectionConfig{MetadataXML: "<EntityDescriptor/>"},
		AttributeMap: AttributeMap{EmailClaim: "email"}, Status: ConnectionStatusUntested}
	if err := validSAML.Validate(); err != nil {
		t.Errorf("valid SAML: %v", err)
	}
	validOIDC := Connection{ID: "c2", TenantID: "acme", Type: ConnectionTypeOIDC,
		OIDC:         &OIDCConnectionConfig{IssuerURL: "https://issuer.test", ClientID: "client-1"},
		AttributeMap: AttributeMap{EmailClaim: "email"}, Status: ConnectionStatusUntested}
	if err := validOIDC.Validate(); err != nil {
		t.Errorf("valid OIDC: %v", err)
	}

	noEmail := validSAML
	noEmail.AttributeMap.EmailClaim = ""
	noMetadata := validSAML
	noMetadata.SAML = nil
	noIssuer := validOIDC
	noIssuer.OIDC = &OIDCConnectionConfig{ClientID: "client-1"}
	mixed := validSAML
	mixed.OIDC = &OIDCConnectionConfig{IssuerURL: "https://issuer.test", ClientID: "client-1"}
	unknown := validSAML
	unknown.Type = "kerberos"
	emptyIDs := validSAML
	emptyIDs.ID = ""

	cases := map[string]Connection{
		"empty email claim":      noEmail,
		"SAML without metadata":  noMetadata,
		"OIDC without issuer":    noIssuer,
		"mixed protocol configs": mixed,
		"unknown type":           unknown,
		"empty IDs":              emptyIDs,
	}
	for name, conn := range cases {
		if err := conn.Validate(); err == nil {
			t.Errorf("%s: expected rejection, got nil error", name)
		}
	}
}
