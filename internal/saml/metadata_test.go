package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// validMetadata builds parseable IdP metadata for metadata tests.
func validMetadata(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return idpMetadataXML(testIDPEntity, testSSOURL, selfSignedCert(t, key, "meta-test-idp"))
}

func TestParseIDPMetadataValid(t *testing.T) {
	info, err := ParseIDPMetadata(validMetadata(t))
	if err != nil {
		t.Fatalf("ParseIDPMetadata: %v", err)
	}
	if info.EntityID != testIDPEntity {
		t.Errorf("EntityID = %q, want %q", info.EntityID, testIDPEntity)
	}
	if info.SSOURL != testSSOURL {
		t.Errorf("SSOURL = %q, want %q", info.SSOURL, testSSOURL)
	}
	if info.Descriptor == nil {
		t.Errorf("Descriptor is nil, want parsed metadata")
	}
}

func TestParseIDPMetadataRejects(t *testing.T) {
	noCert := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + testIDPEntity + `">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + testSSOURL + `"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`

	noSSO := strings.Replace(validMetadata(t),
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="`+testSSOURL+`"/>`,
		``, 1)

	spOnly := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.test/">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`</SPSSODescriptor></EntityDescriptor>`

	cases := map[string]string{
		"empty document":   "",
		"not XML":          "this is not xml",
		"SP-only metadata": spOnly,
		"no SSO service":   noSSO,
		"no certificate":   noCert,
	}
	for name, xml := range cases {
		if _, err := ParseIDPMetadata(xml); err == nil {
			t.Errorf("%s: expected rejection, got nil error", name)
		}
	}
}
