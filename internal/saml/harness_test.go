package saml

// This file holds the shared SAML test harness: throwaway keys and certs,
// IdP metadata rendering, and an in-process test IdP that mints real signed
// responses through the library's own IdentityProvider.
//
// WHY a separate harness file: every SAML test needs the same fixtures, and
// duplicating key generation across test files would hide drift between
// them. One harness means all tests validate against identical trust roots.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"keyway/internal/connection"
)

// MintParams describes one test-IdP response to mint.

const (
	testSPEntity  = "https://keyway.test/sp"
	testIDPEntity = "https://idp.test/metadata"
	testACSURL    = "https://keyway.test/callback/saml/conn-1"
	testSSOURL    = "https://idp.test/sso"
)

// selfSignedCert mints a throwaway CA-style cert for test signing.
func selfSignedCert(t *testing.T, key *rsa.PrivateKey, name string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test certificate: %v", err)
	}
	return cert
}

// idpMetadataXML renders IdP metadata embedding the given signing cert.
func idpMetadataXML(entityID, ssoURL string, cert *x509.Certificate) string {
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">` +
		`<X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(cert.Raw) + `</X509Certificate></X509Data>` +
		`</KeyInfo></KeyDescriptor>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + ssoURL + `"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`
}

// testAdapter builds an Adapter wired to a test IdP. It returns the adapter
// plus the IdP signing material needed to mint responses for it.
func testAdapter(t *testing.T, mapping connection.AttributeMap) (*Adapter, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	spKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate SP key: %v", err)
	}
	spCert := selfSignedCert(t, spKey, "keyway-test-sp")
	idpKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	idpCert := selfSignedCert(t, idpKey, "keyway-test-idp")
	conn := connection.Connection{
		ID:           "conn-1",
		TenantID:     "acme",
		Type:         connection.ConnectionTypeSAML,
		SAML:         &connection.SAMLConnectionConfig{MetadataXML: idpMetadataXML(testIDPEntity, testSSOURL, idpCert)},
		AttributeMap: mapping,
		Status:       connection.ConnectionStatusActive,
	}
	sp := SPConfig{
		EntityID:    testSPEntity,
		MetadataURL: testSPEntity + "/metadata",
		ACSURL:      testACSURL,
		Key:         spKey,
		Certificate: spCert,
	}
	adapter, err := NewAdapter(conn, sp)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	return adapter, idpKey, idpCert
}

var testMapping = connection.AttributeMap{
	EmailClaim:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	NameClaim:   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
	GroupsClaim: "http://schemas.xmlsoap.org/claims/Group",
}
