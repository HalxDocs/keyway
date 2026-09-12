package saml

// This file mints signed test-IdP responses through the library's own
// IdentityProvider, so tests validate against real signatures instead of
// hand-written XML.
//
// WHY a separate file: response minting is the test-side IdP implementation.
// Isolating it from trust-root fixtures (harness_test.go) keeps each file's
// reason to change distinct: keys and metadata evolve separately from the
// assertion shapes under test.

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/url"
	"testing"
	"time"

	libsaml "github.com/crewjam/saml"
)

// MintParams describes one test-IdP response to mint.
type MintParams struct {
	RequestID  string
	RelayState string
	Attributes map[string][]string
	NotBefore  time.Time
	NotAfter   time.Time
}

// mintResponse runs the test IdP: it builds an assertion from params, signs
// response and assertion with the IdP key, and returns the POST form values.
func mintResponse(t *testing.T, idpKey *rsa.PrivateKey, idpCert *x509.Certificate, params MintParams) (string, string) {
	t.Helper()
	now := time.Now()
	var attrs []libsaml.Attribute
	for name, members := range params.Attributes {
		var vals []libsaml.AttributeValue
		for _, member := range members {
			vals = append(vals, libsaml.AttributeValue{Value: member})
		}
		attrs = append(attrs, libsaml.Attribute{Name: name, Values: vals})
	}
	idp := &libsaml.IdentityProvider{
		Key:         idpKey,
		Certificate: idpCert,
		MetadataURL: mustParseTestURL(t, testIDPEntity),
	}
	idpReq := &libsaml.IdpAuthnRequest{
		IDP:        idp,
		Request:    libsaml.AuthnRequest{ID: params.RequestID},
		RelayState: params.RelayState,
		Now:        now,
		ACSEndpoint: &libsaml.IndexedEndpoint{
			Binding:  libsaml.HTTPPostBinding,
			Location: testACSURL,
		},
		SPSSODescriptor: &libsaml.SPSSODescriptor{},
		Assertion: &libsaml.Assertion{
			ID:           fmt.Sprintf("assert-%d", now.UnixNano()),
			IssueInstant: now,
			Version:      "2.0",
			Issuer:       libsaml.Issuer{Value: testIDPEntity},
			Subject: &libsaml.Subject{
				NameID: &libsaml.NameID{Value: "ada@example.com"},
				SubjectConfirmations: []libsaml.SubjectConfirmation{
					{
						Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
						SubjectConfirmationData: &libsaml.SubjectConfirmationData{
							NotOnOrAfter: params.NotAfter,
							Recipient:    testACSURL,
							InResponseTo: params.RequestID,
						},
					},
				},
			},
			Conditions: &libsaml.Conditions{
				NotBefore:    params.NotBefore,
				NotOnOrAfter: params.NotAfter,
				AudienceRestrictions: []libsaml.AudienceRestriction{
					{Audience: libsaml.Audience{Value: testSPEntity}},
				},
			},
			AttributeStatements: []libsaml.AttributeStatement{{Attributes: attrs}},
		},
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		t.Fatalf("mint test response: %v", err)
	}
	return form.SAMLResponse, form.RelayState
}

func mustParseTestURL(t *testing.T, raw string) url.URL {
	t.Helper()
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		t.Fatalf("parse test URL: %v", err)
	}
	return *parsed
}
