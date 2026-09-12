package api

// The miniature test IdP lives here: it mints real signed SAML responses
// through the library's own IdentityProvider, so callback tests validate
// against genuine signatures instead of hand-written XML.
//
// WHY a separate file: response minting is the test-side IdP. Isolating it
// from the stack fixtures keeps each file's reason to change distinct.

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/url"
	"testing"
	"time"

	libsaml "github.com/crewjam/saml"
)

// apiMint posts a signed response for a fabricated pending login.
func apiMint(t *testing.T, idpKey *rsa.PrivateKey, idpCert *x509.Certificate, requestID, relay string) (string, string) {
	t.Helper()
	now := time.Now()
	idp := &libsaml.IdentityProvider{Key: idpKey, Certificate: idpCert,
		MetadataURL: mustAPIURL(t, apiIDP)}
	idpReq := &libsaml.IdpAuthnRequest{
		IDP: idp, Request: libsaml.AuthnRequest{ID: requestID}, RelayState: relay, Now: now,
		ACSEndpoint:     &libsaml.IndexedEndpoint{Binding: libsaml.HTTPPostBinding, Location: apiACS},
		SPSSODescriptor: &libsaml.SPSSODescriptor{},
		Assertion: &libsaml.Assertion{
			ID: fmt.Sprintf("assert-%d", now.UnixNano()), IssueInstant: now, Version: "2.0",
			Issuer: libsaml.Issuer{Value: apiIDP},
			Subject: &libsaml.Subject{
				NameID: &libsaml.NameID{Value: "ada@example.com"},
				SubjectConfirmations: []libsaml.SubjectConfirmation{{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &libsaml.SubjectConfirmationData{
						NotOnOrAfter: now.Add(5 * time.Minute), Recipient: apiACS, InResponseTo: requestID,
					},
				}},
			},
			Conditions: &libsaml.Conditions{
				NotBefore: now.Add(-5 * time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
				AudienceRestrictions: []libsaml.AudienceRestriction{
					{Audience: libsaml.Audience{Value: apiEntity}},
				},
			},
			AttributeStatements: []libsaml.AttributeStatement{{
				Attributes: []libsaml.Attribute{
					{Name: "email", Values: []libsaml.AttributeValue{{Value: "ada@example.com"}}},
				},
			}},
		},
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		t.Fatalf("mint response: %v", err)
	}
	return form.SAMLResponse, form.RelayState
}

func mustAPIURL(t *testing.T, raw string) url.URL {
	t.Helper()
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return *parsed
}
