// Package saml adapts any SAML 2.0 identity provider to Keyway's Identity.
//
// WHY this package exists: the auth flow must accept logins from SAML
// identity providers without learning SAML XML details. This is the only
// place allowed to import the SAML library; everything above it deals
// solely in connection.Connection and normalize.Identity.
package saml

import (
	"fmt"
	"net/url"

	libsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// IDPInfo is the distilled trust material Keyway needs from IdP metadata.
//
// WHY this struct exists: raw EntityDescriptor trees are verbose and easy
// to misread (multiple descriptors, bindings, key uses). Distilling once,
// at connection-setup time, means login-time code works from three
// unambiguous values instead of re-walking XML on every login.
type IDPInfo struct {
	// EntityID is the IdP's unique identifier; responses must carry it as Issuer.
	EntityID string

	// SSOURL is where Keyway sends authentication requests.
	SSOURL string

	// Binding is the SSO binding Keyway will use (redirect preferred).
	Binding string

	// Descriptor is the full parsed metadata, retained so the service
	// provider can validate response signatures against the IdP's keys.
	Descriptor *libsaml.EntityDescriptor
}

// ParseIDPMetadata parses and validates raw IdP metadata XML.
//
// WHY this function exists: metadata is the SAML trust root the way the
// issuer URL is the OIDC trust root. Garbage in here becomes forged logins
// later, so missing descriptors, missing SSO services, and missing signing
// certificates fail fast at connection setup, never at login time.
func ParseIDPMetadata(metadataXML string) (IDPInfo, error) {
	if metadataXML == "" {
		return IDPInfo{}, fmt.Errorf("saml: parse metadata: empty metadata document")
	}
	descriptor, err := samlsp.ParseMetadata([]byte(metadataXML))
	if err != nil {
		return IDPInfo{}, fmt.Errorf("saml: parse metadata: %w", err)
	}
	if len(descriptor.IDPSSODescriptors) == 0 {
		return IDPInfo{}, fmt.Errorf("saml: parse metadata: no IDPSSODescriptor in %q", descriptor.EntityID)
	}
	sso := pickSSOService(descriptor.IDPSSODescriptors[0].SingleSignOnServices)
	if sso == nil || sso.Location == "" {
		return IDPInfo{}, fmt.Errorf("saml: parse metadata: no usable SingleSignOnService in %q", descriptor.EntityID)
	}
	if _, err := url.ParseRequestURI(sso.Location); err != nil {
		return IDPInfo{}, fmt.Errorf("saml: parse metadata: invalid SSO location: %w", err)
	}
	if !hasSigningCert(&descriptor.IDPSSODescriptors[0]) {
		return IDPInfo{}, fmt.Errorf("saml: parse metadata: no signing certificate in %q", descriptor.EntityID)
	}
	return IDPInfo{
		EntityID:   descriptor.EntityID,
		SSOURL:     sso.Location,
		Binding:    sso.Binding,
		Descriptor: descriptor,
	}, nil
}

// pickSSOService prefers the redirect binding and falls back to the first
// listed service, because redirect keeps authentication requests out of
// POST bodies and matches what most IdPs advertise first anyway.
func pickSSOService(services []libsaml.Endpoint) *libsaml.Endpoint {
	if len(services) == 0 {
		return nil
	}
	for i := range services {
		if services[i].Binding == libsaml.HTTPRedirectBinding && services[i].Location != "" {
			return &services[i]
		}
	}
	return &services[0]
}

// hasSigningCert reports whether the descriptor carries a usable signing
// key. Certificates marked encryption-only do not count: without a signing
// key Keyway could not validate responses, and an unsigned-accepting setup
// must never be constructed silently.
func hasSigningCert(descriptor *libsaml.IDPSSODescriptor) bool {
	for _, key := range descriptor.KeyDescriptors {
		if key.Use == "encryption" {
			continue
		}
		for _, cert := range key.KeyInfo.X509Data.X509Certificates {
			if cert.Data != "" {
				return true
			}
		}
	}
	return false
}
