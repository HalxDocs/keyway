// Package saml — SP metadata rendering.
//
// WHY this file exists: Keyway must publish its own SAML descriptor so an
// IdP can import the ACS URL and signing certificate. This is the only
// place that turns a ServiceProvider into XML bytes; callers above receive
// opaque bytes to keep crewjam/saml types confined.
package saml

import (
	"encoding/xml"
	"fmt"
)

// Metadata returns the SP EntityDescriptor as indented XML.
//
// WHY a method on Adapter instead of exposing the provider: the handler
// above normalize must never import the SAML library. Opaque bytes keep
// the protocol library confined while still letting flow produce the exact
// document the running instance advertises — entity ID, ACS URL, and
// certificate derived from the live SPConfig.
func (a *Adapter) Metadata() ([]byte, error) {
	buf, err := xml.MarshalIndent(a.provider.Metadata(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return append([]byte(xml.Header), buf...), nil
}
