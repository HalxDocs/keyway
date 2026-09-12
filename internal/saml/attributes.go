package saml

import (
	"fmt"

	libsaml "github.com/crewjam/saml"

	"keyway/internal/connection"
	"keyway/internal/normalize"
)

// assertionAttributes flattens a validated assertion's attribute
// statements into name-to-values form.
//
// WHY this function exists: SAML attributes are multi-valued XML elements
// addressed by Name or FriendlyName, and IdPs never agree on either. One
// flattening site, keyed by both names, means the AttributeMap lookup below
// works for ADFS-style URIs and short names alike without XML handling
// leaking into the adapter.
func assertionAttributes(assertion *libsaml.Assertion) map[string][]string {
	values := make(map[string][]string)
	if assertion == nil {
		return values
	}
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			var members []string
			for _, value := range attr.Values {
				if value.Value != "" {
					members = append(members, value.Value)
				} else if value.NameID != nil && value.NameID.Value != "" {
					members = append(members, value.NameID.Value)
				}
			}
			if attr.Name != "" {
				values[attr.Name] = append(values[attr.Name], members...)
			}
			if attr.FriendlyName != "" && attr.FriendlyName != attr.Name {
				values[attr.FriendlyName] = append(values[attr.FriendlyName], members...)
			}
		}
	}
	return values
}

// identityFromAttributes maps flattened attributes to a normalized Identity
// using the connection's configured claim names.
//
// WHY this function exists: it is the SAML twin of the OIDC dynamic-key
// lookup. Email is required and fails closed with the offending claim name,
// so a misconfigured AttributeMap surfaces as an explicit error instead of
// the silent empty-Email bug that fixed claim structs would produce.
func identityFromAttributes(values map[string][]string, mapping connection.AttributeMap) (normalize.Identity, error) {
	if mapping.EmailClaim == "" {
		return normalize.Identity{}, fmt.Errorf("saml: map attributes: no email claim configured")
	}
	members, ok := values[mapping.EmailClaim]
	if !ok || len(members) == 0 || members[0] == "" {
		return normalize.Identity{}, fmt.Errorf("saml: map attributes: email claim %q missing or empty", mapping.EmailClaim)
	}
	identity := normalize.Identity{
		Email:     members[0],
		RawClaims: normalize.RawClaims{},
	}
	if mapping.NameClaim != "" {
		if names, ok := values[mapping.NameClaim]; ok && len(names) > 0 {
			identity.Name = names[0]
		}
	}
	if mapping.GroupsClaim != "" {
		identity.Groups = append([]string(nil), values[mapping.GroupsClaim]...)
	}
	for name, vals := range values {
		copied := append([]string(nil), vals...)
		identity.RawClaims[name] = copied
	}
	return identity, nil
}
