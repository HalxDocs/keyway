package saml

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	libsaml "github.com/crewjam/saml"

	"keyway/internal/connection"
)

// SPConfig carries Keyway's own service-provider identity for one deployment.
//
// WHY this struct exists: SAML is mutual trust — the IdP must recognize
// Keyway as well as Keyway recognizing the IdP. One deployment-wide SP
// identity (entity ID, endpoints, signing key) is the Phase 1 call because
// real multi-tenant connectors share one SP across customer IdPs; per
// connection keys wait for Phase 4. It lives here temporarily until the
// config package exists.
type SPConfig struct {
	// EntityID identifies Keyway to identity providers, usually a URL.
	EntityID string

	// MetadataURL serves Keyway's SP metadata document.
	MetadataURL string

	// ACSURL receives IdP responses; FinishLogin validates Destination against it.
	ACSURL string

	// Key signs authentication requests; Certificate advertises the public half.
	Key         crypto.Signer
	Certificate *x509.Certificate

	// MaxSkew bounds accepted clock drift on assertion time windows.
	// Zero selects the library default without mutating its globals.
	MaxSkew time.Duration
}

// Adapter speaks SAML for one connection: it builds login challenges and
// validates responses into normalized identities.
//
// WHY this struct exists: it binds the IdP trust material, the SP identity,
// and the attribute map from one connection.Connection, so a response from
// tenant A's IdP can never validate or map through tenant B's config.
type Adapter struct {
	provider   *libsaml.ServiceProvider
	acsURL     url.URL
	ssoURL     string
	attributes connection.AttributeMap
	maxSkew    time.Duration
	now        func() time.Time
}

// NewAdapter builds an Adapter for one SAML connection.
//
// WHY a constructor instead of a bare struct literal: a connection without
// IdP metadata, or a deployment without SP identity, must fail here before
// serving logins rather than producing unsigned or misrouted requests.
func NewAdapter(conn connection.Connection, sp SPConfig) (*Adapter, error) {
	if conn.Type != connection.ConnectionTypeSAML {
		return nil, fmt.Errorf("saml: new adapter: connection %q is type %q, not saml", conn.ID, conn.Type)
	}
	if conn.SAML == nil || conn.SAML.MetadataXML == "" {
		return nil, fmt.Errorf("saml: new adapter: connection %q has no SAML metadata", conn.ID)
	}
	if conn.AttributeMap.EmailClaim == "" {
		return nil, fmt.Errorf("saml: new adapter: connection %q needs an email claim mapping", conn.ID)
	}
	if sp.EntityID == "" || sp.ACSURL == "" || sp.MetadataURL == "" {
		return nil, fmt.Errorf("saml: new adapter: service provider identity is incomplete")
	}
	if sp.Key == nil || sp.Certificate == nil {
		return nil, fmt.Errorf("saml: new adapter: service provider signing key is required")
	}
	idp, err := ParseIDPMetadata(conn.SAML.MetadataXML)
	if err != nil {
		return nil, err
	}
	acsURL, err := url.ParseRequestURI(sp.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: new adapter: invalid ACS URL: %w", err)
	}
	metadataURL, err := url.ParseRequestURI(sp.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("saml: new adapter: invalid metadata URL: %w", err)
	}
	maxSkew := sp.MaxSkew
	if maxSkew <= 0 {
		maxSkew = libsaml.MaxClockSkew
	}
	provider := &libsaml.ServiceProvider{
		EntityID:    sp.EntityID,
		Key:         sp.Key,
		Certificate: sp.Certificate,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		IDPMetadata: idp.Descriptor,
	}
	return &Adapter{provider: provider, acsURL: *acsURL, ssoURL: idp.SSOURL, attributes: conn.AttributeMap, maxSkew: maxSkew, now: time.Now}, nil
}
