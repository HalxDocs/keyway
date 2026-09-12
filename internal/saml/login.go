package saml

import (
	"context"
	"encoding/base64"
	"fmt"

	libsaml "github.com/crewjam/saml"

	"keyway/internal/normalize"
)

// LoginChallenge starts one SP-initiated login.
//
// WHY this struct exists: the caller must persist the RequestID alongside
// its RelayState before redirecting the user, so the callback can prove the
// returning response answers this exact request. Returning both together
// makes dropping either one a visible omission.
type LoginChallenge struct {
	// URL is the IdP redirect target carrying the authentication request.
	URL string

	// RequestID is the outgoing request ID the response must answer.
	RequestID string
}

// ReceivedResponse is what the IdP posted back to the callback endpoint.
//
// WHY this struct exists: naming the wire values (base64 response plus the
// accompanying RelayState) keeps them distinct from the expected values
// below, so a reviewer can see at a glance which side of each comparison
// came from the network and which came from Keyway's own records.
type ReceivedResponse struct {
	// SAMLResponseB64 is the base64-encoded response exactly as posted.
	SAMLResponseB64 string

	// RelayState is the state value returned alongside the response.
	RelayState string
}

// ExpectedResponse is what Keyway's pending login demands back.
//
// WHY this struct exists: it is the SAML twin of OIDC's expectedNonce.
// Both halves must match for the login to proceed, and the adapter — not
// the caller — enforces that, so neither protocol's replay protection can
// be forgotten one layer up.
type ExpectedResponse struct {
	// RequestIDs holds the acceptable InResponseTo values, normally the one
	// stored RequestID from LoginChallenge.
	RequestIDs []string

	// RelayState is the state Keyway generated and stored when starting.
	RelayState string
}

// StartLogin builds the IdP redirect URL for one login and reports the
// request ID the response must answer.
//
// WHY this method exists: the request ID is the InResponseTo anchor for
// replay protection. Building the request in two steps (request object,
// then redirect URL) instead of the one-call helper is deliberate: only the
// two-step form exposes the request ID for Keyway to store.
func (a *Adapter) StartLogin(relayState string) (LoginChallenge, error) {
	if relayState == "" {
		return LoginChallenge{}, fmt.Errorf("saml: start login: empty relay state")
	}
	authReq, err := a.provider.MakeAuthenticationRequest(a.ssoURL, libsaml.HTTPRedirectBinding, libsaml.HTTPPostBinding)
	if err != nil {
		return LoginChallenge{}, fmt.Errorf("saml: start login: %w", err)
	}
	redirectURL, err := authReq.Redirect(relayState, a.provider)
	if err != nil {
		return LoginChallenge{}, fmt.Errorf("saml: start login: %w", err)
	}
	return LoginChallenge{URL: redirectURL.String(), RequestID: authReq.ID}, nil
}

// FinishLogin validates a posted response and maps it to an Identity.
//
// WHY this method exists: it is the single seam where untrusted IdP output
// becomes trusted application input. RelayState is compared first so a
// response carried on the wrong login flow rejects before any XML is
// trusted; signatures, issuer, audience, times, and request ID are then
// enforced by response validation; attributes map by configured names last.
func (a *Adapter) FinishLogin(_ context.Context, received ReceivedResponse, expected ExpectedResponse) (identity normalize.Identity, err error) {
	// The SAML library dereferences Conditions and Subject without nil
	// checks, so a structurally odd (but signed) response would panic the
	// whole process instead of rejecting the login. This boundary converts
	// any such panic into an ordinary rejection.
	defer func() {
		if recovered := recover(); recovered != nil {
			identity = normalize.Identity{}
			err = fmt.Errorf("saml: finish login: invalid assertion structure")
		}
	}()
	if received.SAMLResponseB64 == "" {
		return normalize.Identity{}, fmt.Errorf("saml: finish login: empty response")
	}
	if expected.RelayState == "" {
		return normalize.Identity{}, fmt.Errorf("saml: finish login: empty expected relay state")
	}
	if received.RelayState != expected.RelayState {
		return normalize.Identity{}, fmt.Errorf("saml: finish login: relay state mismatch")
	}
	decoded, err := base64.StdEncoding.DecodeString(received.SAMLResponseB64)
	if err != nil {
		return normalize.Identity{}, fmt.Errorf("saml: finish login: decode response: %w", err)
	}
	assertion, err := a.provider.ParseXMLResponse(decoded, expected.RequestIDs, a.acsURL)
	if err != nil {
		return normalize.Identity{}, fmt.Errorf("saml: finish login: %w", err)
	}
	if err := a.checkTimeWindow(assertion); err != nil {
		return normalize.Identity{}, err
	}
	identity, err = identityFromAttributes(assertionAttributes(assertion), a.attributes)
	if err != nil {
		return normalize.Identity{}, err
	}
	return identity, nil
}

// checkTimeWindow enforces the adapter's configured clock-skew tolerance on
// assertion conditions, per-connection and without touching the library's
// package-level skew variables.
func (a *Adapter) checkTimeWindow(assertion *libsaml.Assertion) error {
	if assertion == nil || assertion.Conditions == nil {
		return nil
	}
	now := a.now()
	conditions := assertion.Conditions
	if !conditions.NotBefore.IsZero() && now.Before(conditions.NotBefore.Add(-a.maxSkew)) {
		return fmt.Errorf("saml: finish login: assertion not yet valid")
	}
	if !conditions.NotOnOrAfter.IsZero() && !now.Before(conditions.NotOnOrAfter.Add(a.maxSkew)) {
		return fmt.Errorf("saml: finish login: assertion expired")
	}
	return nil
}
