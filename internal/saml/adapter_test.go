package saml

import (
	"context"
	"testing"
	"time"
)

// TestFinishLoginRoundTrip is the SAML twin of the OIDC custom-claims test:
// ADFS-style URI claim names must populate Identity through AttributeMap.
func TestFinishLoginRoundTrip(t *testing.T) {
	adapter, idpKey, idpCert := testAdapter(t, testMapping)
	ctx := context.Background()

	challenge, err := adapter.StartLogin("relay-1")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if challenge.RequestID == "" || challenge.URL == "" {
		t.Fatalf("StartLogin returned empty challenge: %+v", challenge)
	}

	now := time.Now()
	responseB64, relayState := mintResponse(t, idpKey, idpCert, MintParams{
		RequestID:  challenge.RequestID,
		RelayState: "relay-1",
		Attributes: map[string][]string{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"ada@example.com"},
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         {"Ada"},
			"http://schemas.xmlsoap.org/claims/Group":                            {"eng", "sso"},
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(5 * time.Minute),
	})
	identity, err := adapter.FinishLogin(ctx,
		ReceivedResponse{SAMLResponseB64: responseB64, RelayState: relayState},
		ExpectedResponse{RequestIDs: []string{challenge.RequestID}, RelayState: "relay-1"})
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if identity.Email != "ada@example.com" {
		t.Errorf("Email = %q, want ada@example.com", identity.Email)
	}
	if identity.Name != "Ada" {
		t.Errorf("Name = %q, want Ada", identity.Name)
	}
	if len(identity.Groups) != 2 || identity.Groups[0] != "eng" {
		t.Errorf("Groups = %v, want [eng sso]", identity.Groups)
	}
}
