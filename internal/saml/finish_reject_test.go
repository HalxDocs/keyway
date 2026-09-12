package saml

import (
	"context"
	"encoding/base64"
	"testing"
	"time"
)

func TestFinishLoginRejects(t *testing.T) {
	adapter, idpKey, idpCert := testAdapter(t, testMapping)
	ctx := context.Background()
	now := time.Now()

	challenge, err := adapter.StartLogin("relay-1")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	mint := func() (string, string) {
		return mintResponse(t, idpKey, idpCert, MintParams{
			RequestID:  challenge.RequestID,
			RelayState: "relay-1",
			Attributes: map[string][]string{
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"ada@example.com"},
			},
			NotBefore: now.Add(-5 * time.Minute),
			NotAfter:  now.Add(5 * time.Minute),
		})
	}
	expected := ExpectedResponse{RequestIDs: []string{challenge.RequestID}, RelayState: "relay-1"}

	t.Run("relay mismatch", func(t *testing.T) {
		responseB64, _ := mint()
		received := ReceivedResponse{SAMLResponseB64: responseB64, RelayState: "relay-evil"}
		if _, err := adapter.FinishLogin(ctx, received, expected); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})

	t.Run("empty expected relay", func(t *testing.T) {
		responseB64, relayState := mint()
		received := ReceivedResponse{SAMLResponseB64: responseB64, RelayState: relayState}
		if _, err := adapter.FinishLogin(ctx, received, ExpectedResponse{RequestIDs: []string{challenge.RequestID}}); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})

	t.Run("empty response", func(t *testing.T) {
		if _, err := adapter.FinishLogin(ctx, ReceivedResponse{}, expected); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})

	t.Run("malformed base64", func(t *testing.T) {
		received := ReceivedResponse{SAMLResponseB64: "!!!not-base64!!!", RelayState: "relay-1"}
		if _, err := adapter.FinishLogin(ctx, received, expected); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})

	t.Run("wrong request ID", func(t *testing.T) {
		responseB64, relayState := mint()
		received := ReceivedResponse{SAMLResponseB64: responseB64, RelayState: relayState}
		wrong := ExpectedResponse{RequestIDs: []string{"id-no-such-request"}, RelayState: "relay-1"}
		if _, err := adapter.FinishLogin(ctx, received, wrong); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		responseB64, relayState := mint()
		decoded, err := base64.StdEncoding.DecodeString(responseB64)
		if err != nil {
			t.Fatalf("decode minted response: %v", err)
		}
		decoded[len(decoded)-20] ^= 0xff
		tampered := base64.StdEncoding.EncodeToString(decoded)
		received := ReceivedResponse{SAMLResponseB64: tampered, RelayState: relayState}
		if _, err := adapter.FinishLogin(ctx, received, expected); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})

	t.Run("expired assertion", func(t *testing.T) {
		responseB64, relayState := mintResponse(t, idpKey, idpCert, MintParams{
			RequestID:  challenge.RequestID,
			RelayState: "relay-1",
			Attributes: map[string][]string{
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"ada@example.com"},
			},
			NotBefore: now.Add(-2 * time.Hour),
			NotAfter:  now.Add(-time.Hour),
		})
		received := ReceivedResponse{SAMLResponseB64: responseB64, RelayState: relayState}
		if _, err := adapter.FinishLogin(ctx, received, expected); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})

	t.Run("missing email claim", func(t *testing.T) {
		responseB64, relayState := mintResponse(t, idpKey, idpCert, MintParams{
			RequestID:  challenge.RequestID,
			RelayState: "relay-1",
			Attributes: map[string][]string{
				"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": {"Ada"},
			},
			NotBefore: now.Add(-5 * time.Minute),
			NotAfter:  now.Add(5 * time.Minute),
		})
		received := ReceivedResponse{SAMLResponseB64: responseB64, RelayState: relayState}
		if _, err := adapter.FinishLogin(ctx, received, expected); err == nil {
			t.Errorf("expected rejection, got nil error")
		}
	})
}
