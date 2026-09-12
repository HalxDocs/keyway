package secret

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testBox(t *testing.T) *Box {
	t.Helper()
	key := make([]byte, KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	box, err := NewBox(key)
	if err != nil {
		t.Fatalf("NewBox: %v", err)
	}
	return box
}

func TestNewBoxRejectsShortKey(t *testing.T) {
	if _, err := NewBox([]byte("too short")); err == nil {
		t.Errorf("expected rejection of short master key, got nil error")
	}
	if _, err := NewBox(nil); err == nil {
		t.Errorf("expected rejection of nil master key, got nil error")
	}
}

func TestSealRoundTrip(t *testing.T) {
	box := testBox(t)
	sealed, err := box.Seal([]byte("client-secret-123"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, []byte("client-secret-123")) {
		t.Errorf("sealed output contains plaintext")
	}
	plain, err := box.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(plain, []byte("client-secret-123")) {
		t.Errorf("round trip = %q, want client-secret-123", plain)
	}
}

func TestUnsealRejects(t *testing.T) {
	box := testBox(t)
	sealed, err := box.Seal([]byte("data"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	sealed[len(sealed)-1] ^= 0xff
	if _, err := box.Unseal(sealed); err == nil {
		t.Errorf("tampered ciphertext: expected rejection, got nil error")
	}

	if _, err := box.Unseal([]byte("short")); err == nil {
		t.Errorf("truncated value: expected rejection, got nil error")
	}

	other := testBox(t)
	fresh, err := box.Seal([]byte("data"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := other.Unseal(fresh); err == nil {
		t.Errorf("wrong key: expected rejection, got nil error")
	}
}
