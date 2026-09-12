// Package secret encrypts sensitive connection material at rest.
//
// WHY this package exists: OIDC client secrets must never sit in plaintext
// in SQLite. One small AES-GCM box, keyed by a master key the operator
// supplies, keeps that promise in a single auditable place instead of
// scattered ad-hoc crypto. Key rotation is out of scope for v1: ciphertext
// carries no version prefix, so rotating the master key requires
// re-entering secrets. That gap is documented here, not silent.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// KeyLength is the required master-key size in bytes (AES-256).
const KeyLength = 32

// Box seals and unseals secrets with one master key.
//
// WHY a struct holding a cipher instead of free functions taking the key:
// constructing once validates the key length up front, so a short key fails
// at startup rather than mid-login when the first secret is stored.
type Box struct {
	aead cipher.AEAD
}

// NewBox builds a Box from a 32-byte master key, typically read from the
// KEYWAY_MASTER_KEY environment variable by the caller.
func NewBox(masterKey []byte) (*Box, error) {
	if len(masterKey) != KeyLength {
		return nil, fmt.Errorf("secret: new box: master key must be %d bytes, got %d", KeyLength, len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("secret: new box: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: new box: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal encrypts plaintext with a fresh random nonce, returning
// nonce|ciphertext. A fresh nonce per call means identical secrets seal to
// different bytes, so the database leaks nothing by comparison.
func (b *Box) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secret: seal: %w", err)
	}
	return b.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Unseal decrypts output previously produced by Seal. Any tampering or a
// wrong master key fails authentication and returns an error, never data.
func (b *Box) Unseal(sealed []byte) ([]byte, error) {
	if len(sealed) < b.aead.NonceSize() {
		return nil, fmt.Errorf("secret: unseal: sealed value too short")
	}
	nonce, ciphertext := sealed[:b.aead.NonceSize()], sealed[b.aead.NonceSize():]
	plaintext, err := b.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("secret: unseal: %w", err)
	}
	return plaintext, nil
}
