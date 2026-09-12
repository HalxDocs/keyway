// Package cli implements Keyway's command surface over direct database access.
//
// WHY this package exists: operators provision tenants and connections
// without a running server, using the same storage package the server
// uses — one code path for persistence, no HTTP client to maintain. Run
// functions return printable output and errors instead of exiting, so the
// logic stays testable and cmd/keyway owns process concerns alone.
package cli

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"keyway/internal/secret"
	"keyway/internal/storage"
)

// masterKeyEnv names the environment variable carrying the hex-encoded
// 32-byte master key. Every command needing storage reads it.
const masterKeyEnv = "KEYWAY_MASTER_KEY"

// OpenStore opens the database file with the master key from the
// environment. A missing or malformed key fails here naming keygen, never
// later mid-operation.
func OpenStore(dbPath string) (*storage.SQLiteStore, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("cli: database path is required")
	}
	hexKey := os.Getenv(masterKeyEnv)
	if hexKey == "" {
		return nil, fmt.Errorf("cli: set %s (generate one with `keyway keygen`)", masterKeyEnv)
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("cli: decode %s: %w", masterKeyEnv, err)
	}
	box, err := secret.NewBox(raw)
	if err != nil {
		return nil, fmt.Errorf("cli: %w", err)
	}
	store, err := storage.NewSQLiteStore(dbPath, box)
	if err != nil {
		return nil, err
	}
	return store, nil
}

// KeyPair is one SP signing identity with its provenance attached.
type KeyPair struct {
	Key         crypto.Signer
	Certificate *x509.Certificate
	// Ephemeral reports a throwaway identity: fine for a first boot, wrong
	// for anything whose entity ID an IdP must keep trusting.
	Ephemeral bool
}

// LoadKeyPair reads an SP signing identity from PEM files, or mints an
// ephemeral RSA identity when both paths are blank. Exactly one path set is
// a loud error: half an identity can only produce confusing signatures.
func LoadKeyPair(keyPath, certPath string) (KeyPair, error) {
	if keyPath == "" && certPath == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return KeyPair{}, fmt.Errorf("cli: generate ephemeral key: %w", err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "keyway-ephemeral-sp"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return KeyPair{}, fmt.Errorf("cli: generate ephemeral key: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return KeyPair{}, fmt.Errorf("cli: generate ephemeral key: %w", err)
		}
		return KeyPair{Key: key, Certificate: cert, Ephemeral: true}, nil
	}
	if keyPath == "" || certPath == "" {
		return KeyPair{}, fmt.Errorf("cli: --sp-key and --sp-cert must be given together")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return KeyPair{}, fmt.Errorf("cli: read key file: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return KeyPair{}, fmt.Errorf("cli: read cert file: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return KeyPair{}, fmt.Errorf("cli: parse key pair: %w", err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return KeyPair{}, fmt.Errorf("cli: private key cannot sign")
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return KeyPair{}, fmt.Errorf("cli: parse certificate: %w", err)
		}
	}
	return KeyPair{Key: signer, Certificate: leaf}, nil
}
