package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// SPKeygenParams carries the output paths for one stable SP signing
// identity. Refusing to overwrite existing files is deliberate: silently
// replacing a live key would invalidate the IdP's trust without warning.
type SPKeygenParams struct {
	KeyPath  string
	CertPath string
	CN       string
}

// SPKeygen mints one self-signed RSA identity for --sp-key/--sp-cert. The
// Common Name defaults to keyway-sp; validity is 825 days. The key file is
// created 0600 and neither path may already exist.
func SPKeygen(p SPKeygenParams) (string, error) {
	if p.KeyPath == "" || p.CertPath == "" {
		return "", fmt.Errorf("cli: sp-keygen: key and cert paths are required")
	}
	cn := p.CN
	if cn == "" {
		cn = "keyway-sp"
	}
	for _, path := range []string{p.KeyPath, p.CertPath} {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("cli: sp-keygen: refusing to overwrite %q", path)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("cli: sp-keygen: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("cli: sp-keygen: serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("cli: sp-keygen: create certificate: %w", err)
	}
	keyOut, err := os.OpenFile(p.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("cli: sp-keygen: open key file: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return "", fmt.Errorf("cli: sp-keygen: write key: %w", err)
	}
	certOut, err := os.OpenFile(p.CertPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", fmt.Errorf("cli: sp-keygen: open cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", fmt.Errorf("cli: sp-keygen: write cert: %w", err)
	}
	return fmt.Sprintf("wrote %s %s", p.KeyPath, p.CertPath), nil
}
