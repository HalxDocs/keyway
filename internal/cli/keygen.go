package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Keygen prints one fresh hex-encoded 32-byte master key for
// KEYWAY_MASTER_KEY. Keys come from the OS random source, never from
// anything memorable or derivable.
func Keygen() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cli: keygen: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
