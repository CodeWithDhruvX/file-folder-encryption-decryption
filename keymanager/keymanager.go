package keymanager

import (
	"crypto/rand"
	"fmt"
)

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256 requires 32 bytes key
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %v", err)
	}
	return key, nil
}
