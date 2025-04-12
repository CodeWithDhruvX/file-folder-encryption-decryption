package keymanager

import (
	"crypto/aes"
	"crypto/rand"
	"io"
)

// AES key (16, 24, or 32 bytes)
// var key = []byte("thisis32bitlongpassphraseimusing")[:32]

// Generate a random IV (16 bytes)
func GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
