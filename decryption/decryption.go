package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func DecryptFile(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher block: %v", err)
	}

	// Ensure IV size is correct
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size")
	}

	// Initialize AES CFB decrypter
	stream := cipher.NewCFBDecrypter(block, iv)

	// Create buffer for plaintext
	plaintext := make([]byte, len(ciphertext))

	// Decrypt data
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
