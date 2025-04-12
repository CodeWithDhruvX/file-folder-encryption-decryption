package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

var key = []byte("thisis32bitlongpassphraseimusing")[:32]

func Decrypt(encodedData, encodedIV string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return "", fmt.Errorf("invalid encrypted data")
	}

	iv, err := base64.StdEncoding.DecodeString(encodedIV)
	if err != nil || len(iv) != aes.BlockSize {
		return "", fmt.Errorf("invalid IV size")
	}

	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	cfb.XORKeyStream(plaintext, data)

	return string(plaintext), nil
}
