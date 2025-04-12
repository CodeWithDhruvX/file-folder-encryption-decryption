package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encrypt-decrypt-file-golang/keymanager"
)

// Encrypt data using AES CFB
// Encrypt data using AES CFB

var key = []byte("thisis32bitlongpassphraseimusing")[:32]

func Encrypt(data []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	iv, err := keymanager.GenerateIV()
	if err != nil {
		return "", "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	cfb.XORKeyStream(ciphertext, data)

	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(iv), nil
}
