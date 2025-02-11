package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
)

func EncryptFile(filePath string, key []byte) ([]byte, error) {

	// read the plaintext from the file
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// step-1 Create a new AES cipher block using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher block: %v", err)
	}

	// step-2 Create a slice of bytes to store the ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// step-3 generate a rabndom IV (Intialization Vector)
	iv := ciphertext[:aes.BlockSize]
	if _, err = rand.Read(iv); err != nil {
		return nil, fmt.Errorf("could not generate random iv: %v", err)
	}

	//step-4  Intitalize the AES CFB mode with the block and IV
	stream := cipher.NewCFBEncrypter(block, iv)

	//step-5 Encrypt the plaintext and store the ciphertext in the slice
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// return the decrypted plain text
	return ciphertext, nil

}
