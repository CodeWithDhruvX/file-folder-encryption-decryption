package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func DecryptFile(ciphertext []byte, key []byte) ([]byte, error) {

	// step-1 Create a new AES cipher block using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create cipher block: %v", err)
	}

	// ensure the ciphertext length is at least AES block size
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf(("ciphertext is too short"))
	}

	// step-2 extract the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]

	// step-3 extract the actual encrypted data (exclusing the IV)
	ciphertext = ciphertext[aes.BlockSize:]

	// step-4 Intitalize the AES CFB decrypter with the block and IV
	stream := cipher.NewCFBDecrypter(block, iv)

	//  STEP-5 cerate a buffer to hold the decrypted palintext
	plaintext := make([]byte, len(ciphertext))

	// Step-6 decrtypt the ciphertext and store the plaintext in the buffer
	stream.XORKeyStream(plaintext, ciphertext)

	//  return the decrtpted plaintext
	return plaintext, nil
}
