package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Key for AES encryption (16, 24, or 32 bytes)
var key = []byte("thisis32bitlongpassphraseimusing")[:32]

// Generate a random IV (16 bytes)
func generateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

// Encrypts data using AES CFB mode
func encrypt(data []byte) (string, string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	iv, err := generateIV()
	if err != nil {
		return "", "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	cfb.XORKeyStream(ciphertext, data)

	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(iv), nil
}

// Decrypts AES CFB encrypted data
func decrypt(encodedData, encodedIV string) (string, error) {
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

// Reads file content
func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// Writes content to a file
func writeFile(filename string, content string) error {
	return ioutil.WriteFile(filename, []byte(content), 0644)
}

// Encrypt text from a file
// Encrypt text from a file (POST request)
// Encrypt text from an uploaded file (POST request with form-data)
func encryptFileHandler(c *gin.Context) {
	// Get the uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is required"})
		return
	}

	// Save the uploaded file temporarily
	tempFilePath := "./" + file.Filename
	if err := c.SaveUploadedFile(file, tempFilePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Read the file content
	data, err := readFile(tempFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	// Encrypt the file content
	encryptedText, iv, err := encrypt(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

	// Save encrypted data to a file
	err = writeFile("encrypted.txt", encryptedText)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save encrypted file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "File encrypted successfully",
		"encrypted_text": encryptedText,
		"iv":             iv,
	})
}

// Decrypt text and save to a new file
func decryptFileHandler(c *gin.Context) {
	var req struct {
		EncryptedText string `json:"encrypted_text"`
		IV            string `json:"iv"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	decryptedText, err := decrypt(req.EncryptedText, req.IV)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption failed"})
		return
	}

	// Save decrypted data to a new file
	err = writeFile("decrypted.txt", decryptedText)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save decrypted file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "File decrypted successfully",
		"decrypted_text": decryptedText,
	})
}

func main() {
	r := gin.Default()

	r.POST("/encrypt-file", encryptFileHandler) // Encrypt file via POST request
	r.POST("/decrypt-file", decryptFileHandler) // Decrypt file

	fmt.Println("Server running on http://localhost:8080")
	r.Run(":8080")
}
