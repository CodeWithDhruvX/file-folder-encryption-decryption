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

// Key for AES encryption (32 bytes)
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

// Encrypt multiple files
func encryptFilesHandler(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No files uploaded"})
		return
	}

	var encryptedFiles []map[string]string

	for _, file := range files {
		// Save uploaded file temporarily
		tempFilePath := "./" + file.Filename
		if err := c.SaveUploadedFile(file, tempFilePath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
			return
		}

		// Read file content
		data, err := readFile(tempFilePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
			return
		}

		// Encrypt file content
		encryptedText, iv, err := encrypt(data)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}

		// Save encrypted data
		encFileName := "encrypted_" + file.Filename + ".txt"
		err = writeFile(encFileName, encryptedText)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save encrypted file"})
			return
		}

		encryptedFiles = append(encryptedFiles, map[string]string{
			"original_file":  file.Filename,
			"encrypted_file": encFileName,
			"encrypted_text": encryptedText, // अब एन्क्रिप्टेड टेक्स्ट भी response में आएगा
			"iv":             iv,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "Files encrypted successfully",
		"encrypted_files": encryptedFiles,
	})
}

// Decrypt multiple files
func decryptFilesHandler(c *gin.Context) {
	var req struct {
		Files []struct {
			EncryptedText string `json:"encrypted_text"`
			IV            string `json:"iv"`
			FileName      string `json:"file_name"`
		} `json:"files"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var decryptedFiles []map[string]string

	for _, file := range req.Files {
		// Decrypt file content
		decryptedText, err := decrypt(file.EncryptedText, file.IV)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption failed"})
			return
		}

		// Save decrypted data
		decFileName := "decrypted_" + file.FileName
		err = writeFile(decFileName, decryptedText)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save decrypted file"})
			return
		}

		decryptedFiles = append(decryptedFiles, map[string]string{
			"decrypted_file": decFileName,
			"original_name":  file.FileName,
			"decrypted_text": decryptedText, // ✅ Decrypted text added in response
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "Files decrypted successfully",
		"decrypted_files": decryptedFiles,
	})
}

func main() {
	r := gin.Default()

	r.POST("/encrypt-files", encryptFilesHandler) // Encrypt multiple files
	r.POST("/decrypt-files", decryptFilesHandler) // Decrypt multiple files

	fmt.Println("Server running on http://localhost:8080")
	r.Run(":8080")
}
