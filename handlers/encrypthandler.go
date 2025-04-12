package handlers

import (
	"encrypt-decrypt-file-golang/encryption"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

func EncryptFileHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is required"})
		return
	}

	tempFilePath := "./" + file.Filename
	if err := c.SaveUploadedFile(file, tempFilePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	data, err := readFile(tempFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	encryptedText, iv, err := encryption.Encrypt(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

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

// Read file content
func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// Write string content to file
func writeFile(filename string, content string) error {
	return ioutil.WriteFile(filename, []byte(content), 0644)
}
