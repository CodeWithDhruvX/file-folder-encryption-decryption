package handlers

import (
	"encrypt-decrypt-file-golang/decryption"
	"net/http"

	"github.com/gin-gonic/gin"
)

func DecryptFileHandler(c *gin.Context) {
	var req struct {
		EncryptedText string `json:"encrypted_text"`
		IV            string `json:"iv"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	decryptedText, err := decryption.Decrypt(req.EncryptedText, req.IV)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption failed"})
		return
	}

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
