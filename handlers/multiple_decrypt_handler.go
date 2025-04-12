package handlers

import (
	"encrypt-decrypt-file-golang/decryption"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Decrypt multiple files (POST JSON array)
func DecryptMultipleFilesHandler(c *gin.Context) {
	var req []struct {
		Filename      string `json:"filename"`
		EncryptedText string `json:"encrypted_text"`
		IV            string `json:"iv"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	results := []gin.H{}

	for _, item := range req {
		decryptedText, err := decryption.Decrypt(item.EncryptedText, item.IV)
		if err != nil {
			results = append(results, gin.H{
				"filename": item.Filename,
				"error":    "Decryption failed",
			})
			continue
		}

		decryptedFilename := "decrypted_" + item.Filename
		err = writeFile(decryptedFilename, decryptedText)
		if err != nil {
			results = append(results, gin.H{
				"filename": item.Filename,
				"error":    "Failed to save decrypted file",
			})
			continue
		}

		results = append(results, gin.H{
			"filename":       item.Filename,
			"decrypted_file": decryptedFilename,
			"decrypted_text": decryptedText,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Files decrypted",
		"results": results,
	})
}
