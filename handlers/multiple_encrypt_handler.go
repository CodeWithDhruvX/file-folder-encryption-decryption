package handlers

import (
	"encrypt-decrypt-file-golang/encryption"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Encrypt multiple files (POST with form-data)
func EncryptMultipleFilesHandler(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid multipart form"})
		return
	}

	files := form.File["files"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one file is required"})
		return
	}

	results := []gin.H{}

	for _, file := range files {
		tempFilePath := "./" + file.Filename
		if err := c.SaveUploadedFile(file, tempFilePath); err != nil {
			results = append(results, gin.H{
				"filename": file.Filename,
				"error":    "Failed to save file",
			})
			continue
		}

		data, err := readFile(tempFilePath)
		if err != nil {
			results = append(results, gin.H{
				"filename": file.Filename,
				"error":    "Failed to read file",
			})
			continue
		}

		encryptedText, iv, err := encryption.Encrypt(data)
		if err != nil {
			results = append(results, gin.H{
				"filename": file.Filename,
				"error":    "Encryption failed",
			})
			continue
		}

		encFileName := "encrypted_" + file.Filename + ".txt"
		if err := writeFile(encFileName, encryptedText); err != nil {
			results = append(results, gin.H{
				"filename": file.Filename,
				"error":    "Failed to save encrypted file",
			})
			continue
		}

		results = append(results, gin.H{
			"filename":       file.Filename,
			"encrypted_file": encFileName,
			"encrypted_text": encryptedText,
			"iv":             iv,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Files encrypted",
		"results": results,
	})
}
