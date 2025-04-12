package main

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"encrypt-decrypt-file-golang/handlers"
)

// Start the Gin server
func main() {
	r := gin.Default()

	r.POST("/encrypt-file", handlers.EncryptFileHandler)
	r.POST("/encrypt-files", handlers.EncryptMultipleFilesHandler)
	r.POST("/decrypt-file", handlers.DecryptFileHandler)
	r.POST("/decrypt-files", handlers.DecryptMultipleFilesHandler)

	fmt.Println("Server running on http://localhost:8080")
	r.Run(":8080")
}
