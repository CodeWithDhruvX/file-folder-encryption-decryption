package main

import (
	"encrypt-decrypt-file-golang/handlers"
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/encrypt", handlers.EncryptFileHandler)
	http.HandleFunc("/decrypt", handlers.DecryptFileHandler)

	fmt.Println("Server starting on 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
