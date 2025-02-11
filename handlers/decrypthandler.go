package handlers

import (
	"encrypt-decrypt-file-golang/decryption"
	"encrypt-decrypt-file-golang/keymanager"
	"encrypt-decrypt-file-golang/utils"
	"fmt"
	"io"
	"net/http"
	"os"
)

func DecryptFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	key, err := keymanager.GenerateKey()
	if err != nil {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// retrieves the uploaded file named "file" from the http request from data
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading file: %v", err), http.StatusBadRequest)
		return
	}

	defer file.Close()

	// save the uploaded file temporarily on the server
	filePath := "./assets/temp_encrypted_file"
	out, err := os.Create(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving file: %v", err), http.StatusInternalServerError)
		return
	}
	defer out.Close()
	io.Copy(out, file)

	// reads the content of the temporarily saved encrypted file into memory
	encryptedFile, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading file: %v", err), http.StatusInternalServerError)
		return
	}

	// decrypts the file using the key
	decryptedFile, err := decryption.DecryptFile(encryptedFile, key)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decrypting file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(decryptedFile)
	utils.LogRequest(("File decrypted and sent successfully"))

}
