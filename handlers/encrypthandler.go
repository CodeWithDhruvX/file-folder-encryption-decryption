package handlers

import (
	"encrypt-decrypt-file-golang/encryption"
	"encrypt-decrypt-file-golang/keymanager"
	"encrypt-decrypt-file-golang/utils"
	"fmt"
	"io"
	"net/http"
	"os"
)

func EncryptFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Requerst method", http.StatusMethodNotAllowed)
		return
	}

	// step-1 Generate a new key using the keymanager package
	key, err := keymanager.GenerateKey()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating key: %v", err), http.StatusInternalServerError)
		return
	}

	// step-2 Encrypt the file using the key
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading file:%v", err), http.StatusBadRequest)
		return
	}

	defer file.Close()

	// step-4 Where the uploaded file will be temmporarily stored
	filePath := "./assets/temp_file"
	out, err := os.Create(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating file: %v", err), http.StatusInternalServerError)
		return
	}
	defer out.Close()
	io.Copy(out, file)

	// step-5 Encrypting the file
	encryptedFile, err := encryption.EncryptFile(filePath, key)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encrypting file: %v", err), http.StatusInternalServerError)
		return
	}

	// step-6 Send the encrypted file to the client
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encryptedFile)
	utils.LogRequest("File encrypted and sent successfully")
}
