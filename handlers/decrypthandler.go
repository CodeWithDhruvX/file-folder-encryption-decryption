package handlers

import (
	"encoding/base64"
	"encoding/json"
	"encrypt-decrypt-file-golang/decryption"
	"fmt"
	"net/http"
)

type DecryptRequest struct {
	EncryptedText string `json:"encrypted_text"`
	IV            string `json:"iv"`
}

func DecryptFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON request
	var req DecryptRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error parsing JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Decode base64 IV and encrypted text
	encryptedData, err := base64.StdEncoding.DecodeString(req.EncryptedText)
	if err != nil {
		http.Error(w, "Invalid encrypted text", http.StatusBadRequest)
		return
	}

	iv, err := base64.StdEncoding.DecodeString(req.IV)
	if err != nil {
		http.Error(w, "Invalid IV", http.StatusBadRequest)
		return
	}

	// Define your decryption key (must be the same used during encryption)
	key := []byte("your-32-byte-secret-key!") // Ensure it's a valid 32-byte AES key

	// Decrypt the file
	decryptedData, err := decryption.DecryptFile(encryptedData, key, iv)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decrypting file: %v", err), http.StatusInternalServerError)
		return
	}

	// Return decrypted data
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(decryptedData)
}
