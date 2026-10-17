package bitwarden_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelbit/internal/api"
	"sentinelbit/internal/bitwarden"
	"sentinelbit/internal/config"
	"sentinelbit/internal/db"
)

func setupTestDB(t *testing.T) (*sql.DB, string) {
	tempDir, err := os.MkdirTemp("", "sentinelbit_bw_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	testDBPath := filepath.Join(tempDir, "test_bw_vault.db")
	database, err := db.InitCustomDB(testDBPath)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to init test db: %v", err)
	}

	return database, tempDir
}

func TestBitwardenFullFlow(t *testing.T) {
	database, tempDir := setupTestDB(t)
	defer database.Close()
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Host: "127.0.0.1",
		Port: "8000",
	}
	api.InitAPI(cfg, database)
	router := api.SetupRouter(database, cfg)

	// 1. Config Check
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/config, got %d", rr.Code)
	}
	var configRes bitwarden.ConfigResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &configRes); err != nil || configRes.Object != "config" {
		t.Fatalf("Failed to parse config response: %v", err)
	}

	// 2. Prelogin Check
	preloginPayload := bitwarden.PreloginRequest{Email: "alice@example.com"}
	pBody, _ := json.Marshal(preloginPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/accounts/prelogin", bytes.NewReader(pBody))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/accounts/prelogin, got %d", rr.Code)
	}
	var preloginRes bitwarden.PreloginResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &preloginRes)
	if preloginRes.KdfIterations != 600000 {
		t.Errorf("Expected 600000 iterations, got %d", preloginRes.KdfIterations)
	}

	// 3. Register Account
	regPayload := bitwarden.RegisterRequest{
		Email:              "alice@example.com",
		Name:               "Alice",
		MasterPasswordHash: "mockMasterPasswordHashBase64",
		Key:                "2.0123456789abcdef|symmetricKeyCiphertext|mac123",
		Keys: &bitwarden.RegisterKeys{
			PublicKey:           "mockRsaPublicKeyPem",
			EncryptedPrivateKey: "2.0123456789abcdef|rsaPrivateCiphertext|mac456",
		},
		Kdf:           0,
		KdfIterations: 600000,
	}
	rBody, _ := json.Marshal(regPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/accounts/register", bytes.NewReader(rBody))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/accounts/register, got %d: %s", rr.Code, rr.Body.String())
	}

	// 4. Token Login (Invalid Password)
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "alice@example.com")
	form.Set("password", "WRONG_PASSWORD_HASH")
	req = httptest.NewRequest(http.MethodPost, "/identity/connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for wrong password, got %d", rr.Code)
	}

	// 5. Token Login (Valid Password)
	form.Set("password", "mockMasterPasswordHashBase64")
	form.Set("deviceType", "14")
	form.Set("deviceIdentifier", "uuid-extension-device-123")
	form.Set("deviceName", "Chrome on Linux")
	req = httptest.NewRequest(http.MethodPost, "/identity/connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /identity/connect/token, got %d: %s", rr.Code, rr.Body.String())
	}
	var tokenRes bitwarden.TokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tokenRes); err != nil || tokenRes.AccessToken == "" {
		t.Fatalf("Failed to parse token response: %v", err)
	}
	if tokenRes.Key != regPayload.Key {
		t.Errorf("Expected Key %q, got %q", regPayload.Key, tokenRes.Key)
	}
	token := tokenRes.AccessToken

	// 6. Profile
	req = httptest.NewRequest(http.MethodGet, "/api/accounts/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/accounts/profile, got %d", rr.Code)
	}
	var profRes bitwarden.ProfileResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &profRes)
	if profRes.Email != "alice@example.com" {
		t.Errorf("Expected email alice@example.com, got %s", profRes.Email)
	}

	// 7. Create Folder
	folderPayload := bitwarden.FolderRequest{Name: "2.iv|WorkFolderEncrypted|mac"}
	fBody, _ := json.Marshal(folderPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/folders", bytes.NewReader(fBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/folders, got %d", rr.Code)
	}
	var folderRes bitwarden.FolderModel
	_ = json.Unmarshal(rr.Body.Bytes(), &folderRes)
	folderID := folderRes.ID
	if folderID == "" {
		t.Fatalf("Folder ID was empty")
	}

	// 8. Create Cipher (Login Item)
	usernameEnc := "2.iv|alice_login|mac"
	passwordEnc := "2.iv|super_secret_pw|mac"
	cipherPayload := bitwarden.CipherModel{
		Type:     1, // Login
		FolderID: &folderID,
		Name:     "2.iv|GitHub|mac",
		Favorite: true,
		Login: &bitwarden.CipherLogin{
			URIs: []bitwarden.CipherURI{
				{URI: "https://github.com", Match: nil},
			},
			Username: &usernameEnc,
			Password: &passwordEnc,
		},
	}
	cBody, _ := json.Marshal(cipherPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/ciphers", bytes.NewReader(cBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/ciphers, got %d: %s", rr.Code, rr.Body.String())
	}
	var cipherRes bitwarden.CipherModel
	_ = json.Unmarshal(rr.Body.Bytes(), &cipherRes)
	cipherID := cipherRes.ID
	if cipherID == "" {
		t.Fatalf("Cipher ID was empty")
	}

	// 9. Sync Endpoint
	req = httptest.NewRequest(http.MethodGet, "/api/sync", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/sync, got %d", rr.Code)
	}
	var syncRes bitwarden.SyncResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &syncRes)
	if len(syncRes.Folders) != 1 || syncRes.Folders[0].ID != folderID {
		t.Errorf("Expected 1 folder in sync, got %d", len(syncRes.Folders))
	}
	if len(syncRes.Ciphers) != 1 || syncRes.Ciphers[0].ID != cipherID {
		t.Errorf("Expected 1 cipher in sync, got %d", len(syncRes.Ciphers))
	}
	if syncRes.Ciphers[0].Login == nil || *syncRes.Ciphers[0].Login.Username != usernameEnc {
		t.Errorf("Expected login username %s, got %+v", usernameEnc, syncRes.Ciphers[0].Login)
	}

	// 10. Update Cipher
	notesEnc := "2.iv|Recovery codes here|mac"
	cipherRes.Notes = &notesEnc
	uBody, _ := json.Marshal(cipherRes)
	req = httptest.NewRequest(http.MethodPut, "/api/ciphers/"+cipherID, bytes.NewReader(uBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for updating cipher, got %d", rr.Code)
	}

	// 11. Delete Cipher (Soft delete / trash)
	req = httptest.NewRequest(http.MethodDelete, "/api/ciphers/"+cipherID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for deleting cipher, got %d", rr.Code)
	}

	// Verify excluded from active ciphers list
	req = httptest.NewRequest(http.MethodGet, "/api/ciphers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	var listRes struct {
		Data []bitwarden.CipherModel `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &listRes)
	if len(listRes.Data) != 0 {
		t.Errorf("Expected 0 active ciphers after soft-delete, got %d", len(listRes.Data))
	}

	// 12. Restore Cipher
	req = httptest.NewRequest(http.MethodPut, "/api/ciphers/"+cipherID+"/restore", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for restoring cipher, got %d", rr.Code)
	}

	// 13. Hard Delete Cipher
	req = httptest.NewRequest(http.MethodDelete, "/api/ciphers/"+cipherID+"/delete", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for hard deleting cipher, got %d", rr.Code)
	}

	// 14. Notifications Hub fallback
	req = httptest.NewRequest(http.MethodGet, "/notifications/hub", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for /notifications/hub fallback, got %d", rr.Code)
	}
}
