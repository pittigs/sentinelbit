package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"sentinelbit/internal/api"
	"sentinelbit/internal/config"
	"sentinelbit/internal/db"
	"sentinelbit/internal/models"
)

func setupTestDB(t *testing.T) (*sql.DB, string) {
	tempDir, err := os.MkdirTemp("", "sentinelbit_api_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	testDBPath := filepath.Join(tempDir, "test_vault.db")
	database, err := db.InitCustomDB(testDBPath)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to init test db: %v", err)
	}

	return database, tempDir
}

func TestHealthAndReadyEndpoints(t *testing.T) {
	database, tempDir := setupTestDB(t)
	defer database.Close()
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		Host: "127.0.0.1",
		Port: "8000",
	}
	api.InitAPI(cfg, database)
	router := api.SetupRouter(database, cfg)

	// 1. Health check
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/health, got %d", rr.Code)
	}

	var healthRes map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &healthRes); err != nil {
		t.Fatalf("Invalid JSON response: %v", err)
	}
	if healthRes["status"] != "healthy" || healthRes["version"] != "3.0.0" {
		t.Errorf("Unexpected health response: %v", healthRes)
	}

	// 2. Ready check
	reqReady := httptest.NewRequest(http.MethodGet, "/api/ready", nil)
	rrReady := httptest.NewRecorder()
	router.ServeHTTP(rrReady, reqReady)

	if rrReady.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /api/ready, got %d", rrReady.Code)
	}

	var readyRes map[string]string
	if err := json.Unmarshal(rrReady.Body.Bytes(), &readyRes); err != nil {
		t.Fatalf("Invalid JSON response: %v", err)
	}
	if readyRes["status"] != "ready" || readyRes["database"] != "connected" {
		t.Errorf("Unexpected ready response: %v", readyRes)
	}
}

func TestCORSPreflightAndHeaders(t *testing.T) {
	database, tempDir := setupTestDB(t)
	defer database.Close()
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{}
	api.InitAPI(cfg, database)
	router := api.SetupRouter(database, cfg)

	// Test OPTIONS preflight from Chrome Extension
	req := httptest.NewRequest(http.MethodOptions, "/api/auth/login-init", nil)
	req.Header.Set("Origin", "chrome-extension://abcdefghijklmnop")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("Expected 204 No Content for OPTIONS preflight, got %d", rr.Code)
	}

	originHeader := rr.Header().Get("Access-Control-Allow-Origin")
	if originHeader != "chrome-extension://abcdefghijklmnop" {
		t.Errorf("Expected CORS origin reflection, got %q", originHeader)
	}
}

func TestAuthAndVaultLifecycle(t *testing.T) {
	database, tempDir := setupTestDB(t)
	defer database.Close()
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		DisableRegistration: false,
	}
	api.InitAPI(cfg, database)
	router := api.SetupRouter(database, cfg)

	username := "testuser"
	authSalt := "test_auth_salt_123"
	encSalt := "test_enc_salt_456"

	// Mock 32-byte hex key for client_auth_key
	clientAuthKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Step 1: Register
	regPayload := models.RegisterRequest{
		Username: username,
		AuthSalt: authSalt,
		AuthHash: clientAuthKeyHex,
		EncSalt:  encSalt,
	}
	body, _ := json.Marshal(regPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Register failed: %d, body: %s", rr.Code, rr.Body.String())
	}

	// Step 2: Login Init
	initPayload := models.LoginInitRequest{Username: username}
	body, _ = json.Marshal(initPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login-init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Login-init failed: %d, body: %s", rr.Code, rr.Body.String())
	}

	var initRes models.LoginInitResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &initRes)
	if initRes.EncSalt != encSalt {
		t.Fatalf("Expected enc_salt %s, got %s", encSalt, initRes.EncSalt)
	}

	// Step 3: Login Verify
	verifyPayload := models.LoginVerifyRequest{
		Username:      username,
		ClientAuthKey: clientAuthKeyHex,
	}
	body, _ = json.Marshal(verifyPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login-verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Login-verify failed: %d, body: %s", rr.Code, rr.Body.String())
	}

	var verifyRes models.LoginResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &verifyRes)
	token := verifyRes.Token
	if token == "" {
		t.Fatalf("Expected non-empty session token")
	}

	// Step 4: Auth Me
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("/api/auth/me failed: %d", rr.Code)
	}

	// Step 5: Vault Create Item
	itemPayload := models.VaultItemCreate{
		Type:             "login",
		Title:            "GitHub Account",
		Folder:           "Development",
		Favorite:         true,
		EncryptedPayload: "{\"iv\":\"123456789012\",\"data\":\"abcdef\"}",
	}
	body, _ = json.Marshal(itemPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/vault/items", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Create vault item failed: %d, body: %s", rr.Code, rr.Body.String())
	}

	// Step 6: List Items
	req = httptest.NewRequest(http.MethodGet, "/api/vault/items", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("List vault items failed: %d", rr.Code)
	}

	var items []models.VaultItemResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &items)
	if len(items) != 1 || items[0].Title != "GitHub Account" {
		t.Fatalf("Expected 1 item with title 'GitHub Account', got %v", items)
	}

	// Step 7: Logout
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Logout failed: %d", rr.Code)
	}

	// Step 8: Verify token is invalidated
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized after logout, got %d", rr.Code)
	}
}
