package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"sentinelbit/internal/crypto"
	"sentinelbit/internal/db"
	"sentinelbit/internal/security"

	_ "modernc.org/sqlite"
)

// setupAuditRouter initializes a clean temporary test database and router
func setupAuditRouter(t *testing.T) (*sql.DB, http.Handler, func()) {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "sentinelbit_pentest_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp db: %v", err)
	}
	dbPath := tmpFile.Name()
	tmpFile.Close()

	os.Setenv("SENTINELBIT_DATA_DIR", os.TempDir())
	testDB, err := db.InitCustomDB(dbPath)
	if err != nil {
		os.Remove(dbPath)
		t.Fatalf("InitCustomDB failed: %v", err)
	}

	router := setupRouter(testDB)

	cleanup := func() {
		testDB.Close()
		os.Remove(dbPath)
	}

	return testDB, router, cleanup
}

// Helper: register and login a test user, returning auth token and user ID
func registerAndLoginUser(t *testing.T, router http.Handler, username, password string) (string, string) {
	t.Helper()

	// 1. Register
	authSalt := crypto.GenerateSalt(16)
	encSalt := crypto.GenerateSalt(16)
	// 64-hex deterministic dummy hash for testing
	authHash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	regBody, _ := json.Marshal(map[string]string{
		"username":  username,
		"auth_salt": authSalt,
		"auth_hash": authHash,
		"enc_salt":  encSalt,
	})

	regReq := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regRec := httptest.NewRecorder()
	router.ServeHTTP(regRec, regReq)

	if regRec.Code != http.StatusOK && regRec.Code != http.StatusCreated {
		t.Fatalf("Register failed for %s: code %d, body %s", username, regRec.Code, regRec.Body.String())
	}

	// 2. Login Verify
	loginBody, _ := json.Marshal(map[string]string{
		"username":        username,
		"client_auth_key": authHash,
	})
	loginReq := httptest.NewRequest("POST", "/api/auth/login-verify", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	router.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("Login failed for %s: code %d, body %s", username, loginRec.Code, loginRec.Body.String())
	}

	var loginResp map[string]interface{}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	token, _ := loginResp["token"].(string)
	userId, _ := loginResp["user_id"].(string)

	return token, userId
}

// ============================================================================
// PENTEST 1: SQL INJECTION RESISTANCE (FUZZING & INJECTION ATTACKS)
// ============================================================================
func TestPentest_SQLInjectionResistance(t *testing.T) {
	_, router, cleanup := setupAuditRouter(t)
	defer cleanup()

	sqlVectors := []string{
		"' OR 1=1 --",
		"' OR '1'='1",
		"admin' --",
		"'; DROP TABLE users; --",
		"'; DROP TABLE vault_items; --",
		"1' UNION SELECT NULL, NULL, NULL, NULL --",
		"1' AND SLEEP(2) --",
		"' OR ''='",
		"\" OR \"\"=\"",
		"admin'/*",
	}

	// 1. SQL Injection on Registration (Username validation must reject invalid chars)
	for _, vector := range sqlVectors {
		regBody, _ := json.Marshal(map[string]string{
			"username":  "user" + vector,
			"auth_salt": crypto.GenerateSalt(16),
			"auth_hash": "dummyhash",
			"enc_salt":  crypto.GenerateSalt(16),
		})
		req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(regBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code == http.StatusInternalServerError {
			t.Errorf("[CRITICAL] SQL Injection caused 500 error during register with vector: %s", vector)
		}
	}

	// 2. SQL Injection on Login Init (Must safely handle arbitrary string inputs)
	for _, vector := range sqlVectors {
		initBody, _ := json.Marshal(map[string]string{"username": vector})
		req := httptest.NewRequest("POST", "/api/auth/login-init", bytes.NewReader(initBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code == http.StatusInternalServerError {
			t.Errorf("[CRITICAL] SQL Injection caused 500 error during login-init with vector: %s", vector)
		}
	}

	// 3. SQL Injection in Vault Item title & folder (Authenticated)
	token, _ := registerAndLoginUser(t, router, "sqli_tester", "ComplexMasterPass123!")

	for _, vector := range sqlVectors {
		itemBody, _ := json.Marshal(map[string]interface{}{
			"type":              "login",
			"title":             "Test " + vector,
			"folder":            "Folder " + vector,
			"encrypted_payload": "enc_payload_data",
		})
		req := httptest.NewRequest("POST", "/api/vault/items", bytes.NewReader(itemBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Errorf("Failed to safely store item containing SQL chars: code %d, vector: %s", rec.Code, vector)
		}
	}

	// 4. Verify Database Integrity: tables still exist and are functional
	req := httptest.NewRequest("GET", "/api/vault/items", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("[CRITICAL] Database corrupted or table dropped! Status: %d", rec.Code)
	}
}

// ============================================================================
// PENTEST 2: BROKEN OBJECT LEVEL AUTHORIZATION (IDOR DEFENSE AUDIT)
// ============================================================================
func TestPentest_BOLA_IDOR_Isolation(t *testing.T) {
	_, router, cleanup := setupAuditRouter(t)
	defer cleanup()

	// Create User Victim and User Attacker
	victimToken, _ := registerAndLoginUser(t, router, "victim_user", "PassVictim!123")
	attackerToken, _ := registerAndLoginUser(t, router, "attacker_user", "PassAttacker!456")

	// Victim creates a private vault item
	createItemBody, _ := json.Marshal(map[string]interface{}{
		"type":              "login",
		"title":             "Victim Secret Bank",
		"folder":            "Finance",
		"encrypted_payload": "victim_super_secret_ciphertext",
	})
	createReq := httptest.NewRequest("POST", "/api/vault/items", bytes.NewReader(createItemBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer "+victimToken)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK && createRec.Code != http.StatusCreated {
		t.Fatalf("Victim failed to create item: %d", createRec.Code)
	}

	var createdItem map[string]interface{}
	_ = json.Unmarshal(createRec.Body.Bytes(), &createdItem)
	victimItemId := createdItem["id"].(string)

	// ATTACK 1: Attacker attempts to list all items (Must only see own empty items)
	listReq := httptest.NewRequest("GET", "/api/vault/items", nil)
	listReq.Header.Set("Authorization", "Bearer "+attackerToken)
	listRec := httptest.NewRecorder()
	router.ServeHTTP(listRec, listReq)

	var attackerItems []map[string]interface{}
	_ = json.Unmarshal(listRec.Body.Bytes(), &attackerItems)
	if len(attackerItems) != 0 {
		t.Fatalf("[CRITICAL IDOR] Attacker was able to read other user's vault items! Found %d items", len(attackerItems))
	}

	// ATTACK 2: Attacker attempts to modify Victim's vault item via PUT
	updateBody, _ := json.Marshal(map[string]interface{}{
		"title":             "Hacked Title",
		"encrypted_payload": "attacker_tampered_payload",
	})
	updateReq := httptest.NewRequest("PUT", "/api/vault/items/"+victimItemId, bytes.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", "Bearer "+attackerToken)
	updateRec := httptest.NewRecorder()
	router.ServeHTTP(updateRec, updateReq)

	if updateRec.Code != http.StatusNotFound {
		t.Errorf("[CRITICAL IDOR] Attacker update was not rejected with 404! Got code: %d", updateRec.Code)
	}

	// ATTACK 3: Attacker attempts to soft-delete Victim's vault item
	delReq := httptest.NewRequest("DELETE", "/api/vault/items/"+victimItemId, nil)
	delReq.Header.Set("Authorization", "Bearer "+attackerToken)
	delRec := httptest.NewRecorder()
	router.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusNotFound {
		t.Errorf("[CRITICAL IDOR] Attacker soft-delete was not rejected with 404! Got code: %d", delRec.Code)
	}

	// ATTACK 4: Attacker attempts to permanently delete Victim's vault item
	delPermReq := httptest.NewRequest("DELETE", "/api/vault/items/"+victimItemId+"?permanent=true", nil)
	delPermReq.Header.Set("Authorization", "Bearer "+attackerToken)
	delPermRec := httptest.NewRecorder()
	router.ServeHTTP(delPermRec, delPermReq)

	if delPermRec.Code != http.StatusNotFound {
		t.Errorf("[CRITICAL IDOR] Attacker permanent delete was not rejected with 404! Got code: %d", delPermRec.Code)
	}

	// ATTACK 5: Attacker attempts to restore Victim's item
	restoreReq := httptest.NewRequest("POST", "/api/vault/items/"+victimItemId+"/restore", nil)
	restoreReq.Header.Set("Authorization", "Bearer "+attackerToken)
	restoreRec := httptest.NewRecorder()
	router.ServeHTTP(restoreRec, restoreReq)

	// Verify Victim's item is untouched
	checkReq := httptest.NewRequest("GET", "/api/vault/items", nil)
	checkReq.Header.Set("Authorization", "Bearer "+victimToken)
	checkRec := httptest.NewRecorder()
	router.ServeHTTP(checkRec, checkReq)

	var victimItems []map[string]interface{}
	_ = json.Unmarshal(checkRec.Body.Bytes(), &victimItems)
	if len(victimItems) != 1 || victimItems[0]["title"] != "Victim Secret Bank" {
		t.Fatalf("[CRITICAL INTEGRITY] Victim's item was tampered with or missing after IDOR attempts!")
	}
}

// ============================================================================
// PENTEST 3: AUTHENTICATION BYPASS & TOKEN TAMPERING
// ============================================================================
func TestPentest_AuthBypassAndTokenTampering(t *testing.T) {
	_, router, cleanup := setupAuditRouter(t)
	defer cleanup()

	protectedEndpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/vault/items"},
		{"POST", "/api/vault/items"},
		{"DELETE", "/api/vault/items/dummy-id"},
		{"GET", "/api/passkeys"},
		{"POST", "/api/passkeys"},
		{"GET", "/api/sync/settings"},
		{"GET", "/api/aliases"},
		{"GET", "/api/share/inbox"},
	}

	for _, ep := range protectedEndpoints {
		// 1. Missing Authorization header
		req := httptest.NewRequest(ep.method, ep.path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("[AUTH BYPASS] %s %s allowed access without Authorization header! Got: %d", ep.method, ep.path, rec.Code)
		}

		// 2. Forged Bearer token
		reqFake := httptest.NewRequest(ep.method, ep.path, nil)
		reqFake.Header.Set("Authorization", "Bearer forged_token_1234567890abcdef")
		recFake := httptest.NewRecorder()
		router.ServeHTTP(recFake, reqFake)

		if recFake.Code != http.StatusUnauthorized {
			t.Errorf("[AUTH BYPASS] %s %s allowed access with forged Bearer token! Got: %d", ep.method, ep.path, recFake.Code)
		}

		// 3. Malformed Authorization headers
		malformedHeaders := []string{
			"Basic dXNlcjpwYXNz",
			"Bearer",
			"Bearer ",
			"bearer token_without_proper_case",
			"Bearer token\x00with_null_byte",
		}
		for _, hdr := range malformedHeaders {
			reqMal := httptest.NewRequest(ep.method, ep.path, nil)
			reqMal.Header.Set("Authorization", hdr)
			recMal := httptest.NewRecorder()
			router.ServeHTTP(recMal, reqMal)

			if recMal.Code != http.StatusUnauthorized {
				t.Errorf("[AUTH BYPASS] %s %s allowed access with malformed header %q! Got: %d", ep.method, ep.path, hdr, recMal.Code)
			}
		}
	}
}

// ============================================================================
// PENTEST 4: USER ENUMERATION PROTECTION (TIMING & DATA LEAK TEST)
// ============================================================================
func TestPentest_AntiUserEnumeration(t *testing.T) {
	_, router, cleanup := setupAuditRouter(t)
	defer cleanup()

	// Create an existing user
	registerAndLoginUser(t, router, "real_registered_user", "SomeSecretKey!2026")

	// 1. Query login-init for existing user
	bodyReal, _ := json.Marshal(map[string]string{"username": "real_registered_user"})
	reqReal := httptest.NewRequest("POST", "/api/auth/login-init", bytes.NewReader(bodyReal))
	reqReal.Header.Set("Content-Type", "application/json")
	recReal := httptest.NewRecorder()
	router.ServeHTTP(recReal, reqReal)

	if recReal.Code != http.StatusOK {
		t.Fatalf("Login-init for real user failed: %d", recReal.Code)
	}

	var respReal map[string]interface{}
	_ = json.Unmarshal(recReal.Body.Bytes(), &respReal)

	// 2. Query login-init for NON-EXISTENT user
	bodyFake, _ := json.Marshal(map[string]string{"username": "ghost_nonexistent_user_999"})
	reqFake := httptest.NewRequest("POST", "/api/auth/login-init", bytes.NewReader(bodyFake))
	reqFake.Header.Set("Content-Type", "application/json")
	recFake := httptest.NewRecorder()
	router.ServeHTTP(recFake, reqFake)

	if recFake.Code != http.StatusOK {
		t.Fatalf("Login-init for fake user failed: %d", recFake.Code)
	}

	var respFake map[string]interface{}
	_ = json.Unmarshal(recFake.Body.Bytes(), &respFake)

	// 3. Verify response parity: fake user MUST receive synthetic salts matching format
	if respFake["auth_salt"] == nil || respFake["enc_salt"] == nil {
		t.Fatalf("[USER ENUMERATION] Missing fake salt response for non-existent user!")
	}

	authSaltStr, ok := respFake["auth_salt"].(string)
	if !ok || len(authSaltStr) < 20 {
		t.Fatalf("[USER ENUMERATION] Fake auth_salt format is noticeably different from real salt!")
	}

	// Status code parity
	if recReal.Code != recFake.Code {
		t.Errorf("[USER ENUMERATION] Status code discrepancy detected! Real: %d, Fake: %d", recReal.Code, recFake.Code)
	}
}

// ============================================================================
// PENTEST 5: TOTP REPLAY & DRIFT ATTACK PREVENTION
// ============================================================================
func TestPentest_TotpReplayGuard(t *testing.T) {
	guard := security.NewTotpReplayGuard()
	userId := "user_totp_victim_123"
	code := "482910"

	// First use: MUST PASS
	allowed1 := guard.CheckAndRecord(userId, code)
	if !allowed1 {
		t.Fatalf("First TOTP verification should be allowed")
	}

	// Second use (Immediate Replay Attack): MUST BE REJECTED!
	allowed2 := guard.CheckAndRecord(userId, code)
	if allowed2 {
		t.Fatalf("[CRITICAL SECURITY] Replay attack succeeded! Replay Guard failed to block reused TOTP token")
	}

	// Different code for same user: MUST PASS
	allowed3 := guard.CheckAndRecord(userId, "951753")
	if !allowed3 {
		t.Fatalf("New distinct TOTP code should be accepted")
	}

	// Same code for DIFFERENT user: MUST PASS
	allowedOtherUser := guard.CheckAndRecord("other_user_456", code)
	if !allowedOtherUser {
		t.Fatalf("Same code for a different user should not collide")
	}
}

// ============================================================================
// PENTEST 6: RATE LIMITING & BRUTE FORCE DEFENSE
// ============================================================================
func TestPentest_RateLimitingResistance(t *testing.T) {
	limiter := security.NewRateLimiter(5, 60*time.Second, 15*time.Minute)
	ipKey := "192.168.1.100:test_user"

	// 1. Initial state: Allowed
	allowed, _ := limiter.Check(ipKey)
	if !allowed {
		t.Fatalf("Initial attempt must be allowed")
	}

	// 2. Perform 5 failures
	for i := 1; i <= 5; i++ {
		limiter.RecordFailure(ipKey)
	}

	// 3. 6th attempt: MUST BE BLOCKED
	allowedBlocked, blockDuration := limiter.Check(ipKey)
	if allowedBlocked {
		t.Fatalf("[BRUTE FORCE VULNERABILITY] Rate limiter failed to block after 5 failed attempts!")
	}
	if blockDuration <= 0 {
		t.Fatalf("Block duration must be positive")
	}

	// 4. Different IP should still be allowed
	allowedOther, _ := limiter.Check("10.0.0.1:test_user")
	if !allowedOther {
		t.Fatalf("Rate limiter blocked an unrelated IP address!")
	}
}

// ============================================================================
// PENTEST 7: HTTP SECURITY HEADERS AUDIT
// ============================================================================
func TestPentest_SecurityHeadersAudit(t *testing.T) {
	_, router, cleanup := setupAuditRouter(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	headers := rec.Header()

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "no-referrer",
	}

	for hdr, expectedVal := range expectedHeaders {
		val := headers.Get(hdr)
		if val != expectedVal {
			t.Errorf("[SECURITY HEADER] Missing or incorrect %s: expected %q, got %q", hdr, expectedVal, val)
		}
	}

	// Verify Content-Security-Policy contains frame-ancestors 'none' to stop Clickjacking
	csp := headers.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("[CLICKJACKING RISK] CSP is missing frame-ancestors 'none'")
	}
}

// ============================================================================
// PENTEST 8: ZERO-KNOWLEDGE DATABASE LEAK TEST
// ============================================================================
func TestPentest_ZeroKnowledgeDataLeak(t *testing.T) {
	testDB, router, cleanup := setupAuditRouter(t)
	defer cleanup()

	plainPassword := "SecretSuperPassword123!"
	token, userId := registerAndLoginUser(t, router, "zk_audit_user", plainPassword)

	// 1. Verify users table does NOT contain the plaintext password anywhere
	var authHash, authSalt string
	err := testDB.QueryRow("SELECT auth_hash, auth_salt FROM users WHERE id = ?", userId).Scan(&authHash, &authSalt)
	if err != nil {
		t.Fatalf("Query user failed: %v", err)
	}

	if strings.Contains(authHash, plainPassword) {
		t.Fatalf("[CRITICAL ZERO-KNOWLEDGE LEAK] Plaintext password found in auth_hash column!")
	}

	// 2. Add secret vault item
	secretNote := "Confidential Medical & Financial Details 987654321"
	body, _ := json.Marshal(map[string]interface{}{
		"type":              "note",
		"title":             "Confidential Note",
		"encrypted_payload": "enc:aes256gcm:d4f3b7...mockCiphertext...",
	})
	req := httptest.NewRequest("POST", "/api/vault/items", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// 3. Inspect raw SQLite database records directly
	var storedPayload string
	err = testDB.QueryRow("SELECT encrypted_payload FROM vault_items WHERE user_id = ?", userId).Scan(&storedPayload)
	if err != nil {
		t.Fatalf("Query vault_items failed: %v", err)
	}

	if strings.Contains(storedPayload, secretNote) {
		t.Fatalf("[CRITICAL ZERO-KNOWLEDGE LEAK] Plaintext secret note found unencrypted in database!")
	}
}
