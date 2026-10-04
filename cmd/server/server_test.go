package main

import (
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelbit/internal/crypto"
	"sentinelbit/internal/security"
)

// Test 1: Zero-Knowledge PBKDF2 Key Derivation
func TestPBKDF2KeyDerivation(t *testing.T) {
	clientAuthKey := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	serverSalt := "TestServerSalt_12345"

	hash1, err := crypto.HashAuthKey(clientAuthKey, serverSalt, 100_000)
	if err != nil {
		t.Fatalf("Failed to hash auth key: %v", err)
	}

	hash2, err := crypto.HashAuthKey(clientAuthKey, serverSalt, 100_000)
	if err != nil {
		t.Fatalf("Failed to hash auth key 2nd time: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("PBKDF2 hashes must be deterministic! %s != %s", hash1, hash2)
	}

	// Constant-time verification
	if !crypto.VerifyAuthKey(clientAuthKey, serverSalt, hash1) {
		t.Errorf("VerifyAuthKey failed on matching hash")
	}

	// Wrong key must fail
	wrongKey := "0000000000000000000000000000000000000000000000000000000000000000"
	if crypto.VerifyAuthKey(wrongKey, serverSalt, hash1) {
		t.Errorf("VerifyAuthKey succeeded on wrong key!")
	}
}

// Test 2: Rate Limiter Brute Force Defense
func TestRateLimiter(t *testing.T) {
	rl := security.NewRateLimiter(3, 500*time.Millisecond, 2*time.Second)
	key := "test_ip_user"

	// First 3 checks should pass
	for i := 0; i < 3; i++ {
		ok, _ := rl.Check(key)
		if !ok {
			t.Fatalf("Check %d should have been allowed", i+1)
		}
		rl.RecordFailure(key)
	}

	// 4th check should be blocked
	ok, wait := rl.Check(key)
	if ok {
		t.Fatalf("4th check should have been blocked")
	}
	if wait <= 0 {
		t.Errorf("Expected wait duration > 0, got %v", wait)
	}

	// Record success resets limiter
	rl.RecordSuccess(key)
	ok, _ = rl.Check(key)
	if !ok {
		t.Errorf("Key should be unblocked after success")
	}
}

// Test 3: TOTP Generation, Verification & Replay Guard
func TestTOTPAndReplayGuard(t *testing.T) {
	secret, err := crypto.GenerateTotpSecret()
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	code, _, err := crypto.GenerateCurrentTotp(secret)
	if err != nil {
		t.Fatalf("Failed to generate current code: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6-digit TOTP, got %s", code)
	}

	if !crypto.VerifyTotpCode(secret, code) {
		t.Errorf("Failed to verify freshly generated TOTP code")
	}

	// Replay Guard
	guard := security.NewTotpReplayGuard()
	userId := "user_xyz_123"

	// First use -> OK
	if !guard.CheckAndRecord(userId, code) {
		t.Errorf("First consumption of TOTP should succeed")
	}

	// Immediate replay -> MUST FAIL
	if guard.CheckAndRecord(userId, code) {
		t.Errorf("Replay of same TOTP code must be rejected!")
	}
}

// Test 4: WebAuthn / Passkey P-256 Keypair & ECDSA Assertion
func TestWebAuthnPasskeySigning(t *testing.T) {
	kp, err := crypto.GeneratePasskeyKeypair()
	if err != nil {
		t.Fatalf("Failed to generate Passkey keypair: %v", err)
	}

	if kp.CredentialId == "" || kp.PrivateKeyPem == "" || kp.PublicKeyPem == "" {
		t.Fatalf("Passkey keypair components missing")
	}

	clientDataJSON := `{"type":"webauthn.get","challenge":"AAAA","origin":"https://sentinelbit.local"}`
	authDataHex := "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000001"

	sigResult, err := crypto.SignWebAuthnAssertion(kp.PrivateKeyPem, clientDataJSON, authDataHex)
	if err != nil {
		t.Fatalf("Failed to sign WebAuthn assertion: %v", err)
	}

	if sigResult.SignatureB64 == "" || sigResult.SignatureHex == "" {
		t.Errorf("Signature result empty")
	}
}

// Test 5: Input Validation & Path Traversal Defense
func TestSecuritySanitization(t *testing.T) {
	// Username checks
	validUser, err := security.ValidateUsername("sebastian_01")
	if err != nil || validUser != "sebastian_01" {
		t.Errorf("Valid username failed: %v", err)
	}

	// Path Traversal in username
	_, err = security.ValidateUsername("../../../etc/passwd")
	if err == nil {
		t.Errorf("Path traversal in username must fail!")
	}

	// XSS in username
	_, err = security.ValidateUsername("<script>alert(1)</script>")
	if err == nil {
		t.Errorf("XSS in username must fail!")
	}

	// Backup target dir validation
	_, err = security.ValidateBackupDir(".", ".")
	if err == nil {
		t.Errorf("Target dir matching base dir must fail!")
	}
}

// Test 6: Security Headers Middleware
func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := security.SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("Missing X-Frame-Options: DENY")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Missing X-Content-Type-Options: nosniff")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy missing clickjacking protection")
	}
}

// Test 7: Anti-Enumeration Dummy Salts
func TestAntiEnumerationSalts(t *testing.T) {
	secret := []byte("super_secret_master_key_for_salt_gen_32b")
	salt1, enc1 := crypto.GenerateDummySalts(secret, "alice")
	salt2, enc2 := crypto.GenerateDummySalts(secret, "alice")
	saltBob, _ := crypto.GenerateDummySalts(secret, "bob")

	// Deterministic for same user
	if salt1 != salt2 || enc1 != enc2 {
		t.Errorf("Dummy salts must be deterministic for the same username")
	}

	// Distinct for different user
	if salt1 == saltBob {
		t.Errorf("Dummy salts must differ for different usernames")
	}

	if subtle.ConstantTimeCompare([]byte(salt1), []byte(salt2)) != 1 {
		t.Errorf("Timing-safe compare failed")
	}
}
