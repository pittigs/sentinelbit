package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateUsername(t *testing.T) {
	valid := []string{"alice", "bob_123", "user-name", "admin.test"}
	for _, u := range valid {
		res, err := ValidateUsername(u)
		if err != nil {
			t.Errorf("Expected valid username %s, got error: %v", u, err)
		}
		if res != u {
			t.Errorf("Expected %s, got %s", u, res)
		}
	}

	invalid := []string{"", "a", "ab", "user@domain", "user with space", "<script>"}
	for _, u := range invalid {
		_, err := ValidateUsername(u)
		if err == nil {
			t.Errorf("Expected invalid username %s to error, but succeeded", u)
		}
	}
}

func TestValidateBackupDir(t *testing.T) {
	_, err := ValidateBackupDir("", "/data")
	if err == nil {
		t.Errorf("Expected empty dir to fail")
	}

	_, err = ValidateBackupDir("/data", "/data")
	if err == nil {
		t.Errorf("Expected targetDir equal to baseDataDir to fail")
	}
}

func TestRateLimiterLogic(t *testing.T) {
	rl := NewRateLimiter(2, 200*time.Millisecond, 500*time.Millisecond)
	key := "test_ip"

	ok, _ := rl.Check(key)
	if !ok {
		t.Fatalf("Check 1 should be allowed")
	}
	rl.RecordFailure(key)

	ok, _ = rl.Check(key)
	if !ok {
		t.Fatalf("Check 2 should be allowed")
	}
	rl.RecordFailure(key)

	// Exceeded
	ok, wait := rl.Check(key)
	if ok {
		t.Fatalf("Check 3 should be blocked")
	}
	if wait <= 0 {
		t.Fatalf("Wait duration should be positive")
	}

	rl.RecordSuccess(key)
	ok, _ = rl.Check(key)
	if !ok {
		t.Fatalf("Check after success should be allowed")
	}
}

func TestTotpReplayGuard(t *testing.T) {
	rg := NewTotpReplayGuard()
	userId := "user123"
	code := "123456"

	if !rg.CheckAndRecord(userId, code) {
		t.Fatalf("First TOTP code should be accepted")
	}

	if rg.CheckAndRecord(userId, code) {
		t.Fatalf("Replayed TOTP code within same window must be rejected")
	}
}

func TestSecurityHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler := SecurityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	headers := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Content-Security-Policy",
	}

	for _, h := range headers {
		if rr.Header().Get(h) == "" {
			t.Errorf("Missing security header: %s", h)
		}
	}
}
