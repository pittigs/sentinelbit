package security

import (
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{3,64}$`)
)

func ValidateUsername(username string) (string, error) {
	u := strings.TrimSpace(username)
	if !usernameRe.MatchString(u) {
		return "", errors.New("Benutzername muss 3-64 Zeichen lang sein und darf nur Buchstaben, Zahlen, '_', '-' oder '.' enthalten")
	}
	return u, nil
}

func ValidateBackupDir(targetDir, baseDataDir string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(targetDir))
	if clean == "" || clean == "." {
		return "", errors.New("Ungültiger Zielpfad")
	}
	absTarget, err := filepath.Abs(clean)
	if err != nil {
		return "", errors.New("Ungültiger Pfad")
	}
	absBase, err := filepath.Abs(baseDataDir)
	if err != nil {
		return "", errors.New("Ungültiger Basis-Pfad")
	}
	if strings.EqualFold(absTarget, absBase) {
		return "", errors.New("Backup-Ziel darf nicht das Haupt-Datenverzeichnis sein")
	}
	return absTarget, nil
}

// Rate Limiter
type rateEntry struct {
	timestamps []time.Time
	blockedUntil time.Time
}

type RateLimiter struct {
	mu          sync.Mutex
	maxAttempts int
	windowSec   time.Duration
	blockSec    time.Duration
	storage     map[string]*rateEntry
}

func NewRateLimiter(maxAttempts int, window, block time.Duration) *RateLimiter {
	return &RateLimiter{
		maxAttempts: maxAttempts,
		windowSec:   window,
		blockSec:    block,
		storage:     make(map[string]*rateEntry),
	}
}

func (rl *RateLimiter) Check(key string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.storage[key]
	if !exists {
		return true, 0
	}

	if now.Before(entry.blockedUntil) {
		return false, entry.blockedUntil.Sub(now)
	}

	// Purge timestamps older than window
	valid := make([]time.Time, 0, len(entry.timestamps))
	cutoff := now.Add(-rl.windowSec)
	for _, ts := range entry.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	entry.timestamps = valid

	if len(entry.timestamps) >= rl.maxAttempts {
		entry.blockedUntil = now.Add(rl.blockSec)
		return false, rl.blockSec
	}

	return true, 0
}

func (rl *RateLimiter) RecordFailure(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.storage[key]
	if !exists {
		entry = &rateEntry{}
		rl.storage[key] = entry
	}
	entry.timestamps = append(entry.timestamps, now)
	if len(entry.timestamps) >= rl.maxAttempts {
		entry.blockedUntil = now.Add(rl.blockSec)
	}
}

func (rl *RateLimiter) RecordSuccess(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.storage, key)
}

// Cleanup purges stale rate limiter entries whose block duration has passed and have no recent attempts
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowSec)
	for key, entry := range rl.storage {
		if now.After(entry.blockedUntil) {
			hasRecent := false
			for _, ts := range entry.timestamps {
				if ts.After(cutoff) {
					hasRecent = true
					break
				}
			}
			if !hasRecent {
				delete(rl.storage, key)
			}
		}
	}
}

// TOTP Replay Guard
type TotpReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewTotpReplayGuard() *TotpReplayGuard {
	return &TotpReplayGuard{
		seen: make(map[string]time.Time),
	}
}

func (g *TotpReplayGuard) CheckAndRecord(userId, code string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	// Purge older than 90s
	for k, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, k)
		}
	}

	key := userId + ":" + strings.TrimSpace(code)
	if _, exists := g.seen[key]; exists {
		return false // Replay detected!
	}

	g.seen[key] = now.Add(90 * time.Second)
	return true
}

// Cleanup purges expired entries from the replay guard map
func (g *TotpReplayGuard) Cleanup() {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	for k, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, k)
		}
	}
}

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://www.google.com https://*.gstatic.com; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")

		// HSTS (HTTP Strict Transport Security) if TLS or HTTPS proxy is active
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware handles Cross-Origin Resource Sharing for browser extensions and companion clients
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Allow browser extensions (Chrome/Firefox/Edge), localhost, and HTTPS origins
			if strings.HasPrefix(origin, "chrome-extension://") ||
				strings.HasPrefix(origin, "moz-extension://") ||
				strings.HasPrefix(origin, "http://localhost") ||
				strings.HasPrefix(origin, "http://127.0.0.1") ||
				strings.HasPrefix(origin, "https://") {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, X-Requested-With")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}

		// Handle preflight OPTIONS requests immediately
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func GetIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// TokenBucket implements a high-performance thread-safe token bucket rate limiter (#44)
type TokenBucket struct {
	tokens         float64
	capacity       float64
	refillRate     float64
	lastRefillTime time.Time
}

type TokenBucketLimiter struct {
	mu         sync.Mutex
	capacity   float64
	refillRate float64
	buckets    map[string]*TokenBucket
}

func NewTokenBucketLimiter(capacity, refillRate float64) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		capacity:   capacity,
		refillRate: refillRate,
		buckets:    make(map[string]*TokenBucket),
	}
}

func (tbl *TokenBucketLimiter) Allow(key string) bool {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	now := time.Now()
	b, exists := tbl.buckets[key]
	if !exists {
		tbl.buckets[key] = &TokenBucket{
			tokens:         tbl.capacity - 1,
			capacity:       tbl.capacity,
			refillRate:     tbl.refillRate,
			lastRefillTime: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastRefillTime).Seconds()
	b.tokens = b.tokens + elapsed*b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.lastRefillTime = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

func TokenBucketMiddleware(limiter *TokenBucketLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := GetIP(r)
			if !limiter.Allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"detail":"Rate limit exceeded. Please slow down."}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

