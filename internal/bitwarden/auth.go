package bitwarden

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const userCtxKey = contextKey("bw_user_ctx")

// HashMasterPassword generates a salted SHA-256 hash of the Bitwarden client-provided masterPasswordHash
func HashMasterPassword(masterPasswordHash, salt string) string {
	sum := sha256.Sum256([]byte(masterPasswordHash + ":" + salt))
	return hex.EncodeToString(sum[:])
}

// GenerateRandomSalt produces a 16-byte hex string
func GenerateRandomSalt() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RequireBwAuth validates Bitwarden Bearer tokens
func RequireBwAuth(database *sql.DB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"unauthorized","message":"Missing or invalid token"}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(authHeader, "Bearer ")
			token = strings.TrimSpace(token)
			if token == "" {
				http.Error(w, `{"error":"unauthorized","message":"Token is empty"}`, http.StatusUnauthorized)
				return
			}

			// Verify in sessions table
			nowISO := time.Now().UTC().Format(time.RFC3339)
			var userID, username string
			err := database.QueryRow(`
				SELECT user_id, username FROM sessions
				WHERE token_hash = ? AND expires_at > ?
			`, token, nowISO).Scan(&userID, &username)

			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"Session expired or invalid"}`, http.StatusUnauthorized)
				return
			}

			// Retrieve Bitwarden-specific user details
			var bwKey, bwPrivKey, bwSecStamp, totpSecret sql.NullString
			var totpEnabled int
			err = database.QueryRow(`
				SELECT bw_key, bw_private_key, bw_security_stamp, totp_enabled, totp_secret
				FROM users WHERE id = ?
			`, userID).Scan(&bwKey, &bwPrivKey, &bwSecStamp, &totpEnabled, &totpSecret)

			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"User not found"}`, http.StatusUnauthorized)
				return
			}

			userCtx := &BwUserContext{
				UserID:        userID,
				Username:      username,
				Email:         username,
				Key:           bwKey.String,
				PrivateKey:    bwPrivKey.String,
				SecurityStamp: bwSecStamp.String,
				TotpEnabled:   totpEnabled == 1,
				TotpSecret:    totpSecret.String,
			}

			ctx := context.WithValue(r.Context(), userCtxKey, userCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetBwUser retrieves the authenticated Bitwarden user context
func GetBwUser(r *http.Request) *BwUserContext {
	val := r.Context().Value(userCtxKey)
	if val == nil {
		return nil
	}
	u, ok := val.(*BwUserContext)
	if !ok {
		return nil
	}
	return u
}
