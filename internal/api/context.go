package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"sentinelbit/internal/config"
	"sentinelbit/internal/crypto"
	"sentinelbit/internal/models"
	"sentinelbit/internal/security"
)

var (
	SessionMu sync.RWMutex
	Sessions  = make(map[string]models.SessionData)

	LoginLimiter = security.NewRateLimiter(5, 60*time.Second, 30*time.Second)
	TotpLimiter  = security.NewRateLimiter(5, 60*time.Second, 30*time.Second)
	ReplayGuard  = security.NewTotpReplayGuard()

	ServerSecret []byte
)

// InitAPI initializes shared cryptographic secrets and loads persisted sessions from the database
func InitAPI(cfg *config.Config, database *sql.DB) {
	ServerSecret = crypto.GetServerSecret(cfg.DataDir)
	LoadSessionsFromDB(database)
}

// LoadSessionsFromDB loads valid, unexpired sessions from SQLite into memory
func LoadSessionsFromDB(database *sql.DB) {
	if database == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := database.Query(`
		SELECT token_hash, user_id, username, expires_at
		FROM sessions WHERE expires_at > ?
	`, now)
	if err != nil {
		return
	}
	defer rows.Close()

	SessionMu.Lock()
	defer SessionMu.Unlock()
	for rows.Next() {
		var token, userId, username, expiresAtStr string
		if err := rows.Scan(&token, &userId, &username, &expiresAtStr); err == nil {
			if t, err := time.Parse(time.RFC3339, expiresAtStr); err == nil {
				Sessions[token] = models.SessionData{
					UserId:    userId,
					Username:  username,
					ExpiresAt: t,
				}
			}
		}
	}
}

// CleanupExpired cleans up expired sessions and rate limiters
func CleanupExpired(database *sql.DB) {
	now := time.Now()
	SessionMu.Lock()
	for token, sess := range Sessions {
		if now.After(sess.ExpiresAt) {
			delete(Sessions, token)
		}
	}
	SessionMu.Unlock()

	if database != nil {
		_, _ = database.Exec("DELETE FROM sessions WHERE expires_at < ?", now.UTC().Format(time.RFC3339))
	}

	LoginLimiter.Cleanup()
	TotpLimiter.Cleanup()
	ReplayGuard.Cleanup()
}

func GetSession(r *http.Request) (*models.SessionData, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("Nicht authentifiziert")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

	SessionMu.RLock()
	sess, exists := Sessions[token]
	SessionMu.RUnlock()

	if !exists {
		return nil, errors.New("Sitzung abgelaufen oder ungültig")
	}

	if time.Now().After(sess.ExpiresAt) {
		SessionMu.Lock()
		delete(Sessions, token)
		SessionMu.Unlock()
		return nil, errors.New("Sitzung abgelaufen. Bitte erneut anmelden.")
	}

	return &sess, nil
}

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := GetSession(r)
		if err != nil {
			HTTPError(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user", sess)
		next(w, r.WithContext(ctx))
	}
}

func GetUserFromCtx(r *http.Request) *models.SessionData {
	if val := r.Context().Value("user"); val != nil {
		if s, ok := val.(*models.SessionData); ok {
			return s
		}
	}
	return nil
}

func JSONResponse(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func HTTPError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": msg})
}
