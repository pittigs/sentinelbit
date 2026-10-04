package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"sentinelbit/internal/backup"
	"sentinelbit/internal/crypto"
	"sentinelbit/internal/db"
	"sentinelbit/internal/models"
	"sentinelbit/internal/security"
)

var (
	hex64Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

	sessionMu sync.RWMutex
	sessions  = make(map[string]models.SessionData)

	loginLimiter = security.NewRateLimiter(5, 60*time.Second, 30*time.Second)
	totpLimiter  = security.NewRateLimiter(5, 60*time.Second, 30*time.Second)
	replayGuard  = security.NewTotpReplayGuard()

	serverSecret []byte
)

func init() {
	serverSecret = crypto.GetServerSecret(db.GetDataDir())
}

// Session helper
func getSession(r *http.Request) (*models.SessionData, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("Nicht authentifiziert")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))

	sessionMu.RLock()
	sess, exists := sessions[token]
	sessionMu.RUnlock()

	if !exists {
		return nil, errors.New("Sitzung abgelaufen oder ungültig")
	}

	if time.Now().After(sess.ExpiresAt) {
		sessionMu.Lock()
		delete(sessions, token)
		sessionMu.Unlock()
		return nil, errors.New("Sitzung abgelaufen. Bitte erneut anmelden.")
	}

	return &sess, nil
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := getSession(r)
		if err != nil {
			httpError(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user", sess)
		next(w, r.WithContext(ctx))
	}
}

func getUserFromCtx(r *http.Request) *models.SessionData {
	if val := r.Context().Value("user"); val != nil {
		if s, ok := val.(*models.SessionData); ok {
			return s
		}
	}
	return nil
}

func jsonResponse(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func httpError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": msg})
}

func setupRouter(database *sql.DB) *chi.Mux {
	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(security.SecurityHeadersMiddleware)

	// API Routes
	r.Route("/api", func(api chi.Router) {
		api.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			jsonResponse(w, map[string]string{
				"status":  "healthy",
				"service": "sentinelbit (Go)",
				"version": "2.0.0",
			}, http.StatusOK)
		})

		// Auth
		api.Route("/auth", func(auth chi.Router) {
			auth.Post("/register", handleRegister(database))
			auth.Post("/login-init", handleLoginInit(database))
			auth.Post("/login-verify", handleLoginVerify(database))
			auth.Post("/logout", handleLogout)
			auth.Get("/me", requireAuth(handleAuthMe))
			auth.Get("/emergency-kit", requireAuth(handleEmergencyKit(database)))

			// 2FA TOTP
			auth.Post("/2fa/setup", requireAuth(handle2faSetup(database)))
			auth.Post("/2fa/verify", requireAuth(handle2faVerify(database)))
			auth.Post("/2fa/disable", requireAuth(handle2faDisable(database)))

			// WebAuthn device unlock keys
			auth.Get("/webauthn/keys", requireAuth(handleListWebAuthnKeys(database)))
			auth.Post("/webauthn/register-key", requireAuth(handleRegisterWebAuthnKey(database)))
			auth.Delete("/webauthn/keys/{keyId}", requireAuth(handleDeleteWebAuthnKey(database)))
		})

		// Vault Items
		api.Route("/vault", func(vault chi.Router) {
			vault.Get("/items", requireAuth(handleListVaultItems(database)))
			vault.Post("/items", requireAuth(handleCreateVaultItem(database)))
			vault.Delete("/items/all", requireAuth(handleClearVault(database)))
			vault.Put("/items/{itemId}", requireAuth(handleUpdateVaultItem(database)))
			vault.Delete("/items/{itemId}", requireAuth(handleDeleteVaultItem(database)))
			vault.Post("/items/{itemId}/restore", requireAuth(handleRestoreVaultItem(database)))
			vault.Get("/trash", requireAuth(handleListTrashItems(database)))
			vault.Delete("/trash", requireAuth(handleEmptyTrash(database)))
		})

		// Passkeys (FIDO2)
		api.Route("/passkeys", func(pk chi.Router) {
			pk.Post("/generate", requireAuth(handlePasskeyGenerate))
			pk.Get("/", requireAuth(handleListPasskeys(database)))
			pk.Post("/", requireAuth(handleSavePasskey(database)))
			pk.Delete("/{passkeyId}", requireAuth(handleDeletePasskey(database)))
			pk.Post("/sign-test", requireAuth(handlePasskeySignTest))
		})

		// Tools
		api.Post("/tools/totp", handleComputeTotp)
		api.Get("/tools/hibp/{prefix}", handleCheckHIBP)

		// Sync & Backup
		api.Get("/sync/settings", requireAuth(handleGetSyncSettings(database)))
		api.Post("/sync/settings", requireAuth(handleSaveSyncSettings(database)))
		api.Post("/sync/now", requireAuth(handleTriggerSyncNow))

		// Aliases
		api.Get("/aliases", requireAuth(handleListAliases(database)))
		api.Post("/aliases", requireAuth(handleCreateAlias(database)))
		api.Delete("/aliases/{aliasId}", requireAuth(handleDeleteAlias(database)))

		// Item Sharing
		api.Post("/share/public-key", requireAuth(handleRegisterSharePublicKey(database)))
		api.Get("/share/user/{targetUsername}/public-key", requireAuth(handleGetRecipientPublicKey(database)))
		api.Post("/share/send", requireAuth(handleSendSharedItem(database)))
		api.Get("/share/inbox", requireAuth(handleListSharedInbox(database)))
		api.Delete("/share/inbox/{itemId}", requireAuth(handleDeleteSharedInboxItem(database)))
	})

	// Static frontend
	staticDir := filepath.Join(".", "static")
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		_ = os.MkdirAll(staticDir, 0755)
	}

	fs := http.FileServer(http.Dir(staticDir))
	r.Handle("/static/*", http.StripPrefix("/static/", fs))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
	})

	return r
}

func main() {
	// Initialize database
	database, err := db.InitDB()
	if err != nil {
		log.Fatalf("Fatal: Database init failed: %v", err)
	}

	// Start background backup worker
	backup.Engine.Start()
	defer backup.Engine.Stop()

	r := setupRouter(database)

	port := os.Getenv("SENTINELBIT_PORT")
	if port == "" {
		port = "8000"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("🛡️ sentinelbit (Go Single-Binary) läuft auf http://127.0.0.1:%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stopChan
	log.Println("Fahre sentinelbit Server herunter...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Println("Server sicher beendet.")
}

// -------------------------------------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------------------------------------

func handleRegister(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		username, err := security.ValidateUsername(req.Username)
		if err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}
		username = strings.ToLower(username)

		if !hex64Re.MatchString(req.AuthHash) {
			httpError(w, "Ungültiges Auth-Key-Format", http.StatusBadRequest)
			return
		}

		if req.AuthSalt == "" || strings.Contains(req.AuthSalt, ":") || len(req.AuthSalt) > 128 ||
			req.EncSalt == "" || len(req.EncSalt) > 128 {
			httpError(w, "Ungültiges Salt-Format", http.StatusBadRequest)
			return
		}

		var existingID string
		err = db.QueryRow("SELECT id FROM users WHERE LOWER(username) = ?", username).Scan(&existingID)
		if err == nil {
			httpError(w, "Benutzername existiert bereits", http.StatusBadRequest)
			return
		}

		userId := uuid.New().String()
		serverSalt := crypto.GenerateSalt(32)
		finalAuthHash, err := crypto.HashAuthKey(req.AuthHash, serverSalt, 100_000)
		if err != nil {
			httpError(w, "Kryptofehler beim Hashen", http.StatusInternalServerError)
			return
		}

		combinedAuthSalt := fmt.Sprintf("%s:%s", req.AuthSalt, serverSalt)
		now := time.Now().UTC().Format(time.RFC3339)

		_, err = db.Exec(`
			INSERT INTO users (id, username, auth_salt, auth_hash, enc_salt, totp_secret, totp_enabled, created_at)
			VALUES (?, ?, ?, ?, ?, NULL, 0, ?)
		`, userId, username, combinedAuthSalt, finalAuthHash, req.EncSalt, now)

		if err != nil {
			httpError(w, "Fehler beim Speichern des Kontos", http.StatusInternalServerError)
			return
		}

		jsonResponse(w, map[string]string{
			"status":  "ok",
			"message": "Konto erfolgreich erstellt",
		}, http.StatusOK)
	}
}

func handleLoginInit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.LoginInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		username := strings.ToLower(strings.TrimSpace(req.Username))
		var authSalt, encSalt string
		var totpEnabled int

		err := db.QueryRow(`
			SELECT auth_salt, enc_salt, totp_enabled FROM users WHERE username = ?
		`, username).Scan(&authSalt, &encSalt, &totpEnabled)

		if err != nil {
			// Timing-safe dummy salts against user enumeration
			dAuthSalt, dEncSalt := crypto.GenerateDummySalts(serverSecret, username)
			jsonResponse(w, models.LoginInitResponse{
				AuthSalt:     dAuthSalt,
				EncSalt:      dEncSalt,
				TotpRequired: false,
			}, http.StatusOK)
			return
		}

		jsonResponse(w, models.LoginInitResponse{
			AuthSalt:     authSalt,
			EncSalt:      encSalt,
			TotpRequired: totpEnabled == 1,
		}, http.StatusOK)
	}
}

func handleLoginVerify(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.LoginVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		ip := security.GetIP(r)
		username := strings.ToLower(strings.TrimSpace(req.Username))
		limiterKey := fmt.Sprintf("%s:%s", ip, username)

		if allowed, waitDur := loginLimiter.Check(limiterKey); !allowed {
			httpError(w, fmt.Sprintf("Zu viele Fehlversuche. Bitte warte %d Sekunden.", int(waitDur.Seconds())), http.StatusTooManyRequests)
			return
		}

		var userId, authSalt, storedAuthHash, encSalt string
		var totpSecret, recoveryCodes sql.NullString
		var totpEnabled int

		err := db.QueryRow(`
			SELECT id, auth_salt, auth_hash, enc_salt, totp_secret, totp_enabled, recovery_codes
			FROM users WHERE username = ?
		`, username).Scan(&userId, &authSalt, &storedAuthHash, &encSalt, &totpSecret, &totpEnabled, &recoveryCodes)

		if err != nil {
			// Anti-enumeration dummy calculation
			_, _ = crypto.HashAuthKey("0000000000000000000000000000000000000000000000000000000000000000", "dummy-salt", 100_000)
			loginLimiter.RecordFailure(limiterKey)
			httpError(w, "Ungültige Anmeldedaten", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authSalt, ":")
		if len(parts) < 2 {
			httpError(w, "Interner Fehler in Salt-Struktur", http.StatusInternalServerError)
			return
		}
		serverSalt := parts[1]

		if !crypto.VerifyAuthKey(req.ClientAuthKey, serverSalt, storedAuthHash) {
			loginLimiter.RecordFailure(limiterKey)
			httpError(w, "Ungültige Anmeldedaten", http.StatusUnauthorized)
			return
		}

		// Check 2FA if enabled
		if totpEnabled == 1 {
			verified := false

			if req.TotpCode != "" && totpSecret.Valid {
				if crypto.VerifyTotpCode(totpSecret.String, req.TotpCode) {
					if replayGuard.CheckAndRecord(userId, req.TotpCode) {
						verified = true
					}
				}
			}

			// Recovery code check
			if !verified && req.RecoveryCode != "" && recoveryCodes.Valid {
				var recList []string
				_ = json.Unmarshal([]byte(recoveryCodes.String), &recList)
				codeUpper := strings.ToUpper(strings.TrimSpace(req.RecoveryCode))
				for i, rc := range recList {
					if subtle.ConstantTimeCompare([]byte(rc), []byte(codeUpper)) == 1 {
						verified = true
						recList = append(recList[:i], recList[i+1:]...)
						newJson, _ := json.Marshal(recList)
						_, _ = db.Exec("UPDATE users SET recovery_codes = ? WHERE id = ?", string(newJson), userId)
						break
					}
				}
			}

			if !verified {
				loginLimiter.RecordFailure(limiterKey)
				httpError(w, "Ungültiger Zwei-Faktor- oder Wiederherstellungscode", http.StatusUnauthorized)
				return
			}
		}

		loginLimiter.RecordSuccess(limiterKey)

		// Create session
		token := uuid.New().String()
		expiresAt := time.Now().Add(12 * time.Hour)

		sessionMu.Lock()
		sessions[token] = models.SessionData{
			UserId:    userId,
			Username:  username,
			ExpiresAt: expiresAt,
		}
		sessionMu.Unlock()

		jsonResponse(w, models.LoginResponse{
			Status:      "ok",
			Token:       token,
			UserId:      userId,
			Username:    username,
			EncSalt:     encSalt,
			TotpEnabled: totpEnabled == 1,
		}, http.StatusOK)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		sessionMu.Lock()
		delete(sessions, token)
		sessionMu.Unlock()
	}
	jsonResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

func handleAuthMe(w http.ResponseWriter, r *http.Request) {
	user := getUserFromCtx(r)
	jsonResponse(w, map[string]interface{}{
		"status":   "authenticated",
		"user_id":  user.UserId,
		"username": user.Username,
	}, http.StatusOK)
}

func handle2faSetup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)

		var enabled int
		_ = db.QueryRow("SELECT totp_enabled FROM users WHERE id = ?", user.UserId).Scan(&enabled)
		if enabled == 1 {
			httpError(w, "2FA ist bereits aktiv. Bitte zuerst deaktivieren.", http.StatusConflict)
			return
		}

		secret, err := crypto.GenerateTotpSecret()
		if err != nil {
			httpError(w, "Fehler beim Generieren des 2FA-Schlüssels", http.StatusInternalServerError)
			return
		}

		uri := crypto.GetTotpURI(secret, user.Username, "sentinelbit")
		qrB64, err := crypto.GenerateTotpQRBase64(uri)
		if err != nil {
			httpError(w, "Fehler beim Erstellen des QR-Codes", http.StatusInternalServerError)
			return
		}

		_, _ = db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", secret, user.UserId)

		jsonResponse(w, models.TotpSetupResponse{
			Secret:       secret,
			ProvisionURI: uri,
			QRCodeBase64: qrB64,
		}, http.StatusOK)
	}
}

func handle2faVerify(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.TotpVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		limiterKey := fmt.Sprintf("totp:%s", user.UserId)
		if allowed, waitDur := totpLimiter.Check(limiterKey); !allowed {
			httpError(w, fmt.Sprintf("Zu viele Versuche. Warte %d s", int(waitDur.Seconds())), http.StatusTooManyRequests)
			return
		}

		var secret sql.NullString
		var enabled int
		err := db.QueryRow("SELECT totp_secret, totp_enabled FROM users WHERE id = ?", user.UserId).Scan(&secret, &enabled)
		if err != nil || !secret.Valid || secret.String == "" {
			httpError(w, "2FA-Einrichtung wurde nicht initialisiert", http.StatusBadRequest)
			return
		}

		if enabled == 1 {
			httpError(w, "2FA ist bereits aktiv", http.StatusConflict)
			return
		}

		if !crypto.VerifyTotpCode(secret.String, req.Code) || !replayGuard.CheckAndRecord(user.UserId, req.Code) {
			totpLimiter.RecordFailure(limiterKey)
			httpError(w, "Ungültiger 2FA-Code. Bitte Uhrzeit prüfen.", http.StatusBadRequest)
			return
		}

		totpLimiter.RecordSuccess(limiterKey)
		recoveryCodes := crypto.GenerateRecoveryCodes(5)
		recJson, _ := json.Marshal(recoveryCodes)

		_, _ = db.Exec("UPDATE users SET totp_enabled = 1, recovery_codes = ? WHERE id = ?", string(recJson), user.UserId)

		jsonResponse(w, map[string]interface{}{
			"status":         "ok",
			"message":        "2FA erfolgreich aktiviert!",
			"recovery_codes": recoveryCodes,
		}, http.StatusOK)
	}
}

func handle2faDisable(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.TotpDisableRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		var secret, recoveryCodes sql.NullString
		err := db.QueryRow("SELECT totp_secret, recovery_codes FROM users WHERE id = ?", user.UserId).Scan(&secret, &recoveryCodes)
		if err != nil {
			httpError(w, "Benutzer nicht gefunden", http.StatusNotFound)
			return
		}

		limiterKey := fmt.Sprintf("totp:%s", user.UserId)
		if allowed, waitDur := totpLimiter.Check(limiterKey); !allowed {
			httpError(w, fmt.Sprintf("Zu viele Versuche. Warte %d s", int(waitDur.Seconds())), http.StatusTooManyRequests)
			return
		}

		isValid := false
		code := strings.TrimSpace(req.Code)
		if secret.Valid && crypto.VerifyTotpCode(secret.String, code) && replayGuard.CheckAndRecord(user.UserId, code) {
			isValid = true
		} else if recoveryCodes.Valid {
			var codes []string
			_ = json.Unmarshal([]byte(recoveryCodes.String), &codes)
			codeUpper := strings.ToUpper(code)
			for _, c := range codes {
				if subtle.ConstantTimeCompare([]byte(c), []byte(codeUpper)) == 1 {
					isValid = true
					break
				}
			}
		}

		if !isValid {
			totpLimiter.RecordFailure(limiterKey)
			httpError(w, "Ungültiger Bestätigungscode", http.StatusBadRequest)
			return
		}

		totpLimiter.RecordSuccess(limiterKey)
		_, _ = db.Exec("UPDATE users SET totp_enabled = 0, totp_secret = NULL, recovery_codes = NULL WHERE id = ?", user.UserId)

		jsonResponse(w, map[string]string{"status": "ok", "message": "2FA wurde deaktiviert"}, http.StatusOK)
	}
}

// Vault items CRUD
func handleListVaultItems(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
			FROM vault_items WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')
			ORDER BY favorite DESC, updated_at DESC
		`, user.UserId)
		if err != nil {
			httpError(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		items := make([]models.VaultItemResponse, 0)
		for rows.Next() {
			var item models.VaultItemResponse
			var fav int
			var folder sql.NullString
			if err := rows.Scan(&item.ID, &item.Type, &item.Title, &folder, &fav, &item.EncryptedPayload, &item.CreatedAt, &item.UpdatedAt); err == nil {
				item.Folder = folder.String
				item.Favorite = fav == 1
				items = append(items, item)
			}
		}
		jsonResponse(w, items, http.StatusOK)
	}
}

func handleListTrashItems(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
			FROM vault_items WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at != ''
			ORDER BY updated_at DESC
		`, user.UserId)
		if err != nil {
			httpError(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		items := make([]models.VaultItemResponse, 0)
		for rows.Next() {
			var item models.VaultItemResponse
			var fav int
			var folder sql.NullString
			if err := rows.Scan(&item.ID, &item.Type, &item.Title, &folder, &fav, &item.EncryptedPayload, &item.CreatedAt, &item.UpdatedAt); err == nil {
				item.Folder = folder.String
				item.Favorite = fav == 1
				items = append(items, item)
			}
		}
		jsonResponse(w, items, http.StatusOK)
	}
}

func handleCreateVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.VaultItemCreate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		itemId := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)
		fav := 0
		if req.Favorite {
			fav = 1
		}

		_, err := db.Exec(`
			INSERT INTO vault_items (id, user_id, type, title, folder, favorite, encrypted_payload, created_at, updated_at, deleted_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		`, itemId, user.UserId, req.Type, req.Title, req.Folder, fav, req.EncryptedPayload, now, now)

		if err != nil {
			httpError(w, "Fehler beim Anlegen des Eintrags", http.StatusInternalServerError)
			return
		}

		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)

		jsonResponse(w, models.VaultItemResponse{
			ID:               itemId,
			Type:             req.Type,
			Title:            req.Title,
			Folder:           req.Folder,
			Favorite:         req.Favorite,
			EncryptedPayload: req.EncryptedPayload,
			CreatedAt:        now,
			UpdatedAt:        now,
		}, http.StatusOK)
	}
}

func handleUpdateVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")

		var req models.VaultItemUpdate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		var existingType, existingTitle, existingFolder, existingPayload, createdAt string
		var existingFav int
		err := db.QueryRow(`
			SELECT type, title, folder, favorite, encrypted_payload, created_at
			FROM vault_items WHERE id = ? AND user_id = ?
		`, itemId, user.UserId).Scan(&existingType, &existingTitle, &existingFolder, &existingFav, &existingPayload, &createdAt)

		if err != nil {
			httpError(w, "Eintrag nicht gefunden", http.StatusNotFound)
			return
		}

		title := existingTitle
		if req.Title != "" {
			title = req.Title
		}
		folder := existingFolder
		if req.Folder != "" {
			folder = req.Folder
		}
		fav := existingFav
		if req.Favorite != nil {
			if *req.Favorite {
				fav = 1
			} else {
				fav = 0
			}
		}
		payload := existingPayload
		if req.EncryptedPayload != "" {
			payload = req.EncryptedPayload
		}
		now := time.Now().UTC().Format(time.RFC3339)

		_, err = db.Exec(`
			UPDATE vault_items SET title = ?, folder = ?, favorite = ?, encrypted_payload = ?, updated_at = ?
			WHERE id = ? AND user_id = ?
		`, title, folder, fav, payload, now, itemId, user.UserId)

		if err != nil {
			httpError(w, "Fehler beim Aktualisieren", http.StatusInternalServerError)
			return
		}

		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)

		jsonResponse(w, models.VaultItemResponse{
			ID:               itemId,
			Type:             existingType,
			Title:            title,
			Folder:           folder,
			Favorite:         fav == 1,
			EncryptedPayload: payload,
			CreatedAt:        createdAt,
			UpdatedAt:        now,
		}, http.StatusOK)
	}
}

func handleDeleteVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")
		permanent := r.URL.Query().Get("permanent") == "true"

		var deletedAt sql.NullString
		err := db.QueryRow("SELECT deleted_at FROM vault_items WHERE id = ? AND user_id = ?", itemId, user.UserId).Scan(&deletedAt)
		if err != nil {
			httpError(w, "Eintrag nicht gefunden", http.StatusNotFound)
			return
		}

		if permanent || (deletedAt.Valid && deletedAt.String != "") {
			_, _ = db.Exec("DELETE FROM vault_items WHERE id = ? AND user_id = ?", itemId, user.UserId)
			_, _ = db.Exec("DELETE FROM passkeys WHERE vault_item_id = ? AND user_id = ?", itemId, user.UserId)
			_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
			jsonResponse(w, map[string]string{"status": "ok", "message": "Eintrag endgültig gelöscht"}, http.StatusOK)
		} else {
			now := time.Now().UTC().Format(time.RFC3339)
			_, _ = db.Exec("UPDATE vault_items SET deleted_at = ? WHERE id = ? AND user_id = ?", now, itemId, user.UserId)
			_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
			jsonResponse(w, map[string]string{"status": "ok", "message": "Eintrag in den Papierkorb verschoben"}, http.StatusOK)
		}
	}
}

func handleRestoreVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")

		_, _ = db.Exec("UPDATE vault_items SET deleted_at = NULL WHERE id = ? AND user_id = ?", itemId, user.UserId)
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		jsonResponse(w, map[string]string{"status": "ok", "message": "Eintrag aus dem Papierkorb wiederhergestellt"}, http.StatusOK)
	}
}

func handleEmptyTrash(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		_, _ = db.Exec("DELETE FROM vault_items WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at != ''", user.UserId)
		jsonResponse(w, map[string]string{"status": "ok", "message": "Papierkorb vollständig geleert"}, http.StatusOK)
	}
}

func handleClearVault(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		_, err1 := db.Exec("DELETE FROM vault_items WHERE user_id = ?", user.UserId)
		_, err2 := db.Exec("DELETE FROM passkeys WHERE user_id = ?", user.UserId)
		if err1 != nil || err2 != nil {
			httpError(w, "Fehler beim Leeren des Tresors", http.StatusInternalServerError)
			return
		}
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		jsonResponse(w, map[string]string{"status": "ok", "message": "Tresor wurde vollständig geleert"}, http.StatusOK)
	}
}

// Passkeys
func handlePasskeyGenerate(w http.ResponseWriter, r *http.Request) {
	var req models.PasskeyGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Ungültiges JSON", http.StatusBadRequest)
		return
	}

	keypair, err := crypto.GeneratePasskeyKeypair()
	if err != nil {
		httpError(w, "Fehler beim Generieren des Passkey-Schlüsselpaars", http.StatusInternalServerError)
		return
	}

	userHandle := uuid.New().String()

	jsonResponse(w, map[string]interface{}{
		"rp_id":            req.RpId,
		"rp_name":          req.RpName,
		"username":         req.Username,
		"user_handle":      userHandle,
		"credential_id":    keypair.CredentialId,
		"private_key_pem":  keypair.PrivateKeyPem,
		"public_key_pem":   keypair.PublicKeyPem,
		"public_key_cose":  keypair.PublicKeyCose,
		"x":                keypair.X,
		"y":                keypair.Y,
	}, http.StatusOK)
}

func handleListPasskeys(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, vault_item_id, rp_id, rp_name, username, user_handle, credential_id,
			       encrypted_private_key, public_key_cose, public_key_pem, sign_count, transports, created_at, last_used_at
			FROM passkeys WHERE user_id = ? ORDER BY created_at DESC
		`, user.UserId)
		if err != nil {
			httpError(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		result := make([]map[string]interface{}, 0)
		for rows.Next() {
			var id, rpId, rpName, uName, credId, encPriv, pubCose, createdAt string
			var vaultItemId, userHandle, pubPem, transports, lastUsedAt sql.NullString
			var signCount int
			if err := rows.Scan(&id, &vaultItemId, &rpId, &rpName, &uName, &userHandle, &credId,
				&encPriv, &pubCose, &pubPem, &signCount, &transports, &createdAt, &lastUsedAt); err == nil {
				
				var trans []string
				if transports.Valid && transports.String != "" {
					_ = json.Unmarshal([]byte(transports.String), &trans)
				} else {
					trans = []string{"internal", "hybrid"}
				}

				item := map[string]interface{}{
					"id":                    id,
					"vault_item_id":         vaultItemId.String,
					"rp_id":                 rpId,
					"rp_name":               rpName,
					"username":              uName,
					"user_handle":           userHandle.String,
					"credential_id":         credId,
					"encrypted_private_key": encPriv,
					"public_key_cose":       pubCose,
					"public_key_pem":        pubPem.String,
					"sign_count":            signCount,
					"transports":            trans,
					"created_at":            createdAt,
					"last_used_at":          lastUsedAt.String,
				}
				result = append(result, item)
			}
		}
		jsonResponse(w, result, http.StatusOK)
	}
}

func handleSavePasskey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.PasskeySaveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		pkId := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)
		trans := `["internal","hybrid"]`
		if req.Transports != "" {
			trans = req.Transports
		}

		_, err := db.Exec(`
			INSERT INTO passkeys (
				id, user_id, vault_item_id, rp_id, rp_name, username, user_handle,
				credential_id, encrypted_private_key, public_key_cose, public_key_pem,
				sign_count, transports, created_at, last_used_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)
		`, pkId, user.UserId, req.VaultItemId, req.RpId, req.RpName,
			req.Username, req.UserHandle, req.CredentialId, req.EncryptedPrivateKey,
			req.PublicKeyCose, req.PublicKeyPem, trans, now)

		if err != nil {
			httpError(w, "Fehler beim Speichern des Passkeys", http.StatusInternalServerError)
			return
		}

		jsonResponse(w, map[string]string{
			"status":  "ok",
			"id":      pkId,
			"message": "Passkey sicher im Tresor gespeichert",
		}, http.StatusOK)
	}
}

func handleDeletePasskey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		pkId := chi.URLParam(r, "passkeyId")
		_, _ = db.Exec("DELETE FROM passkeys WHERE id = ? AND user_id = ?", pkId, user.UserId)
		jsonResponse(w, map[string]string{"status": "ok", "message": "Passkey gelöscht"}, http.StatusOK)
	}
}

func handlePasskeySignTest(w http.ResponseWriter, r *http.Request) {
	var req models.PasskeySignTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Ungültiges JSON", http.StatusBadRequest)
		return
	}

	res, err := crypto.SignWebAuthnAssertion(req.PrivateKeyPem, req.ClientDataJson, req.AuthDataHex)
	if err != nil {
		httpError(w, fmt.Sprintf("Signierfehler: %v", err), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"status":    "ok",
		"assertion": res,
	}, http.StatusOK)
}

func cleanTotpSecretStr(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		if u, err := url.Parse(raw); err == nil {
			if s := u.Query().Get("secret"); s != "" {
				raw = s
			}
		}
	} else if strings.Contains(raw, "secret=") {
		parts := strings.Split(raw, "secret=")
		if len(parts) > 1 {
			raw = strings.Split(parts[1], "&")[0]
		}
	}
	raw = strings.ToUpper(raw)
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, "-", "")
	raw = strings.TrimRight(raw, "=")
	return raw
}

func handleComputeTotp(w http.ResponseWriter, r *http.Request) {
	var req models.TotpComputeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Ungültiges JSON", http.StatusBadRequest)
		return
	}

	clean := cleanTotpSecretStr(req.Secret)
	code, rem, err := crypto.GenerateCurrentTotp(clean)
	if err != nil {
		httpError(w, "Ungültiger TOTP-Schlüssel", http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"code":              code,
		"remaining_seconds": rem,
		"period":            30,
	}, http.StatusOK)
}

func handleCheckHIBP(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimSpace(chi.URLParam(r, "prefix")))
	if len(prefix) != 5 {
		httpError(w, "Prefix muss genau 5 Hex-Zeichen lang sein", http.StatusBadRequest)
		return
	}

	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	client := &http.Client{Timeout: 6 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "sentinelbit-Go-HIBP-Check")

	resp, err := client.Do(req)
	if err != nil {
		jsonResponse(w, map[string]string{
			"status": "offline_fallback",
			"prefix": prefix,
			"data":   "",
			"error":  err.Error(),
		}, http.StatusOK)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	jsonResponse(w, map[string]string{
		"status": "ok",
		"prefix": prefix,
		"data":   string(bodyBytes),
	}, http.StatusOK)
}

// Biometric unlock keys
func handleListWebAuthnKeys(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		rows, err := db.Query("SELECT id, credential_id, device_name, created_at FROM webauthn_unlock_keys WHERE user_id = ?", user.UserId)
		if err != nil {
			httpError(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		res := make([]map[string]string, 0)
		for rows.Next() {
			var id, credId, devName, createdAt string
			if err := rows.Scan(&id, &credId, &devName, &createdAt); err == nil {
				res = append(res, map[string]string{
					"id":            id,
					"credential_id": credId,
					"device_name":   devName,
					"created_at":    createdAt,
				})
			}
		}
		jsonResponse(w, res, http.StatusOK)
	}
}

func handleRegisterWebAuthnKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.WebAuthnKeyRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		keyId := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)
		_, err := db.Exec(`
			INSERT INTO webauthn_unlock_keys (id, user_id, credential_id, public_key, device_name, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, keyId, user.UserId, req.CredentialId, req.PublicKey, req.DeviceName, now)

		if err != nil {
			httpError(w, "Fehler beim Registrieren", http.StatusInternalServerError)
			return
		}

		jsonResponse(w, map[string]string{
			"status":  "ok",
			"id":      keyId,
			"message": "Biometrisches Gerät erfolgreich registriert",
		}, http.StatusOK)
	}
}

func handleDeleteWebAuthnKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		keyId := chi.URLParam(r, "keyId")
		_, _ = db.Exec("DELETE FROM webauthn_unlock_keys WHERE id = ? AND user_id = ?", keyId, user.UserId)
		jsonResponse(w, map[string]string{"status": "ok", "message": "Geräteschlüssel entfernt"}, http.StatusOK)
	}
}

// Backup & Sync
func handleGetSyncSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var targetDir string
		var intervalMin, syncOnChange, retention, isActive int
		var lastSyncedAt, lastSyncStatus sql.NullString

		err := db.QueryRow(`
			SELECT target_dir, interval_minutes, sync_on_change, retention_count, is_active, last_synced_at, last_sync_status
			FROM backup_sync_settings WHERE user_id = ?
		`, user.UserId).Scan(&targetDir, &intervalMin, &syncOnChange, &retention, &isActive, &lastSyncedAt, &lastSyncStatus)

		if err != nil {
			absDefault, _ := filepath.Abs(filepath.Join("backups", user.Username))
			jsonResponse(w, map[string]interface{}{
				"target_dir":       absDefault,
				"interval_minutes": 15,
				"sync_on_change":   true,
				"retention_count":  10,
				"is_active":        false,
				"last_synced_at":   nil,
				"last_sync_status": "Noch nicht eingerichtet",
			}, http.StatusOK)
			return
		}

		status := "Bereit"
		if lastSyncStatus.Valid && lastSyncStatus.String != "" {
			status = lastSyncStatus.String
		}

		jsonResponse(w, map[string]interface{}{
			"target_dir":       targetDir,
			"interval_minutes": intervalMin,
			"sync_on_change":   syncOnChange == 1,
			"retention_count":  retention,
			"is_active":        isActive == 1,
			"last_synced_at":   lastSyncedAt.String,
			"last_sync_status": status,
		}, http.StatusOK)
	}
}

func handleSaveSyncSettings(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.BackupSyncSettingsModel
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		cleanDir, err := security.ValidateBackupDir(req.TargetDir, dbDir())
		if err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}

		retention := req.RetentionCount
		if retention < 1 {
			retention = 10
		}
		interval := req.IntervalMinutes
		if interval < 1 {
			interval = 15
		}

		syncChange := 0
		if req.SyncOnChange {
			syncChange = 1
		}
		active := 0
		if req.IsActive {
			active = 1
		}

		settingId := uuid.New().String()
		_, err = db.Exec(`
			INSERT INTO backup_sync_settings (id, user_id, target_dir, interval_minutes, sync_on_change, retention_count, is_active, last_sync_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'Konfiguriert')
			ON CONFLICT(user_id) DO UPDATE SET
				target_dir = excluded.target_dir,
				interval_minutes = excluded.interval_minutes,
				sync_on_change = excluded.sync_on_change,
				retention_count = excluded.retention_count,
				is_active = excluded.is_active
		`, settingId, user.UserId, cleanDir, interval, syncChange, retention, active)

		if err != nil {
			httpError(w, "Fehler beim Speichern der Einstellungen", http.StatusInternalServerError)
			return
		}

		if req.IsActive {
			_, _ = backup.Engine.ExecuteBackup(user.UserId, false)
		}

		jsonResponse(w, map[string]string{
			"status":  "ok",
			"message": "Backup- & Sync-Plan erfolgreich gespeichert",
		}, http.StatusOK)
	}
}

func handleTriggerSyncNow(w http.ResponseWriter, r *http.Request) {
	user := getUserFromCtx(r)
	file, err := backup.Engine.ExecuteBackup(user.UserId, false)
	if err != nil {
		jsonResponse(w, map[string]interface{}{
			"status":  "error",
			"message": "Synchronisation fehlgeschlagen: " + err.Error(),
		}, http.StatusOK)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"status":  "ok",
		"message": "Synchronisation erfolgreich durchgeführt",
		"file":    file,
	}, http.StatusOK)
}

func dbDir() string {
	return filepath.Dir(db.GetDBPath())
}

// Aliases
func handleListAliases(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		rows, err := db.Query("SELECT id, alias_email, service_name, created_at FROM email_aliases WHERE user_id = ? ORDER BY created_at DESC", user.UserId)
		if err != nil {
			httpError(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		res := make([]map[string]string, 0)
		for rows.Next() {
			var id, email, service, createdAt string
			if err := rows.Scan(&id, &email, &service, &createdAt); err == nil {
				res = append(res, map[string]string{
					"id":           id,
					"alias_email":  email,
					"service_name": service,
					"created_at":   createdAt,
				})
			}
		}
		jsonResponse(w, res, http.StatusOK)
	}
}

func handleCreateAlias(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.EmailAliasCreate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		tok := crypto.GenerateSalt(4)[:8]
		slug := strings.ToLower(strings.TrimSpace(req.ServiceName))
		slug = regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(slug, "")
		if slug == "" {
			slug = "service"
		}
		aliasEmail := fmt.Sprintf("%s.%s@sentinelbit.local", slug, tok)

		aliasId := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)
		_, err := db.Exec(`
			INSERT INTO email_aliases (id, user_id, alias_email, service_name, created_at)
			VALUES (?, ?, ?, ?, ?)
		`, aliasId, user.UserId, aliasEmail, req.ServiceName, now)

		if err != nil {
			httpError(w, "Fehler beim Anlegen des E-Mail-Alias", http.StatusInternalServerError)
			return
		}

		jsonResponse(w, map[string]string{
			"status":       "ok",
			"id":           aliasId,
			"alias_email":  aliasEmail,
			"service_name": req.ServiceName,
		}, http.StatusOK)
	}
}

func handleDeleteAlias(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		aliasId := chi.URLParam(r, "aliasId")
		_, _ = db.Exec("DELETE FROM email_aliases WHERE id = ? AND user_id = ?", aliasId, user.UserId)
		jsonResponse(w, map[string]string{"status": "ok", "message": "E-Mail-Alias gelöscht"}, http.StatusOK)
	}
}

// Item Sharing
func handleRegisterSharePublicKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.SharingPublicKeyRegister
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		_, err := db.Exec(`
			INSERT INTO user_sharing_keys (user_id, public_key_pem, created_at)
			VALUES (?, ?, ?)
			ON CONFLICT(user_id) DO UPDATE SET public_key_pem = excluded.public_key_pem
		`, user.UserId, req.PublicKeyPem, now)

		if err != nil {
			httpError(w, "Fehler beim Speichern des Sharing-Schlüssels", http.StatusInternalServerError)
			return
		}

		jsonResponse(w, map[string]string{"status": "ok", "message": "Öffentlicher Sharing-Schlüssel gespeichert"}, http.StatusOK)
	}
}

func handleGetRecipientPublicKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetUsername := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "targetUsername")))

		var targetUserId string
		err := db.QueryRow("SELECT id FROM users WHERE username = ?", targetUsername).Scan(&targetUserId)
		if err != nil {
			httpError(w, "Empfänger-Benutzername existiert nicht", http.StatusNotFound)
			return
		}

		var pubKeyPem string
		err = db.QueryRow("SELECT public_key_pem FROM user_sharing_keys WHERE user_id = ?", targetUserId).Scan(&pubKeyPem)
		if err != nil {
			httpError(w, "Empfänger hat noch keinen Sharing-Schlüssel aktiviert", http.StatusBadRequest)
			return
		}

		jsonResponse(w, map[string]string{
			"username":       targetUsername,
			"public_key_pem": pubKeyPem,
		}, http.StatusOK)
	}
}

func handleSendSharedItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var req models.ShareItemSendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		sharedId := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)
		targetUsername := strings.ToLower(strings.TrimSpace(req.RecipientUsername))

		_, err := db.Exec(`
			INSERT INTO shared_items (id, sender_id, recipient_username, type, title, encrypted_payload, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, sharedId, user.UserId, targetUsername, req.Type, req.Title, req.EncryptedPayload, now)

		if err != nil {
			httpError(w, "Fehler beim Teilen des Eintrags", http.StatusInternalServerError)
			return
		}

		jsonResponse(w, map[string]string{
			"status":  "ok",
			"message": fmt.Sprintf("Eintrag sicher für '%s' freigegeben!", targetUsername),
		}, http.StatusOK)
	}
}

func handleListSharedInbox(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		rows, err := db.Query(`
			SELECT s.id, s.type, s.title, s.encrypted_payload, s.created_at, u.username as sender_username
			FROM shared_items s
			JOIN users u ON s.sender_id = u.id
			WHERE s.recipient_username = ?
			ORDER BY s.created_at DESC
		`, user.Username)
		if err != nil {
			httpError(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		res := make([]map[string]string, 0)
		for rows.Next() {
			var id, itype, title, payload, createdAt, sender string
			if err := rows.Scan(&id, &itype, &title, &payload, &createdAt, &sender); err == nil {
				res = append(res, map[string]string{
					"id":                id,
					"type":              itype,
					"title":             title,
					"encrypted_payload": payload,
					"created_at":        createdAt,
					"sender_username":   sender,
				})
			}
		}
		jsonResponse(w, res, http.StatusOK)
	}
}

func handleDeleteSharedInboxItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")
		_, _ = db.Exec("DELETE FROM shared_items WHERE id = ? AND recipient_username = ?", itemId, user.Username)
		jsonResponse(w, map[string]string{"status": "ok", "message": "Geteilter Eintrag entfernt"}, http.StatusOK)
	}
}

func handleEmergencyKit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromCtx(r)
		var encSalt, authSalt, createdAt string
		var totpEnabled int
		var recoveryCodes sql.NullString

		err := db.QueryRow(`
			SELECT enc_salt, auth_salt, totp_enabled, recovery_codes, created_at
			FROM users WHERE id = ?
		`, user.UserId).Scan(&encSalt, &authSalt, &totpEnabled, &recoveryCodes, &createdAt)

		if err != nil {
			httpError(w, "Benutzerdaten nicht gefunden", http.StatusNotFound)
			return
		}

		var recList []string
		if recoveryCodes.Valid && recoveryCodes.String != "" {
			_ = json.Unmarshal([]byte(recoveryCodes.String), &recList)
		}

		jsonResponse(w, map[string]interface{}{
			"username":       user.Username,
			"enc_salt":       encSalt,
			"auth_salt":      authSalt,
			"totp_enabled":   totpEnabled == 1,
			"recovery_codes": recList,
			"created_at":     createdAt,
			"generated_at":   time.Now().UTC().Format(time.RFC3339),
		}, http.StatusOK)
	}
}

