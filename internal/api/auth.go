package api

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinelbit/internal/config"
	"sentinelbit/internal/crypto"
	"sentinelbit/internal/models"
	"sentinelbit/internal/security"
)

var hex64Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func HandleRegister(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg != nil && cfg.DisableRegistration {
			HTTPError(w, "Registrierung neuer Benutzer ist auf diesem Server deaktiviert", http.StatusForbidden)
			return
		}

		var req models.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		username, err := security.ValidateUsername(req.Username)
		if err != nil {
			HTTPError(w, err.Error(), http.StatusBadRequest)
			return
		}
		username = strings.ToLower(username)

		if !hex64Re.MatchString(req.AuthHash) {
			HTTPError(w, "Ungültiges Auth-Key-Format", http.StatusBadRequest)
			return
		}

		if req.AuthSalt == "" || strings.Contains(req.AuthSalt, ":") || len(req.AuthSalt) > 128 ||
			req.EncSalt == "" || len(req.EncSalt) > 128 {
			HTTPError(w, "Ungültiges Salt-Format", http.StatusBadRequest)
			return
		}

		var existingID string
		err = db.QueryRow("SELECT id FROM users WHERE LOWER(username) = ?", username).Scan(&existingID)
		if err == nil {
			HTTPError(w, "Benutzername existiert bereits", http.StatusBadRequest)
			return
		}

		userId := uuid.New().String()
		serverSalt := crypto.GenerateSalt(32)
		finalAuthHash, err := crypto.HashAuthKey(req.AuthHash, serverSalt, 100_000)
		if err != nil {
			HTTPError(w, "Kryptofehler beim Hashen", http.StatusInternalServerError)
			return
		}

		combinedAuthSalt := fmt.Sprintf("%s:%s", req.AuthSalt, serverSalt)
		now := time.Now().UTC().Format(time.RFC3339)

		_, err = db.Exec(`
			INSERT INTO users (id, username, auth_salt, auth_hash, enc_salt, totp_secret, totp_enabled, created_at)
			VALUES (?, ?, ?, ?, ?, NULL, 0, ?)
		`, userId, username, combinedAuthSalt, finalAuthHash, req.EncSalt, now)

		if err != nil {
			HTTPError(w, "Fehler beim Speichern des Kontos", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, map[string]string{
			"status":  "ok",
			"message": "Konto erfolgreich erstellt",
		}, http.StatusOK)
	}
}

func HandleLoginInit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.LoginInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
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
			dAuthSalt, dEncSalt := crypto.GenerateDummySalts(ServerSecret, username)
			JSONResponse(w, models.LoginInitResponse{
				AuthSalt:     dAuthSalt,
				EncSalt:      dEncSalt,
				TotpRequired: false,
			}, http.StatusOK)
			return
		}

		JSONResponse(w, models.LoginInitResponse{
			AuthSalt:     authSalt,
			EncSalt:      encSalt,
			TotpRequired: totpEnabled == 1,
		}, http.StatusOK)
	}
}

func HandleLoginVerify(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.LoginVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		ip := security.GetIP(r)
		username := strings.ToLower(strings.TrimSpace(req.Username))
		limiterKey := fmt.Sprintf("%s:%s", ip, username)

		if allowed, waitDur := LoginLimiter.Check(limiterKey); !allowed {
			HTTPError(w, fmt.Sprintf("Zu viele Fehlversuche. Bitte warte %d Sekunden.", int(waitDur.Seconds())), http.StatusTooManyRequests)
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
			LoginLimiter.RecordFailure(limiterKey)
			HTTPError(w, "Ungültige Anmeldedaten", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authSalt, ":")
		if len(parts) < 2 {
			HTTPError(w, "Interner Fehler in Salt-Struktur", http.StatusInternalServerError)
			return
		}
		serverSalt := parts[1]

		if !crypto.VerifyAuthKey(req.ClientAuthKey, serverSalt, storedAuthHash) {
			LoginLimiter.RecordFailure(limiterKey)
			HTTPError(w, "Ungültige Anmeldedaten", http.StatusUnauthorized)
			return
		}

		// Check 2FA if enabled
		if totpEnabled == 1 {
			verified := false

			if req.TotpCode != "" && totpSecret.Valid {
				if crypto.VerifyTotpCode(totpSecret.String, req.TotpCode) {
					if ReplayGuard.CheckAndRecord(userId, req.TotpCode) {
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
				LoginLimiter.RecordFailure(limiterKey)
				HTTPError(w, "Ungültiger Zwei-Faktor- oder Wiederherstellungscode", http.StatusUnauthorized)
				return
			}
		}

		LoginLimiter.RecordSuccess(limiterKey)

		// Create session with 12h validity
		token := uuid.New().String()
		expiresAt := time.Now().Add(12 * time.Hour)
		nowStr := time.Now().UTC().Format(time.RFC3339)
		expiresAtStr := expiresAt.UTC().Format(time.RFC3339)

		SessionMu.Lock()
		Sessions[token] = models.SessionData{
			UserId:    userId,
			Username:  username,
			ExpiresAt: expiresAt,
		}
		SessionMu.Unlock()

		// Persist session to database for restart resilience
		_, _ = db.Exec(`
			INSERT INTO sessions (token_hash, user_id, username, enc_salt, totp_enabled, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(token_hash) DO UPDATE SET expires_at = excluded.expires_at
		`, token, userId, username, encSalt, totpEnabled, expiresAtStr, nowStr)

		JSONResponse(w, models.LoginResponse{
			Status:      "ok",
			Token:       token,
			UserId:      userId,
			Username:    username,
			EncSalt:     encSalt,
			TotpEnabled: totpEnabled == 1,
		}, http.StatusOK)
	}
}

func HandleLogout(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			SessionMu.Lock()
			delete(Sessions, token)
			SessionMu.Unlock()

			if db != nil {
				_, _ = db.Exec("DELETE FROM sessions WHERE token_hash = ?", token)
			}
		}
		JSONResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
	}
}

func HandleAuthMe(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromCtx(r)
	JSONResponse(w, map[string]interface{}{
		"status":   "authenticated",
		"user_id":  user.UserId,
		"username": user.Username,
	}, http.StatusOK)
}

func Handle2faSetup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)

		var enabled int
		_ = db.QueryRow("SELECT totp_enabled FROM users WHERE id = ?", user.UserId).Scan(&enabled)
		if enabled == 1 {
			HTTPError(w, "2FA ist bereits aktiv. Bitte zuerst deaktivieren.", http.StatusConflict)
			return
		}

		secret, err := crypto.GenerateTotpSecret()
		if err != nil {
			HTTPError(w, "Fehler beim Generieren des 2FA-Schlüssels", http.StatusInternalServerError)
			return
		}

		uri := crypto.GetTotpURI(secret, user.Username, "sentinelbit")
		qrB64, err := crypto.GenerateTotpQRBase64(uri)
		if err != nil {
			HTTPError(w, "Fehler beim Erstellen des QR-Codes", http.StatusInternalServerError)
			return
		}

		_, _ = db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", secret, user.UserId)

		JSONResponse(w, models.TotpSetupResponse{
			Secret:       secret,
			ProvisionURI: uri,
			QRCodeBase64: qrB64,
		}, http.StatusOK)
	}
}

func Handle2faVerify(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.TotpVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		limiterKey := fmt.Sprintf("totp:%s", user.UserId)
		if allowed, waitDur := TotpLimiter.Check(limiterKey); !allowed {
			HTTPError(w, fmt.Sprintf("Zu viele Versuche. Warte %d s", int(waitDur.Seconds())), http.StatusTooManyRequests)
			return
		}

		var secret sql.NullString
		var enabled int
		err := db.QueryRow("SELECT totp_secret, totp_enabled FROM users WHERE id = ?", user.UserId).Scan(&secret, &enabled)
		if err != nil || !secret.Valid || secret.String == "" {
			HTTPError(w, "2FA-Einrichtung wurde nicht initialisiert", http.StatusBadRequest)
			return
		}

		if enabled == 1 {
			HTTPError(w, "2FA ist bereits aktiv", http.StatusConflict)
			return
		}

		if !crypto.VerifyTotpCode(secret.String, req.Code) || !ReplayGuard.CheckAndRecord(user.UserId, req.Code) {
			TotpLimiter.RecordFailure(limiterKey)
			HTTPError(w, "Ungültiger 2FA-Code. Bitte Uhrzeit prüfen.", http.StatusBadRequest)
			return
		}

		TotpLimiter.RecordSuccess(limiterKey)
		recoveryCodes := crypto.GenerateRecoveryCodes(5)
		recJson, _ := json.Marshal(recoveryCodes)

		_, _ = db.Exec("UPDATE users SET totp_enabled = 1, recovery_codes = ? WHERE id = ?", string(recJson), user.UserId)

		JSONResponse(w, map[string]interface{}{
			"status":         "ok",
			"message":        "2FA erfolgreich aktiviert!",
			"recovery_codes": recoveryCodes,
		}, http.StatusOK)
	}
}

func Handle2faDisable(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.TotpDisableRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		var secret, recoveryCodes sql.NullString
		err := db.QueryRow("SELECT totp_secret, recovery_codes FROM users WHERE id = ?", user.UserId).Scan(&secret, &recoveryCodes)
		if err != nil {
			HTTPError(w, "Benutzer nicht gefunden", http.StatusNotFound)
			return
		}

		limiterKey := fmt.Sprintf("totp:%s", user.UserId)
		if allowed, waitDur := TotpLimiter.Check(limiterKey); !allowed {
			HTTPError(w, fmt.Sprintf("Zu viele Versuche. Warte %d s", int(waitDur.Seconds())), http.StatusTooManyRequests)
			return
		}

		isValid := false
		code := strings.TrimSpace(req.Code)
		if secret.Valid && crypto.VerifyTotpCode(secret.String, code) && ReplayGuard.CheckAndRecord(user.UserId, code) {
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
			TotpLimiter.RecordFailure(limiterKey)
			HTTPError(w, "Ungültiger Bestätigungscode", http.StatusBadRequest)
			return
		}

		TotpLimiter.RecordSuccess(limiterKey)
		_, _ = db.Exec("UPDATE users SET totp_enabled = 0, totp_secret = NULL, recovery_codes = NULL WHERE id = ?", user.UserId)

		JSONResponse(w, map[string]string{"status": "ok", "message": "2FA wurde deaktiviert"}, http.StatusOK)
	}
}

func HandleListWebAuthnKeys(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query("SELECT id, credential_id, device_name, created_at FROM webauthn_unlock_keys WHERE user_id = ?", user.UserId)
		if err != nil {
			HTTPError(w, "Datenbankfehler", http.StatusInternalServerError)
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
		JSONResponse(w, res, http.StatusOK)
	}
}

func HandleRegisterWebAuthnKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.WebAuthnKeyRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		keyId := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)
		_, err := db.Exec(`
			INSERT INTO webauthn_unlock_keys (id, user_id, credential_id, public_key, device_name, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, keyId, user.UserId, req.CredentialId, req.PublicKey, req.DeviceName, now)

		if err != nil {
			HTTPError(w, "Fehler beim Registrieren", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, map[string]string{
			"status":  "ok",
			"id":      keyId,
			"message": "Biometrisches Gerät erfolgreich registriert",
		}, http.StatusOK)
	}
}

func HandleDeleteWebAuthnKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		keyId := chi.URLParam(r, "keyId")
		_, _ = db.Exec("DELETE FROM webauthn_unlock_keys WHERE id = ? AND user_id = ?", keyId, user.UserId)
		JSONResponse(w, map[string]string{"status": "ok", "message": "Geräteschlüssel entfernt"}, http.StatusOK)
	}
}

func HandleEmergencyKit(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var encSalt, authSalt, createdAt string
		var totpEnabled int
		var recoveryCodes sql.NullString

		err := db.QueryRow(`
			SELECT enc_salt, auth_salt, totp_enabled, recovery_codes, created_at
			FROM users WHERE id = ?
		`, user.UserId).Scan(&encSalt, &authSalt, &totpEnabled, &recoveryCodes, &createdAt)

		if err != nil {
			HTTPError(w, "Benutzerdaten nicht gefunden", http.StatusNotFound)
			return
		}

		var recList []string
		if recoveryCodes.Valid && recoveryCodes.String != "" {
			_ = json.Unmarshal([]byte(recoveryCodes.String), &recList)
		}

		JSONResponse(w, map[string]interface{}{
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
