package bitwarden

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"sentinelbit/internal/config"
)

// JSON helper
func jsonResp(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

// -------------------------------------------------------------
// CONFIG & PRELOGIN
// -------------------------------------------------------------

func HandleConfig(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, ConfigResponse{
			Version: "2026.10.0",
			GitHash: "sentinelbit",
			Server: map[string]string{
				"name": "SentinelBit",
			},
			Environment: map[string]string{},
			FeatureStates: map[string]bool{
				"twoFactor": true,
			},
			Object: "config",
		}, http.StatusOK)
	}
}

func HandlePrelogin(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PreloginRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		email := strings.ToLower(strings.TrimSpace(req.Email))
		kdf := 0
		kdfIterations := 600000

		if email != "" {
			var dbKdf, dbIter int
			err := database.QueryRow("SELECT bw_kdf, bw_kdf_iterations FROM users WHERE username = ?", email).Scan(&dbKdf, &dbIter)
			if err == nil {
				kdf = dbKdf
				if dbIter > 0 {
					kdfIterations = dbIter
				}
			}
		}

		jsonResp(w, PreloginResponse{
			Kdf:           kdf,
			KdfIterations: kdfIterations,
		}, http.StatusOK)
	}
}

// -------------------------------------------------------------
// ACCOUNTS & IDENTITY TOKEN
// -------------------------------------------------------------

func HandleRegister(database *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg != nil && cfg.DisableRegistration {
			http.Error(w, `{"message":"Registration is disabled on this server"}`, http.StatusForbidden)
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		email := strings.ToLower(strings.TrimSpace(req.Email))
		if email == "" || req.MasterPasswordHash == "" || req.Key == "" {
			http.Error(w, `{"message":"Email, masterPasswordHash, and key are required"}`, http.StatusBadRequest)
			return
		}

		kdf := req.Kdf
		iter := req.KdfIterations
		if iter < 100000 {
			iter = 600000
		}

		salt := GenerateRandomSalt()
		passwordHash := HashMasterPassword(req.MasterPasswordHash, salt)
		securityStamp := uuid.NewString()
		now := time.Now().UTC().Format(time.RFC3339)

		var pubKey, privKey string
		if req.Keys != nil {
			pubKey = req.Keys.PublicKey
			privKey = req.Keys.EncryptedPrivateKey
		}

		// Check if user already exists
		var existingID string
		err := database.QueryRow("SELECT id FROM users WHERE username = ?", email).Scan(&existingID)
		if err == nil {
			// Update existing user with Bitwarden keys
			_, err = database.Exec(`
				UPDATE users SET
					bw_key = ?,
					bw_private_key = ?,
					bw_public_key = ?,
					bw_password_hash = ?,
					bw_password_salt = ?,
					bw_kdf = ?,
					bw_kdf_iterations = ?,
					bw_security_stamp = ?,
					updated_at = ?
				WHERE id = ?
			`, req.Key, privKey, pubKey, passwordHash, salt, kdf, iter, securityStamp, now, existingID)

			if err != nil {
				http.Error(w, `{"message":"Database error while updating account"}`, http.StatusInternalServerError)
				return
			}
			jsonResp(w, map[string]interface{}{}, http.StatusOK)
			return
		}

		// Insert new user
		newID := uuid.NewString()
		_, err = database.Exec(`
			INSERT INTO users (
				id, username, auth_salt, auth_hash, enc_salt,
				bw_key, bw_private_key, bw_public_key, bw_password_hash, bw_password_salt,
				bw_kdf, bw_kdf_iterations, bw_security_stamp, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, newID, email, salt, "", salt, req.Key, privKey, pubKey, passwordHash, salt, kdf, iter, securityStamp, now, now)

		if err != nil {
			http.Error(w, `{"message":"Database error creating account: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		jsonResp(w, map[string]interface{}{}, http.StatusOK)
	}
}

func HandleToken(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		grantType := r.FormValue("grant_type")
		if grantType != "password" && grantType != "refresh_token" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "unsupported_grant_type",
				"error_description": "Grant type must be password or refresh_token",
			})
			return
		}

		username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
		password := r.FormValue("password")

		var userID, uName, bwKey, bwPrivKey, bwHash, bwSalt, totpSecret sql.NullString
		var totpEnabled int

		err := database.QueryRow(`
			SELECT id, username, bw_key, bw_private_key, bw_password_hash, bw_password_salt, totp_enabled, totp_secret
			FROM users WHERE username = ?
		`, username).Scan(&userID, &uName, &bwKey, &bwPrivKey, &bwHash, &bwSalt, &totpEnabled, &totpSecret)

		if err != nil || !bwHash.Valid || bwHash.String == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "Invalid username or password.",
			})
			return
		}

		// Verify password hash
		expectedHash := HashMasterPassword(password, bwSalt.String)
		if expectedHash != bwHash.String {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "Invalid username or password.",
			})
			return
		}

		// 2FA TOTP Verification
		if totpEnabled == 1 && totpSecret.Valid && totpSecret.String != "" {
			token2fa := strings.TrimSpace(r.FormValue("twoFactorToken"))
			if token2fa == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":               "invalid_grant",
					"error_description":   "Two factor required.",
					"TwoFactorProviders":  []int{0},
					"TwoFactorProviders2": map[string]interface{}{"0": nil},
				})
				return
			}

			if !totp.Validate(token2fa, totpSecret.String) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":               "invalid_grant",
					"error_description":   "Invalid two factor token.",
					"TwoFactorProviders":  []int{0},
					"TwoFactorProviders2": map[string]interface{}{"0": nil},
				})
				return
			}
		}

		// Session creation
		token := uuid.NewString()
		expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		nowISO := time.Now().UTC().Format(time.RFC3339)

		_, _ = database.Exec(`
			INSERT INTO sessions (token_hash, user_id, username, enc_salt, totp_enabled, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, token, userID.String, uName.String, "bw", totpEnabled, expiresAt, nowISO)

		// Record Device if provided
		deviceID := strings.TrimSpace(r.FormValue("deviceIdentifier"))
		if deviceID != "" {
			devName := r.FormValue("deviceName")
			devType, _ := strconv.Atoi(r.FormValue("deviceType"))
			_, _ = database.Exec(`
				INSERT INTO bw_devices (id, user_id, device_identifier, device_name, device_type, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)
			`, uuid.NewString(), userID.String, deviceID, devName, devType, nowISO, nowISO)
		}

		jsonResp(w, TokenResponse{
			AccessToken:         token,
			ExpiresIn:           2592000, // 30 days
			TokenType:           "Bearer",
			RefreshToken:        token,
			Key:                 bwKey.String,
			PrivateKey:          bwPrivKey.String,
			TwoFactorToken:      nil,
			ResetMasterPassword: false,
		}, http.StatusOK)
	}
}

func HandleProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		jsonResp(w, ProfileResponse{
			ID:                 user.UserID,
			Name:               user.Username,
			Email:              user.Username,
			EmailVerified:      true,
			Premium:            true,
			MasterPasswordHint: nil,
			Culture:            "de-DE",
			TwoFactorEnabled:   user.TotpEnabled,
			Key:                user.Key,
			PrivateKey:         user.PrivateKey,
			SecurityStamp:      user.SecurityStamp,
			Organizations:      []interface{}{},
			Object:             "profile",
		}, http.StatusOK)
	}
}

// -------------------------------------------------------------
// SYNC ENDPOINT
// -------------------------------------------------------------

func HandleSync(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)

		// Folders
		folders := make([]FolderModel, 0)
		fRows, err := database.Query("SELECT id, name, revision_date FROM bw_folders WHERE user_id = ?", user.UserID)
		if err == nil {
			defer fRows.Close()
			for fRows.Next() {
				var f FolderModel
				if err := fRows.Scan(&f.ID, &f.Name, &f.RevisionDate); err == nil {
					f.Object = "folder"
					folders = append(folders, f)
				}
			}
		}

		// Ciphers
		ciphers := make([]CipherModel, 0)
		cRows, err := database.Query(`
			SELECT id, folder_id, type, name, notes, favorite, login_data, secure_note_data, card_data,
			       identity_data, fields, reprompt, revision_date, deleted_date
			FROM bw_ciphers
			WHERE user_id = ?
		`, user.UserID)

		if err == nil {
			defer cRows.Close()
			for cRows.Next() {
				var c CipherModel
				var folderID, notes, loginData, secData, cardData, idData, fieldsData, deletedDate sql.NullString
				var fav int

				if err := cRows.Scan(
					&c.ID, &folderID, &c.Type, &c.Name, &notes, &fav,
					&loginData, &secData, &cardData, &idData, &fieldsData,
					&c.Reprompt, &c.RevisionDate, &deletedDate,
				); err == nil {
					c.Object = "cipher"
					c.Favorite = fav == 1
					if folderID.Valid && folderID.String != "" {
						c.FolderID = &folderID.String
					}
					if notes.Valid && notes.String != "" {
						c.Notes = &notes.String
					}
					if deletedDate.Valid && deletedDate.String != "" {
						c.DeletedDate = &deletedDate.String
					}

					// Login data
					if loginData.Valid && loginData.String != "" {
						var login CipherLogin
						if err := json.Unmarshal([]byte(loginData.String), &login); err == nil {
							c.Login = &login
						}
					}
					// Fields
					c.Fields = make([]CipherField, 0)
					if fieldsData.Valid && fieldsData.String != "" {
						_ = json.Unmarshal([]byte(fieldsData.String), &c.Fields)
					}
					// SecureNote
					if secData.Valid && secData.String != "" {
						_ = json.Unmarshal([]byte(secData.String), &c.SecureNote)
					}
					// Card
					if cardData.Valid && cardData.String != "" {
						_ = json.Unmarshal([]byte(cardData.String), &c.Card)
					}
					// Identity
					if idData.Valid && idData.String != "" {
						_ = json.Unmarshal([]byte(idData.String), &c.Identity)
					}

					ciphers = append(ciphers, c)
				}
			}
		}

		profile := ProfileResponse{
			ID:                 user.UserID,
			Name:               user.Username,
			Email:              user.Username,
			EmailVerified:      true,
			Premium:            true,
			MasterPasswordHint: nil,
			Culture:            "de-DE",
			TwoFactorEnabled:   user.TotpEnabled,
			Key:                user.Key,
			PrivateKey:         user.PrivateKey,
			SecurityStamp:      user.SecurityStamp,
			Organizations:      []interface{}{},
			Object:             "profile",
		}

		jsonResp(w, SyncResponse{
			Profile:     profile,
			Folders:     folders,
			Collections: []interface{}{},
			Ciphers:     ciphers,
			Domains: SyncDomains{
				EquivalentDomains:       nil,
				GlobalEquivalentDomains: []interface{}{},
				Object:                  "domains",
			},
			Object: "sync",
		}, http.StatusOK)
	}
}

// -------------------------------------------------------------
// CIPHERS CRUD
// -------------------------------------------------------------

func HandleGetCiphers(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		ciphers := make([]CipherModel, 0)
		rows, err := database.Query(`
			SELECT id, folder_id, type, name, notes, favorite, login_data, secure_note_data, card_data,
			       identity_data, fields, reprompt, revision_date, deleted_date
			FROM bw_ciphers WHERE user_id = ? AND (deleted_date IS NULL OR deleted_date = '')
		`, user.UserID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var c CipherModel
				var folderID, notes, loginData, secData, cardData, idData, fieldsData, deletedDate sql.NullString
				var fav int
				if err := rows.Scan(&c.ID, &folderID, &c.Type, &c.Name, &notes, &fav,
					&loginData, &secData, &cardData, &idData, &fieldsData,
					&c.Reprompt, &c.RevisionDate, &deletedDate); err == nil {
					c.Object = "cipher"
					c.Favorite = fav == 1
					if folderID.Valid && folderID.String != "" {
						c.FolderID = &folderID.String
					}
					if notes.Valid {
						c.Notes = &notes.String
					}
					if loginData.Valid && loginData.String != "" {
						var login CipherLogin
						_ = json.Unmarshal([]byte(loginData.String), &login)
						c.Login = &login
					}
					c.Fields = make([]CipherField, 0)
					if fieldsData.Valid && fieldsData.String != "" {
						_ = json.Unmarshal([]byte(fieldsData.String), &c.Fields)
					}
					ciphers = append(ciphers, c)
				}
			}
		}
		jsonResp(w, map[string]interface{}{"data": ciphers, "object": "list"}, http.StatusOK)
	}
}

func HandleCreateCipher(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		var c CipherModel
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, `{"message":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		c.ID = uuid.NewString()
		c.RevisionDate = time.Now().UTC().Format(time.RFC3339)
		c.Object = "cipher"

		favInt := 0
		if c.Favorite {
			favInt = 1
		}

		var folderID string
		if c.FolderID != nil {
			folderID = *c.FolderID
		}
		var notes string
		if c.Notes != nil {
			notes = *c.Notes
		}

		loginBytes, _ := json.Marshal(c.Login)
		secBytes, _ := json.Marshal(c.SecureNote)
		cardBytes, _ := json.Marshal(c.Card)
		idBytes, _ := json.Marshal(c.Identity)
		fieldsBytes, _ := json.Marshal(c.Fields)

		_, err := database.Exec(`
			INSERT INTO bw_ciphers (
				id, user_id, folder_id, type, name, notes, favorite,
				login_data, secure_note_data, card_data, identity_data, fields,
				reprompt, revision_date
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, c.ID, user.UserID, folderID, c.Type, c.Name, notes, favInt,
			string(loginBytes), string(secBytes), string(cardBytes), string(idBytes), string(fieldsBytes),
			c.Reprompt, c.RevisionDate)

		if err != nil {
			http.Error(w, `{"message":"Error creating cipher"}`, http.StatusInternalServerError)
			return
		}

		jsonResp(w, c, http.StatusOK)
	}
}

func HandleUpdateCipher(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		cipherID := chi.URLParam(r, "id")

		var c CipherModel
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, `{"message":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}

		c.ID = cipherID
		c.RevisionDate = time.Now().UTC().Format(time.RFC3339)
		c.Object = "cipher"

		favInt := 0
		if c.Favorite {
			favInt = 1
		}

		var folderID string
		if c.FolderID != nil {
			folderID = *c.FolderID
		}
		var notes string
		if c.Notes != nil {
			notes = *c.Notes
		}

		loginBytes, _ := json.Marshal(c.Login)
		secBytes, _ := json.Marshal(c.SecureNote)
		cardBytes, _ := json.Marshal(c.Card)
		idBytes, _ := json.Marshal(c.Identity)
		fieldsBytes, _ := json.Marshal(c.Fields)

		_, err := database.Exec(`
			UPDATE bw_ciphers SET
				folder_id = ?, type = ?, name = ?, notes = ?, favorite = ?,
				login_data = ?, secure_note_data = ?, card_data = ?, identity_data = ?, fields = ?,
				reprompt = ?, revision_date = ?
			WHERE id = ? AND user_id = ?
		`, folderID, c.Type, c.Name, notes, favInt,
			string(loginBytes), string(secBytes), string(cardBytes), string(idBytes), string(fieldsBytes),
			c.Reprompt, c.RevisionDate, cipherID, user.UserID)

		if err != nil {
			http.Error(w, `{"message":"Error updating cipher"}`, http.StatusInternalServerError)
			return
		}

		jsonResp(w, c, http.StatusOK)
	}
}

func HandleDeleteCipher(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		cipherID := chi.URLParam(r, "id")
		nowISO := time.Now().UTC().Format(time.RFC3339)

		// Soft delete (trash)
		_, _ = database.Exec("UPDATE bw_ciphers SET deleted_date = ?, revision_date = ? WHERE id = ? AND user_id = ?", nowISO, nowISO, cipherID, user.UserID)
		jsonResp(w, map[string]interface{}{}, http.StatusOK)
	}
}

func HandleHardDeleteCipher(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		cipherID := chi.URLParam(r, "id")
		_, _ = database.Exec("DELETE FROM bw_ciphers WHERE id = ? AND user_id = ?", cipherID, user.UserID)
		jsonResp(w, map[string]interface{}{}, http.StatusOK)
	}
}

func HandleRestoreCipher(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		cipherID := chi.URLParam(r, "id")
		nowISO := time.Now().UTC().Format(time.RFC3339)

		_, _ = database.Exec("UPDATE bw_ciphers SET deleted_date = NULL, revision_date = ? WHERE id = ? AND user_id = ?", nowISO, cipherID, user.UserID)
		jsonResp(w, map[string]interface{}{"id": cipherID, "object": "cipher"}, http.StatusOK)
	}
}

// -------------------------------------------------------------
// FOLDERS CRUD
// -------------------------------------------------------------

func HandleGetFolders(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		folders := make([]FolderModel, 0)
		rows, err := database.Query("SELECT id, name, revision_date FROM bw_folders WHERE user_id = ?", user.UserID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var f FolderModel
				if err := rows.Scan(&f.ID, &f.Name, &f.RevisionDate); err == nil {
					f.Object = "folder"
					folders = append(folders, f)
				}
			}
		}
		jsonResp(w, map[string]interface{}{"data": folders, "object": "list"}, http.StatusOK)
	}
}

func HandleCreateFolder(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		var req FolderRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		folder := FolderModel{
			ID:           uuid.NewString(),
			Name:         req.Name,
			RevisionDate: time.Now().UTC().Format(time.RFC3339),
			Object:       "folder",
		}

		_, err := database.Exec("INSERT INTO bw_folders (id, user_id, name, revision_date) VALUES (?, ?, ?, ?)",
			folder.ID, user.UserID, folder.Name, folder.RevisionDate)

		if err != nil {
			http.Error(w, `{"message":"Error creating folder"}`, http.StatusInternalServerError)
			return
		}
		jsonResp(w, folder, http.StatusOK)
	}
}

func HandleUpdateFolder(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		folderID := chi.URLParam(r, "id")
		var req FolderRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		nowISO := time.Now().UTC().Format(time.RFC3339)
		_, _ = database.Exec("UPDATE bw_folders SET name = ?, revision_date = ? WHERE id = ? AND user_id = ?", req.Name, nowISO, folderID, user.UserID)

		jsonResp(w, FolderModel{
			ID:           folderID,
			Name:         req.Name,
			RevisionDate: nowISO,
			Object:       "folder",
		}, http.StatusOK)
	}
}

func HandleDeleteFolder(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		folderID := chi.URLParam(r, "id")
		_, _ = database.Exec("DELETE FROM bw_folders WHERE id = ? AND user_id = ?", folderID, user.UserID)
		jsonResp(w, map[string]interface{}{}, http.StatusOK)
	}
}

// -------------------------------------------------------------
// TWO-FACTOR & EXTENSION COMPATIBILITY
// -------------------------------------------------------------

func HandleTwoFactorProviders() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetBwUser(r)
		providers := []map[string]interface{}{
			{
				"enabled": user.TotpEnabled,
				"type":    0,
				"object":  "twoFactorProvider",
			},
		}
		jsonResp(w, map[string]interface{}{"data": providers, "object": "list"}, http.StatusOK)
	}
}
