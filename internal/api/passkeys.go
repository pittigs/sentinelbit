package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinelbit/internal/backup"
	"sentinelbit/internal/crypto"
	"sentinelbit/internal/models"
)

func HandlePasskeyGenerate(w http.ResponseWriter, r *http.Request) {
	var req models.PasskeyGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
		return
	}

	keypair, err := crypto.GeneratePasskeyKeypair()
	if err != nil {
		HTTPError(w, "Fehler beim Generieren des Passkey-Schlüsselpaars", http.StatusInternalServerError)
		return
	}

	userHandle := uuid.New().String()

	JSONResponse(w, map[string]interface{}{
		"rp_id":           req.RpId,
		"rp_name":         req.RpName,
		"username":        req.Username,
		"user_handle":     userHandle,
		"credential_id":   keypair.CredentialId,
		"private_key_pem": keypair.PrivateKeyPem,
		"public_key_pem":  keypair.PublicKeyPem,
		"public_key_cose": keypair.PublicKeyCose,
		"x":               keypair.X,
		"y":               keypair.Y,
	}, http.StatusOK)
}

func HandleListPasskeys(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, vault_item_id, rp_id, rp_name, username, user_handle, credential_id,
			       encrypted_private_key, public_key_cose, public_key_pem, sign_count, transports, created_at, last_used_at
			FROM passkeys WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '') ORDER BY created_at DESC
		`, user.UserId)
		if err != nil {
			HTTPError(w, "Datenbankfehler", http.StatusInternalServerError)
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
		JSONResponse(w, result, http.StatusOK)
	}
}

func HandleSavePasskey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.PasskeySaveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
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
			HTTPError(w, "Fehler beim Speichern des Passkeys", http.StatusInternalServerError)
			return
		}

		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)

		JSONResponse(w, map[string]string{
			"status":  "ok",
			"id":      pkId,
			"message": "Passkey sicher im Tresor gespeichert",
		}, http.StatusOK)
	}
}

func HandleDeletePasskey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		pkId := chi.URLParam(r, "passkeyId")
		_, _ = db.Exec("DELETE FROM passkeys WHERE id = ? AND user_id = ?", pkId, user.UserId)
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		JSONResponse(w, map[string]string{"status": "ok", "message": "Passkey gelöscht"}, http.StatusOK)
	}
}

func HandlePasskeySignTest(w http.ResponseWriter, r *http.Request) {
	var req models.PasskeySignTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
		return
	}

	res, err := crypto.SignWebAuthnAssertion(req.PrivateKeyPem, req.ClientDataJson, req.AuthDataHex)
	if err != nil {
		HTTPError(w, fmt.Sprintf("Signierfehler: %v", err), http.StatusBadRequest)
		return
	}

	JSONResponse(w, map[string]interface{}{
		"status":    "ok",
		"assertion": res,
	}, http.StatusOK)
}
