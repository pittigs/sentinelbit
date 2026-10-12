package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinelbit/internal/backup"
	"sentinelbit/internal/models"
)

func HandleListVaultItems(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
			FROM vault_items WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')
			ORDER BY favorite DESC, updated_at DESC
		`, user.UserId)
		if err != nil {
			HTTPError(w, "Datenbankfehler", http.StatusInternalServerError)
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
		JSONResponse(w, items, http.StatusOK)
	}
}

func HandleListTrashItems(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
			FROM vault_items WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at != ''
			ORDER BY updated_at DESC
		`, user.UserId)
		if err != nil {
			HTTPError(w, "Datenbankfehler", http.StatusInternalServerError)
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
		JSONResponse(w, items, http.StatusOK)
	}
}

func HandleCreateVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.VaultItemCreate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
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
			HTTPError(w, "Fehler beim Anlegen des Eintrags", http.StatusInternalServerError)
			return
		}

		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		broadcastVaultEvent(db, user.UserId, "vault_item_created", itemId)

		JSONResponse(w, models.VaultItemResponse{
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

type BatchVaultItemCreate struct {
	Items []models.VaultItemCreate `json:"items"`
}

func HandleBatchCreateVaultItems(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req BatchVaultItemCreate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		if len(req.Items) == 0 {
			JSONResponse(w, map[string]interface{}{"inserted": 0}, http.StatusOK)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			HTTPError(w, "Transaktionsfehler: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		stmt, err := tx.Prepare(`
			INSERT INTO vault_items (id, user_id, type, title, folder, favorite, encrypted_payload, created_at, updated_at, deleted_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		`)
		if err != nil {
			HTTPError(w, "Statement-Fehler: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		now := time.Now().UTC().Format(time.RFC3339)
		inserted := 0
		for _, item := range req.Items {
			fav := 0
			if item.Favorite {
				fav = 1
			}
			itemId := uuid.New().String()
			_, err := stmt.Exec(itemId, user.UserId, item.Type, item.Title, item.Folder, fav, item.EncryptedPayload, now, now)
			if err != nil {
				HTTPError(w, "Fehler beim Importieren: "+err.Error(), http.StatusInternalServerError)
				return
			}
			inserted++
		}

		if err := tx.Commit(); err != nil {
			HTTPError(w, "Commit-Fehler: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Trigger backup ONCE after the entire batch is committed
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		broadcastVaultEvent(db, user.UserId, "vault_batch_created", inserted)

		JSONResponse(w, map[string]interface{}{
			"inserted": inserted,
			"message":  "Erfolgreich importiert",
		}, http.StatusOK)
	}
}

func HandleUpdateVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")

		var req models.VaultItemUpdate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		var existingType, existingTitle, existingFolder, existingPayload, createdAt string
		var existingFav int
		err := db.QueryRow(`
			SELECT type, title, folder, favorite, encrypted_payload, created_at
			FROM vault_items WHERE id = ? AND user_id = ?
		`, itemId, user.UserId).Scan(&existingType, &existingTitle, &existingFolder, &existingFav, &existingPayload, &createdAt)

		if err != nil {
			HTTPError(w, "Eintrag nicht gefunden", http.StatusNotFound)
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
			HTTPError(w, "Fehler beim Aktualisieren", http.StatusInternalServerError)
			return
		}

		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		broadcastVaultEvent(db, user.UserId, "vault_item_updated", itemId)

		JSONResponse(w, models.VaultItemResponse{
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

func HandleDeleteVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")
		permanent := r.URL.Query().Get("permanent") == "true"

		var deletedAt sql.NullString
		err := db.QueryRow("SELECT deleted_at FROM vault_items WHERE id = ? AND user_id = ?", itemId, user.UserId).Scan(&deletedAt)
		if err != nil {
			HTTPError(w, "Eintrag nicht gefunden", http.StatusNotFound)
			return
		}

		if permanent || (deletedAt.Valid && deletedAt.String != "") {
			_, _ = db.Exec("DELETE FROM vault_items WHERE id = ? AND user_id = ?", itemId, user.UserId)
			_, _ = db.Exec("DELETE FROM passkeys WHERE vault_item_id = ? AND user_id = ?", itemId, user.UserId)
			_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
			broadcastVaultEvent(db, user.UserId, "vault_item_deleted", itemId)
			JSONResponse(w, map[string]string{"status": "ok", "message": "Eintrag endgültig gelöscht"}, http.StatusOK)
		} else {
			now := time.Now().UTC().Format(time.RFC3339)
			_, _ = db.Exec("UPDATE vault_items SET deleted_at = ? WHERE id = ? AND user_id = ?", now, itemId, user.UserId)
			_, _ = db.Exec("UPDATE passkeys SET deleted_at = ? WHERE vault_item_id = ? AND user_id = ?", now, itemId, user.UserId)
			_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
			broadcastVaultEvent(db, user.UserId, "vault_item_trashed", itemId)
			JSONResponse(w, map[string]string{"status": "ok", "message": "Eintrag in den Papierkorb verschoben"}, http.StatusOK)
		}
	}
}

func HandleRestoreVaultItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")

		_, _ = db.Exec("UPDATE vault_items SET deleted_at = NULL WHERE id = ? AND user_id = ?", itemId, user.UserId)
		_, _ = db.Exec("UPDATE passkeys SET deleted_at = NULL WHERE vault_item_id = ? AND user_id = ?", itemId, user.UserId)
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		broadcastVaultEvent(db, user.UserId, "vault_item_restored", itemId)
		JSONResponse(w, map[string]string{"status": "ok", "message": "Eintrag aus dem Papierkorb wiederhergestellt"}, http.StatusOK)
	}
}

func HandleEmptyTrash(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		_, _ = db.Exec("DELETE FROM vault_items WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at != ''", user.UserId)
		_, _ = db.Exec("DELETE FROM passkeys WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at != ''", user.UserId)
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		broadcastVaultEvent(db, user.UserId, "vault_trash_emptied", nil)
		JSONResponse(w, map[string]string{"status": "ok", "message": "Papierkorb vollständig geleert"}, http.StatusOK)
	}
}

func HandleClearVault(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		_, err1 := db.Exec("DELETE FROM vault_items WHERE user_id = ?", user.UserId)
		_, err2 := db.Exec("DELETE FROM passkeys WHERE user_id = ?", user.UserId)
		if err1 != nil || err2 != nil {
			HTTPError(w, "Fehler beim Leeren des Tresors", http.StatusInternalServerError)
			return
		}
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		broadcastVaultEvent(db, user.UserId, "vault_cleared", nil)
		JSONResponse(w, map[string]string{"status": "ok", "message": "Tresor wurde vollständig geleert"}, http.StatusOK)
	}
}

func broadcastVaultEvent(database *sql.DB, userID, event string, payload interface{}) {
	Broker.Broadcast(userID, event, payload)
	jsonBytes, _ := json.Marshal(map[string]interface{}{
		"event":     event,
		"payload":   payload,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	DispatchWebhooks(database, userID, event, string(jsonBytes))
}

type ReencryptItemPayload struct {
	ID               string `json:"id"`
	EncryptedPayload string `json:"encrypted_payload"`
}

type ReencryptVaultRequest struct {
	NewAuthSalt string                 `json:"new_auth_salt"`
	NewAuthHash string                 `json:"new_auth_hash"`
	NewEncSalt  string                 `json:"new_enc_salt"`
	Items       []ReencryptItemPayload `json:"items"`
}

// HandleReencryptVault atomically updates user master password salts and all encrypted items
func HandleReencryptVault(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req ReencryptVaultRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültige Anfrage", http.StatusBadRequest)
			return
		}

		if req.NewAuthSalt == "" || req.NewAuthHash == "" || req.NewEncSalt == "" {
			HTTPError(w, "Fehlende Schlüsselparameter", http.StatusBadRequest)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			HTTPError(w, "Transaktionsfehler: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		// 1. Update user salts & auth hash
		_, err = tx.Exec(`
			UPDATE users
			SET auth_salt = ?, auth_hash = ?, enc_salt = ?
			WHERE id = ?
		`, req.NewAuthSalt, req.NewAuthHash, req.NewEncSalt, user.UserId)
		if err != nil {
			HTTPError(w, "Fehler beim Aktualisieren des Benutzers", http.StatusInternalServerError)
			return
		}

		// 2. Update active sessions enc_salt
		_, _ = tx.Exec("UPDATE sessions SET enc_salt = ? WHERE user_id = ?", req.NewEncSalt, user.UserId)

		// 3. Update all re-encrypted vault items
		itemStmt, err := tx.Prepare("UPDATE vault_items SET encrypted_payload = ?, updated_at = ? WHERE id = ? AND user_id = ?")
		if err != nil {
			HTTPError(w, "Fehler beim Vorbereiten des Item-Statements", http.StatusInternalServerError)
			return
		}
		defer itemStmt.Close()

		nowIso := time.Now().UTC().Format(time.RFC3339)
		for _, it := range req.Items {
			_, err = itemStmt.Exec(it.EncryptedPayload, nowIso, it.ID, user.UserId)
			if err != nil {
				HTTPError(w, "Fehler beim Aktualisieren der Tresor-Einträge", http.StatusInternalServerError)
				return
			}
		}

		if err := tx.Commit(); err != nil {
			HTTPError(w, "Commit-Fehler: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Trigger backup & broadcast event
		_, _ = backup.Engine.ExecuteBackup(user.UserId, true)
		broadcastVaultEvent(db, user.UserId, "vault_reencrypted", map[string]interface{}{
			"count": len(req.Items),
		})

		JSONResponse(w, map[string]interface{}{
			"status":  "ok",
			"message": "Tresor erfolgreich atomar neu verschlüsselt",
			"count":   len(req.Items),
		}, http.StatusOK)
	}
}

