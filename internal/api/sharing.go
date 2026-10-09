package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinelbit/internal/models"
)

func HandleRegisterSharePublicKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.SharingPublicKeyRegister
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		now := time.Now().UTC().Format(time.RFC3339)
		_, err := db.Exec(`
			INSERT INTO user_sharing_keys (user_id, public_key_pem, created_at)
			VALUES (?, ?, ?)
			ON CONFLICT(user_id) DO UPDATE SET public_key_pem = excluded.public_key_pem
		`, user.UserId, req.PublicKeyPem, now)

		if err != nil {
			HTTPError(w, "Fehler beim Speichern des Sharing-Schlüssels", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, map[string]string{"status": "ok", "message": "Öffentlicher Sharing-Schlüssel gespeichert"}, http.StatusOK)
	}
}

func HandleGetRecipientPublicKey(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetUsername := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "targetUsername")))

		var targetUserId string
		err := db.QueryRow("SELECT id FROM users WHERE username = ?", targetUsername).Scan(&targetUserId)
		if err != nil {
			HTTPError(w, "Empfänger-Benutzername existiert nicht", http.StatusNotFound)
			return
		}

		var pubKeyPem string
		err = db.QueryRow("SELECT public_key_pem FROM user_sharing_keys WHERE user_id = ?", targetUserId).Scan(&pubKeyPem)
		if err != nil {
			HTTPError(w, "Empfänger hat noch keinen Sharing-Schlüssel aktiviert", http.StatusBadRequest)
			return
		}

		JSONResponse(w, map[string]string{
			"username":       targetUsername,
			"public_key_pem": pubKeyPem,
		}, http.StatusOK)
	}
}

func HandleSendSharedItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.ShareItemSendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
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
			HTTPError(w, "Fehler beim Teilen des Eintrags", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, map[string]string{
			"status":  "ok",
			"message": fmt.Sprintf("Eintrag sicher für '%s' freigegeben!", targetUsername),
		}, http.StatusOK)
	}
}

func HandleListSharedInbox(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query(`
			SELECT s.id, s.type, s.title, s.encrypted_payload, s.created_at, u.username as sender_username
			FROM shared_items s
			JOIN users u ON s.sender_id = u.id
			WHERE s.recipient_username = ?
			ORDER BY s.created_at DESC
		`, user.Username)
		if err != nil {
			HTTPError(w, "Datenbankfehler", http.StatusInternalServerError)
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
		JSONResponse(w, res, http.StatusOK)
	}
}

func HandleDeleteSharedInboxItem(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		itemId := chi.URLParam(r, "itemId")
		_, _ = db.Exec("DELETE FROM shared_items WHERE id = ? AND recipient_username = ?", itemId, user.Username)
		JSONResponse(w, map[string]string{"status": "ok", "message": "Geteilter Eintrag entfernt"}, http.StatusOK)
	}
}
