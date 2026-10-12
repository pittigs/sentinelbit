package api

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinelbit/internal/models"
)

// HandleCreateSecureSend creates a new temporary burn-after-reading secret
func HandleCreateSecureSend(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.SecureSendCreateRequest
		if err := jsonDecode(r, &req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		if strings.TrimSpace(req.EncryptedPayload) == "" {
			HTTPError(w, "Verschlüsselter Inhalt darf nicht leer sein", http.StatusBadRequest)
			return
		}

		burnLimit := req.BurnLimit
		if burnLimit <= 0 {
			burnLimit = 1
		} else if burnLimit > 50 {
			burnLimit = 50
		}

		expireHours := req.ExpireHours
		if expireHours <= 0 {
			expireHours = 24
		} else if expireHours > 168 {
			expireHours = 168 // 7 Tage maximal
		}

		sendID := uuid.New().String()
		now := time.Now().UTC()
		expiresAt := now.Add(time.Duration(expireHours) * time.Hour).Format(time.RFC3339)
		createdAt := now.Format(time.RFC3339)

		_, err := db.Exec(`
			INSERT INTO secure_sends (id, encrypted_payload, burn_limit, view_count, expires_at, created_at)
			VALUES (?, ?, ?, 0, ?, ?)
		`, sendID, req.EncryptedPayload, burnLimit, expiresAt, createdAt)

		if err != nil {
			HTTPError(w, "Fehler beim Erstellen des Send-Links", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, models.SecureSendResponse{
			ID:        sendID,
			ExpiresAt: expiresAt,
			BurnLimit: burnLimit,
			ViewCount: 0,
		}, http.StatusCreated)
	}
}

// HandleGetSecureSend retrieves the payload and increments view count or burns it
func HandleGetSecureSend(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sendID := strings.TrimSpace(chi.URLParam(r, "sendId"))
		if sendID == "" {
			HTTPError(w, "ID fehlt", http.StatusBadRequest)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			HTTPError(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		var (
			encryptedPayload string
			burnLimit        int
			viewCount        int
			expiresAtStr     string
		)

		err = tx.QueryRow(`
			SELECT encrypted_payload, burn_limit, view_count, expires_at
			FROM secure_sends WHERE id = ?
		`, sendID).Scan(&encryptedPayload, &burnLimit, &viewCount, &expiresAtStr)

		if err == sql.ErrNoRows {
			HTTPError(w, "Dieser sichere Send-Link existiert nicht mehr oder wurde bereits nach dem Abruf zerstört.", http.StatusNotFound)
			return
		} else if err != nil {
			HTTPError(w, "Fehler beim Laden des Send-Links", http.StatusInternalServerError)
			return
		}

		// Check expiration
		expTime, parseErr := time.Parse(time.RFC3339, expiresAtStr)
		if parseErr == nil && time.Now().UTC().After(expTime) {
			_, _ = tx.Exec("DELETE FROM secure_sends WHERE id = ?", sendID)
			_ = tx.Commit()
			HTTPError(w, "Dieser sichere Send-Link ist abgelaufen und wurde gelöscht.", http.StatusGone)
			return
		}

		newViewCount := viewCount + 1
		remaining := burnLimit - newViewCount
		if remaining < 0 {
			remaining = 0
		}

		if newViewCount >= burnLimit {
			// Burn immediately upon hitting burn limit
			_, _ = tx.Exec("DELETE FROM secure_sends WHERE id = ?", sendID)
		} else {
			_, _ = tx.Exec("UPDATE secure_sends SET view_count = ? WHERE id = ?", newViewCount, sendID)
		}

		if err := tx.Commit(); err != nil {
			HTTPError(w, "Fehler beim Verarbeiten des Send-Links", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, models.SecureSendRetrieveResponse{
			ID:               sendID,
			EncryptedPayload: encryptedPayload,
			BurnLimit:        burnLimit,
			ViewCount:        newViewCount,
			RemainingViews:   remaining,
		}, http.StatusOK)
	}
}
