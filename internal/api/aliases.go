package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"sentinelbit/internal/crypto"
	"sentinelbit/internal/models"
)

func HandleListAliases(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query("SELECT id, alias_email, service_name, created_at FROM email_aliases WHERE user_id = ? ORDER BY created_at DESC", user.UserId)
		if err != nil {
			HTTPError(w, "Datenbankfehler", http.StatusInternalServerError)
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
		JSONResponse(w, res, http.StatusOK)
	}
}

func HandleCreateAlias(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.EmailAliasCreate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
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
			HTTPError(w, "Fehler beim Anlegen des E-Mail-Alias", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, map[string]string{
			"status":       "ok",
			"id":           aliasId,
			"alias_email":  aliasEmail,
			"service_name": req.ServiceName,
		}, http.StatusOK)
	}
}

func HandleDeleteAlias(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		aliasId := chi.URLParam(r, "aliasId")
		_, _ = db.Exec("DELETE FROM email_aliases WHERE id = ? AND user_id = ?", aliasId, user.UserId)
		JSONResponse(w, map[string]string{"status": "ok", "message": "E-Mail-Alias gelöscht"}, http.StatusOK)
	}
}
