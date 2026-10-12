package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type WebhookModel struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	URL       string `json:"url"`
	Secret    string `json:"secret"`
	Events    string `json:"events"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at"`
}

type WebhookCreateRequest struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
	Events string `json:"events,omitempty"`
}

// HandleListWebhooks returns all webhooks registered by the authenticated user
func HandleListWebhooks(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := GetUserFromCtx(r)
		if session == nil {
			HTTPError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		rows, err := database.Query(`
			SELECT id, user_id, url, secret, events, is_active, created_at
			FROM webhooks
			WHERE user_id = ?
			ORDER BY created_at DESC
		`, session.UserId)
		if err != nil {
			HTTPError(w, "Failed to query webhooks", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		hooks := make([]WebhookModel, 0)
		for rows.Next() {
			var h WebhookModel
			var activeInt int
			if err := rows.Scan(&h.ID, &h.UserID, &h.URL, &h.Secret, &h.Events, &activeInt, &h.CreatedAt); err == nil {
				h.IsActive = activeInt == 1
				hooks = append(hooks, h)
			}
		}

		JSONResponse(w, hooks, http.StatusOK)
	}
}

// HandleCreateWebhook registers a new webhook
func HandleCreateWebhook(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := GetUserFromCtx(r)
		if session == nil {
			HTTPError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req WebhookCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		req.URL = strings.TrimSpace(req.URL)
		if req.URL == "" || (!strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://")) {
			HTTPError(w, "Invalid webhook URL: must start with http:// or https://", http.StatusBadRequest)
			return
		}

		if req.Events == "" {
			req.Events = "vault:change"
		}

		secret := req.Secret
		if secret == "" {
			secBytes := make([]byte, 24)
			_, _ = rand.Read(secBytes)
			secret = hex.EncodeToString(secBytes)
		}

		hookID := uuid.New().String()
		nowIso := time.Now().UTC().Format(time.RFC3339)

		_, err := database.Exec(`
			INSERT INTO webhooks (id, user_id, url, secret, events, is_active, created_at)
			VALUES (?, ?, ?, ?, ?, 1, ?)
		`, hookID, session.UserId, req.URL, secret, req.Events, nowIso)
		if err != nil {
			HTTPError(w, "Failed to save webhook", http.StatusInternalServerError)
			return
		}

		JSONResponse(w, WebhookModel{
			ID:        hookID,
			UserID:    session.UserId,
			URL:       req.URL,
			Secret:    secret,
			Events:    req.Events,
			IsActive:  true,
			CreatedAt: nowIso,
		}, http.StatusCreated)
	}
}

// HandleDeleteWebhook removes a webhook
func HandleDeleteWebhook(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := GetUserFromCtx(r)
		if session == nil {
			HTTPError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		hookID := chi.URLParam(r, "hookId")
		res, err := database.Exec("DELETE FROM webhooks WHERE id = ? AND user_id = ?", hookID, session.UserId)
		if err != nil {
			HTTPError(w, "Failed to delete webhook", http.StatusInternalServerError)
			return
		}

		rowsAff, _ := res.RowsAffected()
		if rowsAff == 0 {
			HTTPError(w, "Webhook not found", http.StatusNotFound)
			return
		}

		JSONResponse(w, map[string]string{"status": "deleted"}, http.StatusOK)
	}
}

// HandleTestWebhook sends an immediate test ping event
func HandleTestWebhook(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := GetUserFromCtx(r)
		if session == nil {
			HTTPError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		hookID := chi.URLParam(r, "hookId")
		var url, secret string
		err := database.QueryRow("SELECT url, secret FROM webhooks WHERE id = ? AND user_id = ?", hookID, session.UserId).Scan(&url, &secret)
		if err != nil {
			HTTPError(w, "Webhook not found", http.StatusNotFound)
			return
		}

		payload := map[string]interface{}{
			"event":     "ping",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"user_id":   session.UserId,
			"message":   "SentinelBit Webhook Test Verification",
		}
		payloadBytes, _ := json.Marshal(payload)

		go sendWebhookHTTP(url, secret, "ping", payloadBytes)

		JSONResponse(w, map[string]string{
			"status":  "test_dispatched",
			"message": "Webhook test event queued for delivery",
		}, http.StatusOK)
	}
}

// DispatchWebhooks sends an asynchronous event to all matching user webhooks
func DispatchWebhooks(database *sql.DB, userID, event, payloadJSON string) {
	if database == nil || userID == "" {
		return
	}

	rows, err := database.Query(`
		SELECT url, secret, events FROM webhooks
		WHERE user_id = ? AND is_active = 1
	`, userID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var hookURL, secret, events string
		if err := rows.Scan(&hookURL, &secret, &events); err == nil {
			if strings.Contains(events, event) || strings.Contains(events, "vault:change") || events == "*" {
				go sendWebhookHTTP(hookURL, secret, event, []byte(payloadJSON))
			}
		}
	}
}

func sendWebhookHTTP(targetURL, secret, event string, body []byte) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SentinelBit-Webhook/3.0.0")
	req.Header.Set("X-SentinelBit-Event", event)
	req.Header.Set("X-SentinelBit-Signature", fmt.Sprintf("sha256=%s", sig))

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}
