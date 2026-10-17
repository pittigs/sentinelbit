package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"sentinelbit/internal/backup"
	"sentinelbit/internal/db"
	"sentinelbit/internal/models"
	"sentinelbit/internal/security"
)

func HandleGetSyncSettings(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var targetDir string
		var intervalMin, syncOnChange, retention, isActive, gdriveEnabled int
		var lastSyncedAt, lastSyncStatus, gdriveFolderId, gdriveCredentials sql.NullString

		hasEnvCreds := os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS") != "" ||
			os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_FILE") != "" ||
			os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_JSON") != "" ||
			os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != ""

		err := database.QueryRow(`
			SELECT target_dir, interval_minutes, sync_on_change, retention_count, is_active,
			       last_synced_at, last_sync_status,
			       COALESCE(gdrive_enabled, 0), COALESCE(gdrive_folder_id, ''), COALESCE(gdrive_credentials, '')
			FROM backup_sync_settings WHERE user_id = ?
		`, user.UserId).Scan(&targetDir, &intervalMin, &syncOnChange, &retention, &isActive,
			&lastSyncedAt, &lastSyncStatus, &gdriveEnabled, &gdriveFolderId, &gdriveCredentials)

		if err != nil {
			absDefault, _ := filepath.Abs(filepath.Join("backups", user.Username))
			envGDrive := strings.EqualFold(os.Getenv("SENTINELBIT_GDRIVE_ENABLED"), "true") || os.Getenv("SENTINELBIT_GDRIVE_ENABLED") == "1"
			JSONResponse(w, map[string]interface{}{
				"target_dir":           absDefault,
				"interval_minutes":     15,
				"sync_on_change":       true,
				"retention_count":      10,
				"is_active":            false,
				"last_synced_at":       nil,
				"last_sync_status":     "Noch nicht eingerichtet",
				"gdrive_enabled":       envGDrive,
				"gdrive_folder_id":     os.Getenv("SENTINELBIT_GDRIVE_FOLDER_ID"),
				"gdrive_credentials":   "",
				"has_saved_creds":      false,
				"has_env_credentials":  hasEnvCreds,
			}, http.StatusOK)
			return
		}

		status := "Bereit"
		if lastSyncStatus.Valid && lastSyncStatus.String != "" {
			status = lastSyncStatus.String
		}

		folderID := gdriveFolderId.String
		if folderID == "" {
			folderID = os.Getenv("SENTINELBIT_GDRIVE_FOLDER_ID")
		}

		isGDrive := gdriveEnabled == 1 || strings.EqualFold(os.Getenv("SENTINELBIT_GDRIVE_ENABLED"), "true") || os.Getenv("SENTINELBIT_GDRIVE_ENABLED") == "1"

		JSONResponse(w, map[string]interface{}{
			"target_dir":          targetDir,
			"interval_minutes":    intervalMin,
			"sync_on_change":      syncOnChange == 1,
			"retention_count":     retention,
			"is_active":           isActive == 1,
			"last_synced_at":      lastSyncedAt.String,
			"last_sync_status":    status,
			"gdrive_enabled":      isGDrive,
			"gdrive_folder_id":    folderID,
			"gdrive_credentials":  gdriveCredentials.String,
			"has_saved_creds":     gdriveCredentials.Valid && gdriveCredentials.String != "",
			"has_env_credentials": hasEnvCreds,
		}, http.StatusOK)
	}
}

func HandleSaveSyncSettings(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req models.BackupSyncSettingsModel
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
			return
		}

		cleanDir, err := security.ValidateBackupDir(req.TargetDir, dbDir())
		if err != nil {
			HTTPError(w, err.Error(), http.StatusBadRequest)
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

		gdriveActive := 0
		if req.GDriveEnabled {
			gdriveActive = 1
		}
		folderID := backup.ExtractFolderID(req.GDriveFolderID)
		creds := strings.TrimSpace(req.GDriveCredentials)

		settingId := uuid.New().String()
		_, err = database.Exec(`
			INSERT INTO backup_sync_settings (
				id, user_id, target_dir, interval_minutes, sync_on_change, retention_count, is_active, last_sync_status,
				gdrive_enabled, gdrive_folder_id, gdrive_credentials
			)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'Konfiguriert', ?, ?, ?)
			ON CONFLICT(user_id) DO UPDATE SET
				target_dir = excluded.target_dir,
				interval_minutes = excluded.interval_minutes,
				sync_on_change = excluded.sync_on_change,
				retention_count = excluded.retention_count,
				is_active = excluded.is_active,
				gdrive_enabled = excluded.gdrive_enabled,
				gdrive_folder_id = excluded.gdrive_folder_id,
				gdrive_credentials = CASE WHEN excluded.gdrive_credentials != '' THEN excluded.gdrive_credentials ELSE backup_sync_settings.gdrive_credentials END
		`, settingId, user.UserId, cleanDir, interval, syncChange, retention, active, gdriveActive, folderID, creds)

		if err != nil {
			HTTPError(w, "Fehler beim Speichern der Einstellungen: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if req.IsActive {
			_, _ = backup.Engine.ExecuteBackup(user.UserId, false)
		}

		JSONResponse(w, map[string]string{
			"status":  "ok",
			"message": "Backup- & Sync-Plan erfolgreich gespeichert",
		}, http.StatusOK)
	}
}

func HandleTestGDriveConnection(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req struct {
			Credentials string `json:"credentials"`
			FolderID    string `json:"folder_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		creds := strings.TrimSpace(req.Credentials)
		folderID := backup.ExtractFolderID(req.FolderID)

		if creds == "" {
			var dbCreds sql.NullString
			_ = database.QueryRow("SELECT gdrive_credentials FROM backup_sync_settings WHERE user_id = ?", user.UserId).Scan(&dbCreds)
			if dbCreds.Valid && dbCreds.String != "" {
				creds = dbCreds.String
			}
		}

		uploader := backup.NewGDriveUploader(creds, folderID)
		msg, err := uploader.TestConnection(r.Context())
		if err != nil {
			JSONResponse(w, map[string]interface{}{
				"status":  "error",
				"message": err.Error(),
			}, http.StatusBadRequest)
			return
		}

		JSONResponse(w, map[string]interface{}{
			"status":  "ok",
			"message": msg,
		}, http.StatusOK)
	}
}

func HandleTriggerSyncNow(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromCtx(r)
	file, err := backup.Engine.ExecuteBackup(user.UserId, false)
	if err != nil {
		JSONResponse(w, map[string]interface{}{
			"status":  "error",
			"message": "Synchronisation fehlgeschlagen: " + err.Error(),
		}, http.StatusOK)
		return
	}
	JSONResponse(w, map[string]interface{}{
		"status":  "ok",
		"message": "Synchronisation erfolgreich durchgeführt",
		"file":    file,
	}, http.StatusOK)
}

func dbDir() string {
	return filepath.Dir(db.GetDBPath())
}

func HandleGDriveAuthURL(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
		clientSecret := strings.TrimSpace(r.URL.Query().Get("client_secret"))

		if clientID == "" || clientSecret == "" {
			HTTPError(w, "client_id und client_secret sind erforderlich", http.StatusBadRequest)
			return
		}

		scheme := "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		redirectURI := fmt.Sprintf("%s://%s/api/sync/gdrive/callback", scheme, r.Host)

		state := backup.GenerateOAuthState(user.UserId, clientID, clientSecret, redirectURI)
		authURL, err := backup.GetOAuthAuthURL(state)
		if err != nil {
			HTTPError(w, err.Error(), http.StatusBadRequest)
			return
		}

		JSONResponse(w, map[string]interface{}{
			"status":       "ok",
			"auth_url":     authURL,
			"redirect_uri": redirectURI,
		}, http.StatusOK)
	}
}

func HandleGDriveCallback(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		errParam := r.URL.Query().Get("error")
		if errParam != "" {
			renderOAuthResult(w, false, "Google Autorisierung abgebrochen: "+errParam)
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			renderOAuthResult(w, false, "Ungültiger Callback von Google (Code oder State fehlt).")
			return
		}

		userID, credsJSON, err := backup.ExchangeOAuthCode(r.Context(), state, code)
		if err != nil {
			renderOAuthResult(w, false, "Fehler beim Token-Austausch: "+err.Error())
			return
		}

		// Update user's backup sync settings with the authorized_user JSON
		res, err := database.Exec(`
			UPDATE backup_sync_settings
			SET gdrive_credentials = ?, gdrive_enabled = 1, last_sync_status = 'Google Drive erfolgreich verknüpft'
			WHERE user_id = ?
		`, credsJSON, userID)
		if err != nil {
			renderOAuthResult(w, false, "Fehler beim Speichern der Anmeldedaten: "+err.Error())
			return
		}

		rows, _ := res.RowsAffected()
		if rows == 0 {
			var username string
			_ = database.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
			if username == "" {
				username = "default"
			}
			settingId := uuid.New().String()
			absDefault, _ := filepath.Abs(filepath.Join("backups", username))
			_, err = database.Exec(`
				INSERT INTO backup_sync_settings (
					id, user_id, target_dir, interval_minutes, sync_on_change, retention_count, is_active, last_sync_status,
					gdrive_enabled, gdrive_folder_id, gdrive_credentials
				)
				VALUES (?, ?, ?, 60, 1, 5, 1, 'Google Drive erfolgreich verknüpft', 1, '', ?)
			`, settingId, userID, absDefault, credsJSON)
			if err != nil {
				renderOAuthResult(w, false, "Fehler beim Anlegen der Einstellungen: "+err.Error())
				return
			}
		}

		renderOAuthResult(w, true, "Google Drive erfolgreich autorisiert!")
	}
}

func renderOAuthResult(w http.ResponseWriter, success bool, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	title := "Google Drive Fehler"
	icon := "❌"
	color := "#f87171"
	if success {
		title = "Google Drive verbunden"
		icon = "✅"
		color = "#34d399"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>%s</title>
  <style>
    body { background: #0b0f17; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #151d2c; border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 12px; padding: 32px; text-align: center; max-width: 440px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    h2 { color: %s; margin-top: 0; font-size: 1.3rem; }
    p { color: #94a3b8; font-size: 0.9rem; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size: 40px; margin-bottom: 12px;">%s</div>
    <h2>%s</h2>
    <p>%s</p>
    <p style="font-size: 0.78rem; color: #64748b;">Dieses Fenster schließt sich in wenigen Sekunden...</p>
  </div>
  <script>
    if (window.opener) {
      window.opener.postMessage({ type: 'gdrive_auth_result', success: %t }, '*');
    }
    setTimeout(function() { window.close(); }, 2500);
  </script>
</body>
</html>`, title, color, icon, title, message, success)

	_, _ = w.Write([]byte(html))
}
