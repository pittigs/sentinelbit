package api

import (
	"database/sql"
	"encoding/json"
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
