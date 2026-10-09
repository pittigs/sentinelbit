package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"

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
		var intervalMin, syncOnChange, retention, isActive int
		var lastSyncedAt, lastSyncStatus sql.NullString

		err := database.QueryRow(`
			SELECT target_dir, interval_minutes, sync_on_change, retention_count, is_active, last_synced_at, last_sync_status
			FROM backup_sync_settings WHERE user_id = ?
		`, user.UserId).Scan(&targetDir, &intervalMin, &syncOnChange, &retention, &isActive, &lastSyncedAt, &lastSyncStatus)

		if err != nil {
			absDefault, _ := filepath.Abs(filepath.Join("backups", user.Username))
			JSONResponse(w, map[string]interface{}{
				"target_dir":       absDefault,
				"interval_minutes": 15,
				"sync_on_change":   true,
				"retention_count":  10,
				"is_active":        false,
				"last_synced_at":   nil,
				"last_sync_status": "Noch nicht eingerichtet",
			}, http.StatusOK)
			return
		}

		status := "Bereit"
		if lastSyncStatus.Valid && lastSyncStatus.String != "" {
			status = lastSyncStatus.String
		}

		JSONResponse(w, map[string]interface{}{
			"target_dir":       targetDir,
			"interval_minutes": intervalMin,
			"sync_on_change":   syncOnChange == 1,
			"retention_count":  retention,
			"is_active":        isActive == 1,
			"last_synced_at":   lastSyncedAt.String,
			"last_sync_status": status,
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

		settingId := uuid.New().String()
		_, err = database.Exec(`
			INSERT INTO backup_sync_settings (id, user_id, target_dir, interval_minutes, sync_on_change, retention_count, is_active, last_sync_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'Konfiguriert')
			ON CONFLICT(user_id) DO UPDATE SET
				target_dir = excluded.target_dir,
				interval_minutes = excluded.interval_minutes,
				sync_on_change = excluded.sync_on_change,
				retention_count = excluded.retention_count,
				is_active = excluded.is_active
		`, settingId, user.UserId, cleanDir, interval, syncChange, retention, active)

		if err != nil {
			HTTPError(w, "Fehler beim Speichern der Einstellungen", http.StatusInternalServerError)
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
