package backup

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinelbit/internal/db"
)

type BackupEngine struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

var Engine = &BackupEngine{}

func (be *BackupEngine) Start() {
	be.mu.Lock()
	defer be.mu.Unlock()

	if be.cancel != nil {
		return
	}

	be.ctx, be.cancel = context.WithCancel(context.Background())
	go be.loop()
}

func (be *BackupEngine) Stop() {
	be.mu.Lock()
	defer be.mu.Unlock()

	if be.cancel != nil {
		be.cancel()
		be.cancel = nil
	}
}

func (be *BackupEngine) loop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-be.ctx.Done():
			return
		case <-ticker.C:
			be.runScheduledBackups()
		}
	}
}

func (be *BackupEngine) runScheduledBackups() {
	database, err := db.InitDB()
	if err != nil {
		return
	}

	rows, err := database.Query(`
		SELECT user_id, target_dir, interval_minutes, retention_count, is_active, last_synced_at
		FROM backup_sync_settings
		WHERE is_active = 1
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	type task struct {
		userId       string
		targetDir    string
		intervalMin  int
		retention    int
		lastSyncedAt sql.NullString
	}

	var tasks []task
	for rows.Next() {
		var t task
		var isActive int
		if err := rows.Scan(&t.userId, &t.targetDir, &t.intervalMin, &t.retention, &isActive, &t.lastSyncedAt); err == nil {
			tasks = append(tasks, t)
		}
	}

	now := time.Now()
	for _, t := range tasks {
		due := false
		if !t.lastSyncedAt.Valid || t.lastSyncedAt.String == "" {
			due = true
		} else {
			lastTime, err := time.Parse(time.RFC3339, t.lastSyncedAt.String)
			if err != nil || now.Sub(lastTime) >= time.Duration(t.intervalMin)*time.Minute {
				due = true
			}
		}

		if due {
			_, _ = be.ExecuteBackup(t.userId, false)
		}
	}
}

func (be *BackupEngine) ExecuteBackup(userId string, isChangeTriggered bool) (string, error) {
	database, err := db.InitDB()
	if err != nil {
		return "", err
	}

	var targetDir string
	var retentionCount, syncOnChange int
	err = database.QueryRow(`
		SELECT target_dir, retention_count, sync_on_change
		FROM backup_sync_settings
		WHERE user_id = ? AND is_active = 1
	`, userId).Scan(&targetDir, &retentionCount, &syncOnChange)

	if err != nil {
		return "", fmt.Errorf("no active backup config: %w", err)
	}

	if isChangeTriggered && syncOnChange == 0 {
		return "", nil
	}

	targetDir = filepath.Clean(strings.TrimSpace(targetDir))
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create backup target dir: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	destFile := filepath.Join(targetDir, fmt.Sprintf("sentinelbit_backup_%s_%s.db", userId[:8], timestamp))

	dbPath := db.GetDBPath()
	if err := copyFile(dbPath, destFile); err != nil {
		_, _ = database.Exec(`
			UPDATE backup_sync_settings
			SET last_sync_status = ?
			WHERE user_id = ?
		`, "Fehler: "+err.Error(), userId)
		return "", err
	}

	// Purge old retention backups
	pattern := filepath.Join(targetDir, fmt.Sprintf("sentinelbit_backup_%s_*.db", userId[:8]))
	matches, _ := filepath.Glob(pattern)
	if len(matches) > retentionCount {
		sort.Strings(matches)
		for _, f := range matches[:len(matches)-retentionCount] {
			_ = os.Remove(f)
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	_, _ = database.Exec(`
		UPDATE backup_sync_settings
		SET last_synced_at = ?, last_sync_status = 'Erfolgreich synchronisiert'
		WHERE user_id = ?
	`, nowStr, userId)

	return destFile, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

