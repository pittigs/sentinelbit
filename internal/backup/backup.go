package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

func safeUsername(name string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9_\-]`)
	clean := reg.ReplaceAllString(name, "_")
	if len(clean) > 64 {
		clean = clean[:64]
	}
	if clean == "" {
		clean = "user"
	}
	return clean
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

	var username, encSalt string
	err = database.QueryRow("SELECT username, enc_salt FROM users WHERE id = ?", userId).Scan(&username, &encSalt)
	if err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	// 1. Vault items
	itemRows, err := database.Query(`
		SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
		FROM vault_items
		WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')
		ORDER BY created_at ASC
	`, userId)
	if err != nil {
		return "", fmt.Errorf("failed to query vault items: %w", err)
	}
	defer itemRows.Close()

	items := make([]map[string]interface{}, 0)
	for itemRows.Next() {
		var id, itype, title, payload, createdAt, updatedAt string
		var folder sql.NullString
		var fav int
		if err := itemRows.Scan(&id, &itype, &title, &folder, &fav, &payload, &createdAt, &updatedAt); err == nil {
			items = append(items, map[string]interface{}{
				"id":                id,
				"type":              itype,
				"title":             title,
				"folder":            folder.String,
				"favorite":          fav == 1,
				"encrypted_payload": payload,
				"created_at":        createdAt,
				"updated_at":        updatedAt,
			})
		}
	}

	// 2. Passkeys
	pkRows, err := database.Query(`
		SELECT id, vault_item_id, rp_id, rp_name, username, user_handle, credential_id,
		       encrypted_private_key, public_key_cose, public_key_pem, sign_count, transports, created_at, last_used_at
		FROM passkeys
		WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')
		ORDER BY created_at ASC
	`, userId)
	if err == nil {
		defer pkRows.Close()
	}

	passkeys := make([]map[string]interface{}, 0)
	if pkRows != nil {
		for pkRows.Next() {
			var id, rpId, rpName, uName, credId, encPriv, pubCose, createdAt string
			var vaultItemId, userHandle, pubPem, transports, lastUsedAt sql.NullString
			var signCount int
			if err := pkRows.Scan(&id, &vaultItemId, &rpId, &rpName, &uName, &userHandle, &credId,
				&encPriv, &pubCose, &pubPem, &signCount, &transports, &createdAt, &lastUsedAt); err == nil {
				passkeys = append(passkeys, map[string]interface{}{
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
					"transports":            transports.String,
					"created_at":            createdAt,
					"last_used_at":          lastUsedAt.String,
				})
			}
		}
	}

	// 3. Email aliases
	aliasRows, err := database.Query("SELECT id, alias_email, service_name, created_at FROM email_aliases WHERE user_id = ?", userId)
	if err == nil {
		defer aliasRows.Close()
	}
	aliases := make([]map[string]interface{}, 0)
	if aliasRows != nil {
		for aliasRows.Next() {
			var id, email, service, createdAt string
			if err := aliasRows.Scan(&id, &email, &service, &createdAt); err == nil {
				aliases = append(aliases, map[string]interface{}{
					"id":           id,
					"alias_email":  email,
					"service_name": service,
					"created_at":   createdAt,
				})
			}
		}
	}

	safeName := safeUsername(username)
	now := time.Now()
	nowISO := now.UTC().Format(time.RFC3339)
	timestamp := now.Format("20060102_150405")

	payload := map[string]interface{}{
		"version":        2,
		"type":           "SentinelBit_automated_encrypted_sync",
		"created_at":     nowISO,
		"username":       username,
		"enc_salt":       encSalt,
		"items_count":    len(items),
		"passkeys_count": len(passkeys),
		"items":          items,
		"passkeys":       passkeys,
		"email_aliases":  aliases,
	}

	dataBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("json marshal error: %w", err)
	}

	destFile := filepath.Join(targetDir, fmt.Sprintf("SentinelBit_backup_%s_%s.json", safeName, timestamp))
	latestFile := filepath.Join(targetDir, fmt.Sprintf("SentinelBit_backup_%s_latest.json", safeName))

	if err := os.WriteFile(destFile, dataBytes, 0600); err != nil {
		_, _ = database.Exec(`
			UPDATE backup_sync_settings
			SET last_sync_status = ?
			WHERE user_id = ?
		`, "Fehler: "+err.Error(), userId)
		return "", err
	}
	_ = os.WriteFile(latestFile, dataBytes, 0600)

	// Retention rotation: Keep only last N backups matching pattern
	pattern := filepath.Join(targetDir, fmt.Sprintf("SentinelBit_backup_%s_*.json", safeName))
	matches, _ := filepath.Glob(pattern)
	var backupFiles []string
	for _, m := range matches {
		if !strings.HasSuffix(m, "_latest.json") {
			backupFiles = append(backupFiles, m)
		}
	}

	if retentionCount < 1 {
		retentionCount = 10
	}
	if len(backupFiles) > retentionCount {
		sort.Strings(backupFiles)
		for _, f := range backupFiles[:len(backupFiles)-retentionCount] {
			_ = os.Remove(f)
		}
	}

	_, _ = database.Exec(`
		UPDATE backup_sync_settings
		SET last_synced_at = ?, last_sync_status = 'Erfolgreich synchronisiert'
		WHERE user_id = ?
	`, nowISO, userId)

	return destFile, nil
}
