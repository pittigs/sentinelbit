package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	DB   *sql.DB
	once sync.Once
)

func GetDataDir() string {
	dataDir := os.Getenv("SENTINELBIT_DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	_ = os.MkdirAll(dataDir, 0755)
	return dataDir
}

func GetDBPath() string {
	return filepath.Join(GetDataDir(), "vault.db")
}

func InitDB() (*sql.DB, error) {
	var err error
	once.Do(func() {
		dbPath := GetDBPath()
		DB, err = sql.Open("sqlite", dbPath)
		if err != nil {
			return
		}

		// Enable WAL mode for high concurrency
		_, _ = DB.Exec("PRAGMA journal_mode = WAL;")
		_, _ = DB.Exec("PRAGMA foreign_keys = ON;")

		schema := `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			auth_salt TEXT NOT NULL,
			auth_hash TEXT NOT NULL,
			enc_salt TEXT NOT NULL,
			totp_secret TEXT,
			totp_enabled INTEGER DEFAULT 0,
			recovery_codes TEXT,
			created_at TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS vault_items (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			type TEXT NOT NULL,
			title TEXT NOT NULL,
			folder TEXT DEFAULT '',
			favorite INTEGER DEFAULT 0,
			encrypted_payload TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			deleted_at TEXT DEFAULT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS webauthn_unlock_keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id TEXT NOT NULL,
			public_key TEXT NOT NULL,
			device_name TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS passkeys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_item_id TEXT,
			rp_id TEXT NOT NULL,
			rp_name TEXT NOT NULL,
			username TEXT NOT NULL,
			user_handle TEXT,
			credential_id TEXT NOT NULL,
			encrypted_private_key TEXT NOT NULL,
			public_key_cose TEXT NOT NULL,
			public_key_pem TEXT,
			sign_count INTEGER DEFAULT 0,
			transports TEXT,
			created_at TEXT NOT NULL,
			last_used_at TEXT,
			deleted_at TEXT DEFAULT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS backup_sync_settings (
			id TEXT PRIMARY KEY,
			user_id TEXT UNIQUE NOT NULL,
			target_dir TEXT NOT NULL,
			interval_minutes INTEGER DEFAULT 15,
			sync_on_change INTEGER DEFAULT 1,
			retention_count INTEGER DEFAULT 10,
			is_active INTEGER DEFAULT 1,
			last_synced_at TEXT,
			last_sync_status TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS user_sharing_keys (
			user_id TEXT PRIMARY KEY,
			public_key_pem TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS shared_items (
			id TEXT PRIMARY KEY,
			sender_id TEXT NOT NULL,
			recipient_username TEXT NOT NULL,
			type TEXT NOT NULL,
			title TEXT NOT NULL,
			encrypted_payload TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS email_aliases (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			alias_email TEXT NOT NULL,
			service_name TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		`

		_, err = DB.Exec(schema)
		if err != nil {
			err = fmt.Errorf("error creating tables: %w", err)
			return
		}

		// Ensure deleted_at columns exist
		ensureColumnExists(DB, "vault_items", "deleted_at", "TEXT DEFAULT NULL")
		ensureColumnExists(DB, "passkeys", "deleted_at", "TEXT DEFAULT NULL")
	})

	return DB, err
}

func InitCustomDB(dbPath string) (*sql.DB, error) {
	customDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	_, _ = customDB.Exec("PRAGMA journal_mode = WAL;")
	_, _ = customDB.Exec("PRAGMA foreign_keys = ON;")

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		auth_salt TEXT NOT NULL,
		auth_hash TEXT NOT NULL,
		enc_salt TEXT NOT NULL,
		totp_secret TEXT,
		totp_enabled INTEGER DEFAULT 0,
		recovery_codes TEXT,
		created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS vault_items (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		type TEXT NOT NULL,
		title TEXT NOT NULL,
		folder TEXT DEFAULT '',
		favorite INTEGER DEFAULT 0,
		encrypted_payload TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		deleted_at TEXT DEFAULT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS webauthn_unlock_keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		credential_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		device_name TEXT NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS passkeys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_item_id TEXT,
		rp_id TEXT NOT NULL,
		rp_name TEXT NOT NULL,
		username TEXT NOT NULL,
		user_handle TEXT,
		credential_id TEXT UNIQUE NOT NULL,
		encrypted_private_key TEXT NOT NULL,
		public_key_cose TEXT NOT NULL,
		public_key_pem TEXT,
		sign_count INTEGER DEFAULT 0,
		transports TEXT,
		created_at TEXT NOT NULL,
		last_used_at TEXT,
		deleted_at TEXT DEFAULT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS backup_sync_settings (
		id TEXT PRIMARY KEY,
		user_id TEXT UNIQUE NOT NULL,
		target_dir TEXT NOT NULL,
		interval_minutes INTEGER DEFAULT 15,
		sync_on_change INTEGER DEFAULT 1,
		retention_count INTEGER DEFAULT 10,
		is_active INTEGER DEFAULT 1,
		last_synced_at TEXT,
		last_sync_status TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS user_sharing_keys (
		user_id TEXT PRIMARY KEY,
		public_key_pem TEXT NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS shared_items (
		id TEXT PRIMARY KEY,
		sender_id TEXT NOT NULL,
		recipient_username TEXT NOT NULL,
		type TEXT NOT NULL,
		title TEXT NOT NULL,
		encrypted_payload TEXT NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS email_aliases (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		alias_email TEXT NOT NULL,
		service_name TEXT NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	`

	_, err = customDB.Exec(schema)
	if err != nil {
		return nil, fmt.Errorf("error creating tables: %w", err)
	}

	ensureColumnExists(customDB, "vault_items", "deleted_at", "TEXT DEFAULT NULL")
	ensureColumnExists(customDB, "passkeys", "deleted_at", "TEXT DEFAULT NULL")

	return customDB, nil
}

func ensureColumnExists(db *sql.DB, tableName, colName, colDef string) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err == nil {
			if name == colName {
				found = true
				break
			}
		}
	}

	if !found {
		_, _ = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", tableName, colName, colDef))
	}
}

