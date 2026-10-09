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

// GetDataDir resolves the runtime data directory.
// If SENTINELBIT_DATA_DIR is unset:
// If vault.db already exists in the current working directory, it keeps using "." for backwards compatibility.
// Otherwise, it defaults cleanly to "./data".
func GetDataDir() string {
	dataDir := os.Getenv("SENTINELBIT_DATA_DIR")
	if dataDir == "" {
		if _, err := os.Stat("vault.db"); err == nil {
			dataDir = "."
		} else {
			dataDir = "./data"
		}
	}
	_ = os.MkdirAll(dataDir, 0755)
	return dataDir
}

// GetDBPath returns the full path to the SQLite vault database file
func GetDBPath() string {
	return filepath.Join(GetDataDir(), "vault.db")
}

// InitDB initializes the default application SQLite database connection and runs migrations
func InitDB() (*sql.DB, error) {
	var err error
	once.Do(func() {
		dbPath := GetDBPath()
		DB, err = sql.Open("sqlite", dbPath)
		if err != nil {
			return
		}

		// Enable WAL mode for high concurrency & set busy timeout
		_, _ = DB.Exec("PRAGMA journal_mode = WAL;")
		_, _ = DB.Exec("PRAGMA foreign_keys = ON;")
		_, _ = DB.Exec("PRAGMA busy_timeout = 5000;")
		DB.SetMaxOpenConns(25)
		DB.SetMaxIdleConns(5)

		err = runMigrations(DB)
	})

	return DB, err
}

// InitCustomDB initializes an isolated SQLite database connection for tests or custom paths
func InitCustomDB(dbPath string) (*sql.DB, error) {
	customDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("error opening custom db: %w", err)
	}

	_, _ = customDB.Exec("PRAGMA journal_mode = WAL;")
	_, _ = customDB.Exec("PRAGMA foreign_keys = ON;")
	_, _ = customDB.Exec("PRAGMA busy_timeout = 5000;")
	customDB.SetMaxOpenConns(25)
	customDB.SetMaxIdleConns(5)

	if err := runMigrations(customDB); err != nil {
		return nil, err
	}

	return customDB, nil
}

func runMigrations(db *sql.DB) error {
	var currentVersion int
	_ = db.QueryRow("PRAGMA user_version").Scan(&currentVersion)

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

	CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		username TEXT NOT NULL,
		enc_salt TEXT NOT NULL,
		totp_enabled INTEGER DEFAULT 0,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_vault_items_user_active ON vault_items(user_id, deleted_at, favorite);
	CREATE INDEX IF NOT EXISTS idx_passkeys_user_active ON passkeys(user_id, deleted_at);
	CREATE INDEX IF NOT EXISTS idx_shared_items_recipient ON shared_items(recipient_username);
	CREATE INDEX IF NOT EXISTS idx_email_aliases_user ON email_aliases(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("error creating database schema: %w", err)
	}

	ensureColumnExists(db, "vault_items", "deleted_at", "TEXT DEFAULT NULL")
	ensureColumnExists(db, "passkeys", "deleted_at", "TEXT DEFAULT NULL")

	_, _ = db.Exec("PRAGMA user_version = 2;")
	return nil
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
