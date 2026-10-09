package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitCustomDB(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_vault.db")

	testDB, err := InitCustomDB(dbPath)
	if err != nil {
		t.Fatalf("InitCustomDB failed: %v", err)
	}
	defer testDB.Close()

	// Verify tables exist
	tables := []string{
		"users",
		"vault_items",
		"passkeys",
		"webauthn_unlock_keys",
		"backup_sync_settings",
		"user_sharing_keys",
		"shared_items",
		"email_aliases",
		"sessions",
	}

	for _, tbl := range tables {
		var name string
		err := testDB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl).Scan(&name)
		if err != nil || name != tbl {
			t.Errorf("Table %s was not created: %v", tbl, err)
		}
	}

	// Verify PRAGMA user_version is 2
	var version int
	if err := testDB.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Errorf("Expected PRAGMA user_version 2, got %d (err: %v)", version, err)
	}
}

func TestGetDataDir(t *testing.T) {
	os.Setenv("SENTINELBIT_DATA_DIR", "/tmp/sentinelbit_test_data")
	defer os.Unsetenv("SENTINELBIT_DATA_DIR")

	d := GetDataDir()
	if d != "/tmp/sentinelbit_test_data" {
		t.Errorf("Expected /tmp/sentinelbit_test_data, got %s", d)
	}
}
