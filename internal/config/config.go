package config

import (
	"os"
	"strings"
)

// Config represents runtime configuration settings
type Config struct {
	Port                string
	Host                string
	DataDir             string
	DisableRegistration bool
	LogLevel            string
	ForwardAuthEnabled  bool
	ForwardAuthHeader   string
	GDriveEnabled       bool
	GDriveFolderID      string
	GDriveCredentials   string
}

// Load reads configuration from environment variables with sensible defaults
func Load() *Config {
	port := os.Getenv("SENTINELBIT_PORT")
	if port == "" {
		port = "8000"
	}

	host := os.Getenv("SENTINELBIT_HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	dataDir := os.Getenv("SENTINELBIT_DATA_DIR")
	if dataDir == "" {
		if _, err := os.Stat("vault.db"); err == nil {
			dataDir = "."
		} else {
			dataDir = "./data"
		}
	}
	_ = os.MkdirAll(dataDir, 0755)

	disReg := os.Getenv("SENTINELBIT_DISABLE_REGISTRATION")
	disableRegistration := strings.EqualFold(disReg, "true") || disReg == "1"

	logLevel := strings.ToLower(os.Getenv("SENTINELBIT_LOG_LEVEL"))
	if logLevel == "" {
		logLevel = "info"
	}

	faEnv := os.Getenv("SENTINELBIT_FORWARD_AUTH_ENABLED")
	forwardAuthEnabled := strings.EqualFold(faEnv, "true") || faEnv == "1"

	faHeader := os.Getenv("SENTINELBIT_FORWARD_AUTH_HEADER")
	if faHeader == "" {
		faHeader = "X-Remote-User"
	}

	gdriveEnv := os.Getenv("SENTINELBIT_GDRIVE_ENABLED")
	gdriveEnabled := strings.EqualFold(gdriveEnv, "true") || gdriveEnv == "1"

	gdriveFolderID := os.Getenv("SENTINELBIT_GDRIVE_FOLDER_ID")
	gdriveCreds := os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS")
	if gdriveCreds == "" {
		gdriveCreds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_FILE")
	}
	if gdriveCreds == "" {
		gdriveCreds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_JSON")
	}

	return &Config{
		Port:                port,
		Host:                host,
		DataDir:             dataDir,
		DisableRegistration: disableRegistration,
		LogLevel:            logLevel,
		ForwardAuthEnabled:  forwardAuthEnabled,
		ForwardAuthHeader:   faHeader,
		GDriveEnabled:       gdriveEnabled,
		GDriveFolderID:      gdriveFolderID,
		GDriveCredentials:   gdriveCreds,
	}
}
