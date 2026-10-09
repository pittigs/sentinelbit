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

	return &Config{
		Port:                port,
		Host:                host,
		DataDir:             dataDir,
		DisableRegistration: disableRegistration,
		LogLevel:            logLevel,
	}
}
