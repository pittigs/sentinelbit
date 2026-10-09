package config

import (
	"os"
	"testing"
)

func TestConfigLoadDefaults(t *testing.T) {
	// Clear relevant env vars
	os.Unsetenv("SENTINELBIT_PORT")
	os.Unsetenv("SENTINELBIT_HOST")
	os.Unsetenv("SENTINELBIT_DISABLE_REGISTRATION")
	os.Unsetenv("SENTINELBIT_LOG_LEVEL")

	cfg := Load()
	if cfg.Port != "8000" {
		t.Errorf("Expected default Port 8000, got %s", cfg.Port)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Expected default Host 0.0.0.0, got %s", cfg.Host)
	}
	if cfg.DisableRegistration {
		t.Errorf("Expected DisableRegistration to be false by default")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("Expected default LogLevel 'info', got %s", cfg.LogLevel)
	}
}

func TestConfigCustomEnv(t *testing.T) {
	os.Setenv("SENTINELBIT_PORT", "9090")
	os.Setenv("SENTINELBIT_HOST", "127.0.0.1")
	os.Setenv("SENTINELBIT_DISABLE_REGISTRATION", "true")
	os.Setenv("SENTINELBIT_LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("SENTINELBIT_PORT")
		os.Unsetenv("SENTINELBIT_HOST")
		os.Unsetenv("SENTINELBIT_DISABLE_REGISTRATION")
		os.Unsetenv("SENTINELBIT_LOG_LEVEL")
	}()

	cfg := Load()
	if cfg.Port != "9090" {
		t.Errorf("Expected Port 9090, got %s", cfg.Port)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected Host 127.0.0.1, got %s", cfg.Host)
	}
	if !cfg.DisableRegistration {
		t.Errorf("Expected DisableRegistration to be true")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("Expected LogLevel 'debug', got %s", cfg.LogLevel)
	}
}
