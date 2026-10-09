package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"sentinelbit/internal/api"
	"sentinelbit/internal/backup"
	"sentinelbit/internal/config"
	"sentinelbit/internal/db"
)

// setupRouter maintains full backward-compatibility for test files in cmd/server
func setupRouter(database *sql.DB) *chi.Mux {
	cfg := config.Load()
	return api.SetupRouter(database, cfg)
}

func main() {
	cfg := config.Load()

	// Initialize structured logger
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Initialize database and migrations
	database, err := db.InitDB()
	if err != nil {
		slog.Error("Database init failed", "error", err)
		os.Exit(1)
	}

	// Initialize API secrets and restore active sessions
	api.InitAPI(cfg, database)

	// Start background backup worker
	backup.Engine.Start()
	defer backup.Engine.Stop()

	// Periodic garbage collection for expired sessions and rate limiters
	gcTicker := time.NewTicker(2 * time.Minute)
	gcStop := make(chan struct{})
	go func() {
		for {
			select {
			case <-gcTicker.C:
				api.CleanupExpired(database)
			case <-gcStop:
				gcTicker.Stop()
				return
			}
		}
	}()
	defer close(gcStop)

	r := api.SetupRouter(database, cfg)

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("🛡️ sentinelbit Server gestartet",
			"address", fmt.Sprintf("http://%s", addr),
			"data_dir", cfg.DataDir,
			"registration_disabled", cfg.DisableRegistration,
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP Server Fehler", "error", err)
			os.Exit(1)
		}
	}()

	<-stopChan
	slog.Info("Fahre Server herunter...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Fehler beim Beenden des Servers", "error", err)
	}

	slog.Info("Server ordnungsgemäß beendet. Auf Wiedersehen!")
}
