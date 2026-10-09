package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"sentinelbit/internal/config"
	"sentinelbit/internal/db"
)

const cliVersion = "2.1.0"

func printUsage() {
	fmt.Println("🛡️  sentinelbit-cli - Zero-Knowledge Management CLI")
	fmt.Println()
	fmt.Println("Nutzung:")
	fmt.Println("  sentinelbit-cli <befehl> [optionen]")
	fmt.Println()
	fmt.Println("Verfügbare Befehle:")
	fmt.Println("  status          Prüft den Zustand des laufenden Sentinelbit-Servers")
	fmt.Println("  users           Listet registrierte Benutzer und Tresor-Statistiken auf")
	fmt.Println("  version         Zeigt die Version des CLI-Tools an")
	fmt.Println("  help            Zeigt diese Hilfe an")
	fmt.Println()
	fmt.Println("Beispiele:")
	fmt.Println("  sentinelbit-cli status")
	fmt.Println("  sentinelbit-cli users")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "status":
		cmdStatus()
	case "users":
		cmdUsers()
	case "version", "-v", "--version":
		fmt.Printf("sentinelbit-cli Version %s (Go 2.0 Edition)\n", cliVersion)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unbekannter Befehl: '%s'\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func cmdStatus() {
	cfg := config.Load()
	serverURL := fmt.Sprintf("http://%s:%s/api/health", cfg.Host, cfg.Port)
	if cfg.Host == "0.0.0.0" {
		serverURL = fmt.Sprintf("http://127.0.0.1:%s/api/health", cfg.Port)
	}

	fmt.Printf("📡 Verbinde mit Server: %s ...\n", serverURL)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(serverURL)
	if err != nil {
		fmt.Printf("❌ Server nicht erreichbar (%v)\n", err)
		fmt.Println("   Tipp: Starte den Server mit './run.sh' oder 'make run'")
		os.Exit(1)
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		fmt.Printf("❌ Ungültige Server-Antwort: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Server läuft ordnungsgemäß!")
	fmt.Printf("   Dienst:         %v\n", data["service"])
	fmt.Printf("   Version:        %v\n", data["version"])
	fmt.Printf("   Status:         %v\n", data["status"])
	fmt.Printf("   Registrierung:  %v\n", data["registration"])
	fmt.Printf("   Datenpfad:      %s\n", cfg.DataDir)
}

func cmdUsers() {
	database, err := db.InitDB()
	if err != nil {
		fmt.Printf("❌ Fehler beim Zugriff auf die SQLite-Datenbank: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	rows, err := database.Query(`
		SELECT u.id, u.username, u.totp_enabled, u.created_at,
		       (SELECT COUNT(*) FROM vault_items WHERE user_id = u.id AND (deleted_at IS NULL OR deleted_at = '')) as item_count,
		       (SELECT COUNT(*) FROM passkeys WHERE user_id = u.id AND (deleted_at IS NULL OR deleted_at = '')) as passkey_count
		FROM users u
		ORDER BY u.created_at ASC
	`)
	if err != nil {
		fmt.Printf("❌ Datenbankabfrage fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	fmt.Println("👥 Registrierte Benutzer in der Datenbank:")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("%-20s %-8s %-12s %-10s %-20s\n", "BENUTZER", "2FA", "EINTRÄGE", "PASSKEYS", "ERSTELLT AM")
	fmt.Println("--------------------------------------------------------------------------------")

	count := 0
	for rows.Next() {
		var id, username, createdAt string
		var totpEnabled, itemCount, passkeyCount int
		if err := rows.Scan(&id, &username, &totpEnabled, &createdAt, &itemCount, &passkeyCount); err == nil {
			count++
			totpStr := "Nein"
			if totpEnabled == 1 {
				totpStr = "Ja ✓"
			}
			createdShort := createdAt
			if len(createdAt) > 10 {
				createdShort = createdAt[:10]
			}
			fmt.Printf("%-20s %-8s %-12d %-10d %-20s\n", username, totpStr, itemCount, passkeyCount, createdShort)
		}
	}

	if count == 0 {
		fmt.Println("   (Keine Benutzer vorhanden. Registriere den ersten Account im Browser!)")
	}
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("Gesamt: %d Benutzer\n", count)
}
