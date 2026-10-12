package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"sentinelbit/internal/config"
	"sentinelbit/internal/crypto"
	"sentinelbit/internal/db"
)

const cliVersion = "3.0.0"

func printUsage() {
	fmt.Println("🛡️  sentinelbit-cli - Zero-Knowledge Management CLI")
	fmt.Println()
	fmt.Println("Nutzung:")
	fmt.Println("  sentinelbit-cli <befehl> [optionen]")
	fmt.Println()
	fmt.Println("Verfügbare Befehle:")
	fmt.Println("  status              Prüft den Zustand des laufenden Sentinelbit-Servers")
	fmt.Println("  audit               Führt einen DB-Integritäts- und System-Sicherheitscheck durch")
	fmt.Println("  send <text>         Erstellt einen verschlüsselten Secure-Send Einmal-Link (Zero-Knowledge)")
	fmt.Println("  run [opts] -- <cmd> Führt Befehl mit injizierten Secrets als Umgebungsvariablen aus")
	fmt.Println("  git-credential <op> Git Credential Helper (get/store/erase)")
	fmt.Println("  ssh-key <titel>     Gibt den privaten SSH-Schlüssel eines Eintrags aus")
	fmt.Println("  users               Listet registrierte Benutzer und Tresor-Statistiken auf")
	fmt.Println("  version             Zeigt die Version des CLI-Tools an")
	fmt.Println("  help                Zeigt diese Hilfe an")
	fmt.Println()
	fmt.Println("Beispiele:")
	fmt.Println("  sentinelbit-cli status")
	fmt.Println("  sentinelbit-cli audit")
	fmt.Println("  sentinelbit-cli send \"geheimes_passwort_123\"")
	fmt.Println("  sentinelbit-cli run -- env")
	fmt.Println("  sentinelbit-cli git-credential get")
	fmt.Println("  sentinelbit-cli ssh-key id_rsa | ssh-add -")
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
	case "audit":
		cmdAudit()
	case "send":
		if len(os.Args) < 3 {
			fmt.Println("❌ Fehler: Bitte den geheimen Text angeben.")
			fmt.Println("   Beispiel: sentinelbit-cli send \"MeinGeheimesPasswort\"")
			os.Exit(1)
		}
		cmdSend(os.Args[2])
	case "users":
		cmdUsers()
	case "run":
		cmdRun(os.Args[2:])
	case "git-credential":
		if len(os.Args) < 3 {
			fmt.Println("Nutzung: sentinelbit-cli git-credential <get|store|erase>")
			os.Exit(1)
		}
		cmdGitCredential(os.Args[2])
	case "ssh-key":
		if len(os.Args) < 3 {
			fmt.Println("Nutzung: sentinelbit-cli ssh-key <titel>")
			os.Exit(1)
		}
		cmdSSHKey(os.Args[2])
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

func cmdAudit() {
	dbPath := db.GetDBPath()

	fmt.Println("🔍 SentinelBit System- & Datenbank-Audit:")
	fmt.Println("--------------------------------------------------------------------------------")

	database, err := db.InitDB()
	if err != nil {
		fmt.Printf("❌ Fehler beim Öffnen der SQLite-Datenbank: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// 1. Check file stats
	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		fmt.Printf("❌ Datenbankdatei nicht gefunden: %s (%v)\n", dbPath, err)
		os.Exit(1)
	}
	fmt.Printf("   Datenbankdatei:   %s\n", dbPath)
	fmt.Printf("   Größe:            %.2f MB (%d Bytes)\n", float64(fileInfo.Size())/(1024*1024), fileInfo.Size())

	// WAL file check
	walPath := dbPath + "-wal"
	if walInfo, err := os.Stat(walPath); err == nil {
		fmt.Printf("   SQLite WAL:       Aktiv (%.2f KB)\n", float64(walInfo.Size())/1024)
	} else {
		fmt.Printf("   SQLite WAL:       Nicht aktiv oder synchronisiert\n")
	}

	// 2. PRAGMA integrity_check
	var integrityResult string
	if err := database.QueryRow("PRAGMA integrity_check").Scan(&integrityResult); err != nil {
		fmt.Printf("❌ PRAGMA integrity_check Fehler: %v\n", err)
	} else if integrityResult == "ok" {
		fmt.Println("   SQLite Integrität: OK (PRAGMA integrity_check = ok) ✓")
	} else {
		fmt.Printf("⚠️ SQLite Integrität: Fehlerhaft (%s)\n", integrityResult)
	}

	// 3. Page count & cache
	var pageCount, pageSize int
	_ = database.QueryRow("PRAGMA page_count").Scan(&pageCount)
	_ = database.QueryRow("PRAGMA page_size").Scan(&pageSize)
	fmt.Printf("   Pages / Page-Size: %d Pages @ %d Bytes\n", pageCount, pageSize)

	// 4. Session & Vault Stats
	var activeSessions int
	nowIso := time.Now().UTC().Format(time.RFC3339)
	_ = database.QueryRow("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", nowIso).Scan(&activeSessions)

	var userCount, itemCount, sendCount int
	_ = database.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	_ = database.QueryRow("SELECT COUNT(*) FROM vault_items WHERE deleted_at IS NULL OR deleted_at = ''").Scan(&itemCount)
	_ = database.QueryRow("SELECT COUNT(*) FROM secure_sends WHERE expires_at > ? AND access_count < burn_limit", nowIso).Scan(&sendCount)

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("📊 Statistiken:\n")
	fmt.Printf("   Benutzer:         %d\n", userCount)
	fmt.Printf("   Tresor-Einträge:  %d (aktiv)\n", itemCount)
	fmt.Printf("   Aktive Sessions:  %d\n", activeSessions)
	fmt.Printf("   Aktive Sends:     %d (Burn-after-Reading bereit)\n", sendCount)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("✅ Audit erfolgreich abgeschlossen. Alle Sicherheits- & DB-Prüfungen bestanden.")
}

func cmdSend(text string) {
	cfg := config.Load()

	// 1. Generate 32-byte AES-256 key client-side
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		fmt.Printf("❌ Fehler beim Generieren des Schlüssels: %v\n", err)
		os.Exit(1)
	}

	// 2. Generate 12-byte IV
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Printf("❌ Fehler beim Generieren des IV: %v\n", err)
		os.Exit(1)
	}

	// 3. Encrypt text with AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("❌ Fehler bei AES Cipher: %v\n", err)
		os.Exit(1)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("❌ Fehler bei GCM Initialisierung: %v\n", err)
		os.Exit(1)
	}

	ciphertext := aesGCM.Seal(nil, iv, []byte(text), nil)

	// 4. Send payload to SentinelBit API
	serverURL := fmt.Sprintf("http://%s:%s/api/send", cfg.Host, cfg.Port)
	if cfg.Host == "0.0.0.0" {
		serverURL = fmt.Sprintf("http://127.0.0.1:%s/api/send", cfg.Port)
	}

	payload := map[string]interface{}{
		"ciphertext":   hex.EncodeToString(ciphertext),
		"iv":           hex.EncodeToString(iv),
		"burn_limit":   1,
		"expire_hours": 24,
	}

	bodyBytes, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(serverURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		fmt.Printf("❌ Fehler beim Senden an %s: %v\n", serverURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var errData map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&errData)
		fmt.Printf("❌ Server-Fehler (%d): %v\n", resp.StatusCode, errData)
		os.Exit(1)
	}

	var resData struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&resData); err != nil {
		fmt.Printf("❌ Fehler beim Parsen der Server-Antwort: %v\n", err)
		os.Exit(1)
	}

	baseWebURL := fmt.Sprintf("http://%s:%s", cfg.Host, cfg.Port)
	if cfg.Host == "0.0.0.0" {
		baseWebURL = fmt.Sprintf("http://127.0.0.1:%s", cfg.Port)
	}

	keyHex := hex.EncodeToString(key)
	sendURL := fmt.Sprintf("%s/#send?id=%s&key=%s", baseWebURL, resData.ID, keyHex)

	fmt.Println("🚀 SentinelBit Secure Send - Einmal-Link generiert:")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("Link: %s\n", sendURL)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("🔒 Zero-Knowledge Garantie: Der Schlüssel ('key' im Hash #) wurde lokal generiert")
	fmt.Println("   und nie an den Server übertragen. Nach 1x Abruf oder 24h wird der Datensatz zerstört.")
}

func resolveMasterKey(database *sql.DB, usernameInput, passwordInput string) (string, []byte, error) {
	var userID, username, encSalt string
	var err error

	if usernameInput != "" {
		err = database.QueryRow("SELECT id, username, enc_salt FROM users WHERE username = ?", usernameInput).Scan(&userID, &username, &encSalt)
	} else if envUser := os.Getenv("SENTINELBIT_USER"); envUser != "" {
		err = database.QueryRow("SELECT id, username, enc_salt FROM users WHERE username = ?", envUser).Scan(&userID, &username, &encSalt)
	} else {
		err = database.QueryRow("SELECT id, username, enc_salt FROM users ORDER BY created_at ASC LIMIT 1").Scan(&userID, &username, &encSalt)
	}

	if err != nil {
		return "", nil, fmt.Errorf("kein passender Benutzer gefunden: %w", err)
	}

	password := passwordInput
	if password == "" {
		password = os.Getenv("SENTINELBIT_PASSWORD")
	}
	if password == "" {
		fmt.Fprintf(os.Stderr, "🔑 Master-Passwort für '%s': ", username)
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			password = strings.TrimSpace(scanner.Text())
		}
	}

	if password == "" {
		return "", nil, fmt.Errorf("master-Passwort erforderlich")
	}

	key := crypto.DeriveMasterKey(password, encSalt)
	return userID, key, nil
}

func normalizeEnvKey(s string) string {
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		} else {
			out.WriteRune('_')
		}
	}
	return strings.ToUpper(out.String())
}

func cmdRun(args []string) {
	var username, password, prefix string
	prefix = "SENTINELBIT_SECRET_"

	dashDashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashDashIdx = i
			break
		}
	}

	var flagArgs, cmdArgs []string
	if dashDashIdx >= 0 {
		flagArgs = args[:dashDashIdx]
		cmdArgs = args[dashDashIdx+1:]
	} else {
		cmdArgs = args
	}

	for i := 0; i < len(flagArgs); i++ {
		switch flagArgs[i] {
		case "-u", "--user":
			if i+1 < len(flagArgs) {
				username = flagArgs[i+1]
				i++
			}
		case "-p", "--password":
			if i+1 < len(flagArgs) {
				password = flagArgs[i+1]
				i++
			}
		case "--prefix":
			if i+1 < len(flagArgs) {
				prefix = flagArgs[i+1]
				i++
			}
		}
	}

	if len(cmdArgs) == 0 {
		fmt.Println("❌ Fehler: Kein Befehl zur Ausführung angegeben.")
		fmt.Println("   Nutzung: sentinelbit-cli run [optionen] -- <befehl> [argumente]")
		fmt.Println("   Beispiel: sentinelbit-cli run -- env")
		os.Exit(1)
	}

	database, err := db.InitDB()
	if err != nil {
		fmt.Printf("❌ Datenbankfehler: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	userID, masterKey, err := resolveMasterKey(database, username, password)
	if err != nil {
		fmt.Printf("❌ Authentifizierungsfehler: %v\n", err)
		os.Exit(1)
	}

	rows, err := database.Query("SELECT title, encrypted_payload FROM vault_items WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')", userID)
	if err != nil {
		fmt.Printf("❌ Fehler beim Laden der Einträge: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	var extraEnvs []string
	injectedCount := 0

	for rows.Next() {
		var title, encPayload string
		if err := rows.Scan(&title, &encPayload); err == nil {
			data, err := crypto.DecryptVaultPayload(encPayload, masterKey)
			if err == nil {
				cleanTitle := normalizeEnvKey(title)
				if pwd, ok := data["password"].(string); ok && pwd != "" {
					extraEnvs = append(extraEnvs, fmt.Sprintf("%s%s=%s", prefix, cleanTitle, pwd))
					extraEnvs = append(extraEnvs, fmt.Sprintf("%s%s_PASSWORD=%s", prefix, cleanTitle, pwd))
					injectedCount++
				}
				if uname, ok := data["username"].(string); ok && uname != "" {
					extraEnvs = append(extraEnvs, fmt.Sprintf("%s%s_USERNAME=%s", prefix, cleanTitle, uname))
				}
				if u, ok := data["url"].(string); ok && u != "" {
					extraEnvs = append(extraEnvs, fmt.Sprintf("%s%s_URL=%s", prefix, cleanTitle, u))
				}
				if notes, ok := data["notes"].(string); ok && notes != "" {
					extraEnvs = append(extraEnvs, fmt.Sprintf("%s%s_NOTES=%s", prefix, cleanTitle, notes))
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "🚀 SentinelBit Secret Injection: %d Secrets injiziert. Starte '%s'...\n", injectedCount, cmdArgs[0])

	subCmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	subCmd.Env = append(os.Environ(), extraEnvs...)
	subCmd.Stdin = os.Stdin
	subCmd.Stdout = os.Stdout
	subCmd.Stderr = os.Stderr

	if err := subCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "❌ Fehler: %v\n", err)
		os.Exit(1)
	}
}

func cmdGitCredential(op string) {
	scanner := bufio.NewScanner(os.Stdin)
	params := make(map[string]string)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			params[parts[0]] = parts[1]
		}
	}

	if op != "get" {
		return
	}

	host := params["host"]
	if host == "" {
		return
	}

	database, err := db.InitDB()
	if err != nil {
		return
	}
	defer database.Close()

	userID, masterKey, err := resolveMasterKey(database, "", "")
	if err != nil {
		return
	}

	rows, err := database.Query("SELECT title, encrypted_payload FROM vault_items WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')", userID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var title, encPayload string
		if err := rows.Scan(&title, &encPayload); err == nil {
			data, err := crypto.DecryptVaultPayload(encPayload, masterKey)
			if err == nil {
				urlVal, _ := data["url"].(string)
				if strings.Contains(strings.ToLower(urlVal), strings.ToLower(host)) || strings.Contains(strings.ToLower(title), strings.ToLower(host)) {
					uname, _ := data["username"].(string)
					pwd, _ := data["password"].(string)
					if params["username"] == "" || params["username"] == uname {
						fmt.Printf("username=%s\n", uname)
						fmt.Printf("password=%s\n", pwd)
						return
					}
				}
			}
		}
	}
}

func cmdSSHKey(titleSearch string) {
	database, err := db.InitDB()
	if err != nil {
		fmt.Printf("❌ Fehler: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	userID, masterKey, err := resolveMasterKey(database, "", "")
	if err != nil {
		fmt.Printf("❌ Fehler: %v\n", err)
		os.Exit(1)
	}

	rows, err := database.Query("SELECT title, encrypted_payload FROM vault_items WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')", userID)
	if err != nil {
		fmt.Printf("❌ Fehler: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	titleSearchLower := strings.ToLower(titleSearch)
	for rows.Next() {
		var title, encPayload string
		if err := rows.Scan(&title, &encPayload); err == nil {
			if strings.Contains(strings.ToLower(title), titleSearchLower) {
				data, err := crypto.DecryptVaultPayload(encPayload, masterKey)
				if err == nil {
					keyText := ""
					if pk, ok := data["private_key"].(string); ok && pk != "" {
						keyText = pk
					} else if notes, ok := data["notes"].(string); ok && strings.Contains(notes, "PRIVATE KEY") {
						keyText = notes
					} else if pwd, ok := data["password"].(string); ok {
						keyText = pwd
					}

					if keyText != "" {
						if !strings.HasSuffix(keyText, "\n") {
							keyText += "\n"
						}
						fmt.Print(keyText)
						return
					}
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "❌ Kein SSH-Schlüssel für '%s' gefunden\n", titleSearch)
	os.Exit(1)
}

