# 🛡️ sentinelbit (Go 2.0 Edition)

[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Security Architecture](https://img.shields.io/badge/Security-Zero--Knowledge-10b981?style=flat&logo=security)](https://github.com)
[![Docker Ready](https://img.shields.io/badge/Docker-Multi--Arch%20(ARM64%20%2F%20AMD64)-2496ED?style=flat&logo=docker)](https://docker.com)
[![Passkeys FIDO2](https://img.shields.io/badge/FIDO2-WebAuthn%20P--256-8b5cf6?style=flat&logo=fido)](https://fidoalliance.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Ein hochmoderner, selbst gehosteter **Zero-Knowledge Passwort- & Passkey-Manager**, entwickelt in **Go (Golang)**. Kombiniert client-seitige Web Crypto (AES-256-GCM + PBKDF2), hardwaregestützte FIDO2/WebAuthn Passkeys, einen integrierten 2FA Authenticator, Anti-Phishing Autofill-Schutz und automatische Backup-Synchronisation.

> **Zero-Knowledge Garantie**: Der Server sieht **niemals** deine Klartext-Passwörter, Notizen oder deinen Master-Schlüssel. Sämtliche Ent- und Verschlüsselungsprozesse finden ausschließlich im Browser auf deinem Endgerät statt.

---

## 📸 Screenshots & Architektur

```
                                  +------------------------------------+
                                  |     sentinelbit Client (Browser)   |
                                  |   Master Password -> PBKDF2 100k   |
                                  |  AES-256-GCM Verschlüsselung       |
                                  +-----------------+------------------+
                                                    | (Nur Ciphertext & Auth Hash)
                                                    v
+---------------------------------------------------+-----------------------------------+
|                            sentinelbit Daemon (Go Server)                             |
|                                                                                       |
|  [Chi Router]       [Rate Limiter]       [TOTP Replay Guard]      [Security Headers]  |
|         |                  |                      |                       |           |
|         +------------------+----------------------+-----------------------+           |
|                                    |                                                  |
|                   [Pure-Go SQLite3 (WAL Modus)]                                       |
|                                    |                                                  |
|                        [Automated Sync & Backup Engine]                               |
+---------------------------------------------------------------------------------------+
```

---

## ✨ Features im Überblick

* 🚀 **100% Pure Go Single Binary**: Das komplette Backend kompiliert in eine einzige schlanke Binärdatei (~18 MB) – absolut keine Python-, Node- oder Pip-Abhängigkeiten mehr!
* 🍓 **Optimiert für Raspberry Pi 5 (ARM64)**: Verbraucht im Leerlauf unter 15 MB RAM, startet in Millisekunden und schont CPU & SD-Karte.
* 🛡️ **Zero-Knowledge Kryptografie & Tresor-Gesundheit**: 
  * PBKDF2-HMAC-SHA256 mit 100.000 Iterationen (Client-seitig).
  * Zweite serverseitige Hashing-Schicht mit separatem Salt gegen Datenbank-Leaks.
  * AES-256-GCM für jeden Tresor-Eintrag mit kryptografisch zufälligen IVs.
  * **Interaktiver Tresor-Gesundheitscheck**: Analysiert wiederverwendete Passwörter, schwache Passwörter und fehlende 2FA rein lokal im Browser mit direktem 1-Klick-Bearbeiten.
* ⚡ **FIDO2 / WebAuthn Hardware Passkeys**:
  * Erstellung, Speicherung und Assertion-Signierung von P-256 (ES256) Passkeys.
  * Biometrisches Entsperren via **Windows Hello, Touch ID oder Fingerabdruck**.
* ⏱️ **Integrierter 2FA Authenticator (TOTP)**:
  * Google-Authenticator-kompatibel inklusive QR-Code-Setup und Timing-Replay-Guard.
* 🔌 **Anti-Phishing Browser Extension**:
  * Chrome/Brave/Edge/Firefox-kompatibel (Manifest V3).
  * **Anti-Hidden-Trap Defense**: Verhindert das heimliche Ausfüllen unsichtbarer Phishing-Felder (`display: none`, `opacity: 0`, 1px-Traps oder Offscreen-Inputs).
* 📥 **Universeller Multi-Manager Importer**:
  * Nahtloser 1-Klick-Import aus **Bitwarden** (JSON/CSV), **1Password** (1PUX/CSV), **KeePassXC** (CSV), **LastPass** sowie **Google Chrome** & **Mozilla Firefox**.
* 🔄 **Automatisierter Backup & Sync-Dienst**:
  * Isolierte, benutzerspezifische Backups mit konfigurierbarer Dateirotation und Retention.
* 🎭 **E-Mail-Maskierung ("Hide My Email")**:
  * Generiere auf Knopfdruck zufällige Relay-Aliase für Online-Registrierungen.
* 🤝 **Asymmetrisches E2E Tresor-Sharing**:
  * Teile Passwörter sicher Ende-zu-Ende verschlüsselt mit RSA-OAEP + AES-256-GCM.

---

## 🚀 Schnellstart

### Methode 1: 🐳 1-Klick Docker Run (Empfohlen für Raspberry Pi & Server)

Das fertige Multi-Architektur-Image unterstützt automatisch x86_64 (PC/Server) sowie ARM64 (Raspberry Pi 3/4/5) und kann ohne vorheriges Klonen direkt gestartet werden:

```bash
docker run -d \
  --name sentinelbit \
  -p 8000:8000 \
  -v ./data:/data \
  --restart unless-stopped \
  ghcr.io/pittigs/sentinelbit:latest
```

Oder mit Docker Compose:

```bash
docker compose up -d
```

Öffne anschließend im Browser: **`http://localhost:8000`**

---

### Methode 2: Makefile / Nativ mit Go starten

Voraussetzung: [Go 1.22+](https://golang.org/dl/)

```bash
# Bauen & Starten via Linux-Startskript:
./run.sh            # Startet Sentinelbit direkt auf http://127.0.0.1:8000

# Bauen via Makefile (kompiliert Server & CLI nach ./bin/):
make build          # Kompiliert ./bin/sentinelbit und ./bin/sentinelbit-cli
make run            # Startet den Server direkt

# Oder Cross-Compilation für den Raspberry Pi 5 (ARM64):
make build-pi       # Erstellt ./bin/sentinelbit-arm64 & CLI
```

---

## 💻 Natives CLI-Tool (`sentinelbit-cli`)

Das mitgelieferte Go-CLI erlaubt administrative Aufgaben und Statusabfragen direkt im Terminal:

```bash
# Server-Status & Verbindung prüfen
./bin/sentinelbit-cli status

# Registrierte Benutzer und Tresorstatistiken einsehen
./bin/sentinelbit-cli users
```

---

## ⚙️ Konfiguration & Umgebungsvariablen

Kopiere die Vorlage `.env.example` oder setze die Umgebungsvariablen:

```bash
SENTINELBIT_PORT=8000                  # HTTP-Port (Standard: 8000)
SENTINELBIT_HOST=0.0.0.0               # Bind-Host (z.B. 127.0.0.1 für lokale Nutzung)
SENTINELBIT_DATA_DIR=./data            # Pfad für SQLite-Datenbank & Backups
SENTINELBIT_DISABLE_REGISTRATION=true  # Schließt offene Registrierung für Fremde
SENTINELBIT_LOG_LEVEL=info             # Log-Level: debug, info, warn, error
```

---

## 📱 Progressive Web App (PWA)

sentinelbit enthält ein Web App Manifest und einen integrierten Service Worker.
* **Mobilgeräte (iOS / Android)**: Im Browser öffnen und **"Zum Startbildschirm hinzufügen"** antippen, um Sentinelbit wie eine native App ohne störende Browserleisten zu nutzen.
* **Desktop (Chrome / Edge / Brave)**: Auf das Installations-Icon in der URL-Leiste klicken, um die App als Standalone-Fenster zu installieren.

---

## 🧪 Tests ausführen

sentinelbit verfügt über eine vollständige Testsuite für alle Pakete (Kryptografie, Rate-Limiting, Replay-Schutz, HTTP-Header, Konfiguration und Datenbank):

```bash
go test -v ./...
```

---

## 🔌 Browser-Erweiterung installieren

1. Öffne in Chrome, Brave oder Edge die URL: `chrome://extensions/`
2. Aktiviere oben rechts den **Entwicklermodus** (*Developer mode*).
3. Klicke auf **Entpackte Erweiterung laden** (*Load unpacked*).
4. Wähle den Ordner `extension/` im Projektverzeichnis aus.
5. Das sentinelbit-Icon erscheint in deiner Symbolleiste!

---

## 🔒 Sicherheitsmerkmale

| Schutzmechanismus | Technische Umsetzung |
| :--- | :--- |
| **Kryptografie** | PBKDF2-HMAC-SHA256 (100k Iterationen), AES-256-GCM |
| **Passkeys** | FIDO2 P-256 (ES256) ECDSA WebAuthn |
| **Brute-Force Schutz** | In-Memory Token-Bucket Rate Limiter (5 Versuche / 15 Min Block) |
| **Replay Schutz** | Time-based Sliding Window Guard für TOTP-Tokens (90s Drift) |
| **Anti-Enumeration** | Timing-sichere HMAC Dummy-Salts für unbekannte Benutzer |
| **Anti-Phishing Autofill** | DOM Bounding-Box, Opacity & Visibility Check gegen Trap-Inputs |
| **HTTP Hardening** | Strikte CSP, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` |

---

## 📄 Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).
