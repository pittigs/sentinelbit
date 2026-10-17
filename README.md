# 🛡️ sentinelbit (v3.0.0 Major Release)

[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Security Architecture](https://img.shields.io/badge/Security-Zero--Knowledge-10b981?style=flat&logo=security)](https://github.com)
[![Chrome Web Store](https://img.shields.io/badge/Extension-Manifest%20V3-4285F4?style=flat&logo=googlechrome)](CHROME_STORE_GUIDE.md)
[![Docker Ready](https://img.shields.io/badge/Docker-Multi--Arch%20(ARM64%20%2F%20AMD64)-2496ED?style=flat&logo=docker)](https://docker.com)
[![Passkeys FIDO2](https://img.shields.io/badge/FIDO2-WebAuthn%20P--256-8b5cf6?style=flat&logo=fido)](https://fidoalliance.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Ein hochmoderner, selbst gehosteter **Zero-Knowledge Passwort- & Passkey-Manager**, entwickelt in **Go (Golang)**. Kombiniert client-seitige Web Crypto (AES-256-GCM + PBKDF2), hardwaregestützte FIDO2/WebAuthn Passkeys, einen integrierten 2FA Authenticator, Anti-Phishing Autofill-Schutz und automatische Backup-Synchronisation.

> **Zero-Knowledge Garantie**: Der Server sieht **niemals** deine Klartext-Passwörter, Notizen oder deinen Master-Schlüssel. Sämtliche Ent- und Verschlüsselungsprozesse finden ausschließlich im Browser auf deinem Endgerät statt.

---

## 📸 Architektur & Zero-Knowledge Workflow

```
+------------------------------------+          +--------------------------------------------+
|      sentinelbit Web-Tresor        |          |     sentinelbit Extension (Manifest V3)    |
|   Master Password -> PBKDF2 100k   |          |  - Memory-Only Session (chrome.storage)    |
|   AES-256-GCM Verschlüsselung      |          |  - Background Worker: Ctrl+Shift+L Hotkey  |
+-----------------+------------------+          |  - Badge Counter & Auto-Lock Timer         |
                  |                             +---------------------+----------------------+
                  | (Nur Ciphertexts & Auth-Hash)                     |
                  +-------------------------+-------------------------+
                                            |
                                            v
+--------------------------------------------------------------------------------------------+
|                            sentinelbit Daemon (Go Server v3.0.0)                           |
|                                                                                            |
|  [Chi Router]       [CORS Middleware]       [Rate Limiter]       [TOTP Replay Guard]       |
|  [Security Headers] [Health /api/health]    [Ready /api/ready]   [Automated Sync & Backup] |
|         |                  |                      |                       |                |
|         +------------------+----------------------+-----------------------+                |
|                                            |                                               |
|                   [Pure-Go SQLite3 Engine (WAL Modus & Transaktionen)]                     |
|                                            |                                               |
|              [Rootless Alpine Container (UID 10001: sentinelbit:sentinelbit)]              |
+--------------------------------------------------------------------------------------------+
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
* 🔌 **Browser Extension (Manifest V3 - Bitwarden-Parität)**:
  * Chrome, Brave, Edge und Firefox kompatibel.
  * **In-Memory Session Security**: Keine Klartext-Passwörter auf der Festplatte; flüchtiger Arbeitsspeicher-Cache.
  * **Tastenkürzel `Ctrl+Shift+L`**: Sofortiges Ausfüllen der Logins auf Tastendruck.
  * **Badge-Counter**: Zeigt die Anzahl passender Logins für die aktive Domain direkt im Icon an.
  * **Auto-Lock Timer**: Sperrt den Tresor nach Inaktivität automatisch ab.
  * **Anti-Hidden-Trap Defense**: Verhindert das heimliche Ausfüllen unsichtbarer Phishing-Felder (`display: none`, `opacity: 0`, 1px-Traps oder Offscreen-Inputs).
* 📥 **Universeller Multi-Manager Importer**:
  * Nahtloser 1-Klick-Import aus **Bitwarden** (JSON/CSV), **1Password** (1PUX/CSV), **KeePassXC** (CSV), **LastPass** sowie **Google Chrome** & **Mozilla Firefox**.
* 🔄 **Automatisierter Backup & Sync-Dienst**:
  * Isolierte, benutzerspezifische Backups mit konfigurierbarer Dateirotation und Retention.
  * **Nativer Google Drive Cloud-Upload**: Automatischer Upload verschlüsselter Snapshots nach Google Drive (inkl. Cloud-Retention) ganz ohne Drittanbieter-Tools wie rclone.
* 🎭 **E-Mail-Maskierung ("Hide My Email")**:
  * Generiere auf Knopfdruck zufällige Relay-Aliase für Online-Registrierungen.
* 🤝 **Asymmetrisches E2E Tresor-Sharing**:
  * Teile Passwörter sicher Ende-zu-Ende verschlüsselt mit RSA-OAEP + AES-256-GCM.
* 🐳 **Rootless Container-Sicherheit**:
  * Docker-Image läuft standardmäßig als unprivilegierter Benutzer (`sentinelbit:sentinelbit`, UID 10001).

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

## 🔌 Browser-Erweiterung (Chrome Web Store & Lokal)

Die Erweiterung ist Manifest V3 konform und bietet dieselben Vorzüge wie Bitwarden (flüchtige In-Memory-Verschlüsselung, konfigurierbare Server-URL, Auto-Lock, Tastenkürzel und Badge-Counter):

* **Tastenkombination**: Drücke **`Ctrl+Shift+L`** (oder **`Cmd+Shift+L`** auf Mac) auf jeder Webseite, um passende Zugangsdaten sofort auszufüllen.
* **Auto-Lock**: Automatisches Sperren des Tresors nach einstellbarer Inaktivität (z.B. 15 Minuten).
* **Self-Hosting Konfiguration**: Über das Zahnrad-Symbol ⚙️ im Unlock-Fenster kann jede beliebige Instanz-URL (`https://...`) hinterlegt und getestet werden.

### Lokale Installation im Entwicklermodus:
1. Öffne in Chrome, Brave oder Edge die URL: `chrome://extensions/`
2. Aktiviere oben rechts den **Entwicklermodus** (*Developer mode*).
3. Klicke auf **Entpackte Erweiterung laden** (*Load unpacked*).
4. Wähle den Ordner `extension/` im Projektverzeichnis aus.

### Paket für den Google Chrome Web Store bauen:
```bash
make extension-zip     # Erstellt das fertige dist/sentinelbit-extension.zip
```
Siehe die vollständige [Chrome Web Store Anleitung (CHROME_STORE_GUIDE.md)](CHROME_STORE_GUIDE.md) für alle Einreichungs- und Review-Schritte.

---

## 🔒 Sicherheitsmerkmale

| Schutzmechanismus | Technische Umsetzung |
| :--- | :--- |
| **Kryptografie** | PBKDF2-HMAC-SHA256 (100k Iterationen), AES-256-GCM mit Random-IV |
| **Passkeys** | FIDO2 P-256 (ES256) ECDSA WebAuthn Hardware-Schlüssel |
| **Extension Storage** | In-Memory Session Storage (`chrome.storage.session`) – keine Passwörter auf Festplatte |
| **Brute-Force Schutz** | In-Memory Token-Bucket Rate Limiter (5 Versuche / 15 Min Block) |
| **Replay Schutz** | Time-based Sliding Window Guard für TOTP-Tokens (90s Drift) |
| **Anti-Enumeration** | Timing-sichere HMAC Dummy-Salts für unbekannte Benutzer |
| **CORS & Preflight** | Dedizierte Whitelist für Browser-Erweiterungen (`chrome-extension://*`) & Preflight-Handler |
| **Anti-Phishing Autofill** | DOM Bounding-Box, Opacity & Visibility Check gegen Trap-Inputs |
| **HTTP Hardening** | Strikte CSP, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` |
| **Container Hardening**| Rootless Alpine-Container unter unprivilegiertem System-User (`UID 10001`) |
| **Readiness & Health** | Separate Liveness- (`/api/health`) und Readiness-Probes (`/api/ready`) |

---

## 📚 Weiterführende Dokumentation

* 📖 **[REST API Spezifikation (API.md)](API.md)** – Vollständige Dokumentation aller HTTP-Endpunkte, Payloads und Error-Codes.
* 🏪 **[Chrome Web Store Guide (CHROME_STORE_GUIDE.md)](CHROME_STORE_GUIDE.md)** – Anleitung, Texte und Review-Begründungen für die Google Developer Console.
* 🛡️ **[Datenschutzerklärung (PRIVACY.md)](PRIVACY.md)** – Offizielle DSGVO- und Store-konforme Datenschutzerklärung.
* 🔌 **[Browser-Erweiterung Handbuch (extension/README.md)](extension/README.md)** – Technische Architektur und Entwickler-Dokumentation der Extension.

---

## 📄 Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).
