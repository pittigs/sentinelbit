# 🔌 sentinelbit Browser Extension (v3.0.0)

Offizielle Browser-Erweiterung für den **sentinelbit** Zero-Knowledge Passwort- & Passkey-Manager.
Entwickelt für **Google Chrome, Brave, Microsoft Edge und Mozilla Firefox** auf Basis von **Manifest V3**.

---

## ✨ Highlights & Features

* 🔒 **Zero-Knowledge In-Memory Security**:
  * Entschlüsselte Zugangsdaten liegen **nur im flüchtigen Session-Speicher** (`chrome.storage.session`) im Arbeitsspeicher.
  * **Keine Passwörter im Klartext auf der Festplatte** (`chrome.storage.local` speichert ausschließlich sichere Verbindungseinstellungen).
* ⚡ **Instant Autofill via Hotkey**:
  * Drücke **`Ctrl+Shift+L`** (oder **`Cmd+Shift+L`** auf macOS), um passende Zugangsdaten auf jeder Webseite blitzschnell und ohne Mausklick einzufügen.
* 🏷️ **Domain Badge-Counter**:
  * Zeigt direkt auf dem Erweiterungs-Symbol in der Browserleiste an, wie viele Logins für die aktive Website gespeichert sind (z. B. `1` oder `2`).
* ⏱️ **Auto-Lock Timer**:
  * Schützt deine Daten durch automatisches Sperren nach einer konfigurierbaren Inaktivitätszeit (5, 15, 30 oder 60 Minuten).
* ⚙️ **Self-Hosting Konfiguration (wie Bitwarden)**:
  * Über das Zahnrad-Symbol ⚙️ im Unlock-Fenster kann jede beliebige Instanz-URL (`https://vault.meinedomain.de` oder lokales LAN) eingetragen und mit dem **"📶 Verbindung prüfen"**-Button getestet werden.
* 🖱️ **Kontextmenü-Integration**:
  * Rechtsklick auf beliebige Eingabefelder ➔ *sentinelbit* ➔ *⚡ Zugangsdaten ausfüllen*.
* 🛡️ **Anti-Phishing Schutz**:
  * Ignoriert unsichtbare Phishing-Fallen, verdeckte 1px-Inputs und Offscreen-Honeypots.

---

## 🛠️ Architektur der Erweiterung

```
+---------------------------------------------------------------------------------+
|                        sentinelbit Browser Extension (MV3)                      |
|                                                                                 |
|  [popup.html / popup.js]  <--- chrome.storage.session --->  [background.js]     |
|   - Master Password Login                                  (Service Worker)     |
|   - 2FA / TOTP Eingabe                                      - Hotkey Ctrl+Shift+L|
|   - Server-URL Settings                                     - Badge Counter     |
|   - Password Generator                                      - Auto-Lock Alarm   |
|            |                                                - Context Menus     |
|            | (Runtime Messaging: AUTOFILL)                         |            |
|            +-----------------------+-------------------------------+            |
|                                    |                                            |
|                                    v                                            |
|                          [content.js (DOM-Engine)]                              |
|                           - Form & Field Pairing                                |
|                           - Shadow DOM Traversal                                |
|                           - React/Vue Synthetic Events                          |
+------------------------------------+--------------------------------------------+
                                     | HTTP/REST (Zero-Knowledge Ciphertexts)
                                     v
                 [sentinelbit Go Server (http://127.0.0.1:8000)]
```

---

## 🚀 Lokale Installation (Entwicklermodus)

1. Öffne im Chromium-basierten Browser deiner Wahl:
   * **Google Chrome:** `chrome://extensions/`
   * **Brave:** `brave://extensions/`
   * **Microsoft Edge:** `edge://extensions/`
2. Aktiviere oben rechts den Schalter **"Entwicklermodus"** (*Developer mode*).
3. Klicke auf die Schaltfläche **"Entpackte Erweiterung laden"** (*Load unpacked*).
4. Wähle den Ordner `extension/` im sentinelbit-Verzeichnis aus.
5. Die Erweiterung ist sofort aktiv und einsatzbereit!

---

## 📦 Veröffentlichung im Chrome Web Store

Das fertige Paket für den Upload in das Google Developer Dashboard lässt sich mit einem einzigen Befehl im Hauptverzeichnis erstellen:

```bash
make extension-zip
```

Dies erzeugt die bereinigte Datei `dist/sentinelbit-extension.zip`.

Eine vollständige Anleitung mit allen Copy-Paste-Texten und Google-Review-Begründungen findest du im Hauptverzeichnis unter [CHROME_STORE_GUIDE.md](../CHROME_STORE_GUIDE.md).
