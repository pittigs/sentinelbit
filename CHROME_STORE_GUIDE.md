# 🏪 Google Chrome Web Store – Einreichungs- & Veröffentlichungsleitfaden

Dieser Leitfaden enthält alle fertigen Vorlagen, Beschreibungen und Checklisten, um die **sentinelbit** Browser-Erweiterung wie Bitwarden im Google Chrome Web Store zu veröffentlichen.

---

## 1. Vorbereitete Store-Texte (Copy & Paste)

### 🇩🇪 Deutsch (Primäre Sprache)

* **Titel der Erweiterung:**
  `sentinelbit Password & Passkey Manager`

* **Kurzbeschreibung (Maximal 132 Zeichen):**
  `Zero-Knowledge Autofill, Passkeys und 2FA-Codes für deine selbstgehostete sentinelbit Instanz.`

* **Ausführliche Beschreibung:**
  ```markdown
  sentinelbit ist ein hochmoderner, sicherer und privatsphärefreundlicher Zero-Knowledge Passwort- & Passkey-Manager für deine selbstgehostete sentinelbit-Instanz.

  🔒 ZERO-KNOWLEDGE SICHERHEIT
  Deine Daten gehören dir. Sämtliche Entschlüsselungsprozesse (AES-256-GCM, PBKDF2) finden ausschließlich lokal in deinem Browser statt. Dein Master-Passwort und deine Zugangsdaten verlassen dein Gerät niemals unverschlüsselt.

  ⚡ BLITZSCHNELLES AUTOFILL
  - Fülle Benutzernamen, Passwörter und TOTP-Tokens automatisch mit 1 Klick oder via Tastenkombination (Ctrl+Shift+L) aus.
  - Erkennt moderne Web-Formulare (Vanilla HTML, React, Vue, Angular und Shadow DOM).
  - Anti-Phishing Schutz: Verhindert das Ausfüllen verdeckter 1px-Traps und Honeypot-Felder.

  🔑 FIDO2 / WEBAUTHN PASSKEYS
  - Verwalte und signiere moderne FIDO2 Passkeys für passwortlose Anmeldungen.

  ⏱️ INTEGRIERTER 2FA AUTHENTICATOR
  - Generiert 6-stellige TOTP-Sicherheitscodes direkt im Browser mit 1-Klick-Kopieren.

  🎲 PASSWORT-GENERATOR
  - Erstelle hochkomplexe, kryptografisch sichere Zufallspasswörter direkt im Popup.

  🌐 SELF-HOSTING FREIHEIT
  - Verbinde dich nahtlos mit deiner lokalen Instanz (Raspberry Pi, Docker, Heimserver oder eigener Domain).
  - Einstellbare Server-URL mit Live-Verbindungstest und konfigurierbarem Auto-Lock.

  100% Open Source unter MIT-Lizenz: https://github.com/pittigs/sentinelbit
  ```

---

### 🇬🇧 English (Zweitsprache)

* **Title:**
  `sentinelbit Password & Passkey Manager`

* **Short Description (Max 132 chars):**
  `Zero-knowledge autofill, passkeys, and 2FA authentication for your self-hosted sentinelbit vault.`

* **Detailed Description:**
  ```markdown
  sentinelbit is a modern, privacy-first zero-knowledge password and passkey manager designed for your self-hosted sentinelbit instance.

  🔒 ZERO-KNOWLEDGE SECURITY
  All cryptography (AES-256-GCM, PBKDF2) executes locally in your browser. Neither servers nor third parties can read your plaintext credentials.

  ⚡ FAST & SAFE AUTOFILL
  - 1-click autofill or instant keyboard shortcut (Ctrl+Shift+L / Cmd+Shift+L on Mac).
  - Anti-phishing protection against hidden honeypots and 1px trap inputs.
  - Works with modern web frameworks (React, Vue, Angular, Shadow DOM).

  🔑 PASSKEY & 2FA READY
  - Integrated TOTP authenticator code generation.
  - FIDO2 / WebAuthn passkey management.

  🌐 SELF-HOSTED FRIENDLY
  - Connect easily to your Docker, Raspberry Pi, or custom domain instance.
  ```

---

## 2. Antworten für das Google Review-Formular (Datenschutz & Berechtigungen)

Google fragt bei der Einreichung nach dem Zweck jeder Berechtigung. Nutze diese offiziell konformen Texte:

### Single Purpose Description (Zweck der Erweiterung):
> *"sentinelbit provides secure, zero-knowledge credential management, autofilling saved logins and 2FA tokens into web forms from the user's self-hosted vault."*

### Permission Justification (Berechtigungsbegründungen):
* **`<all_urls>`:**
  > *"Required to detect login input fields and inject user-approved credentials across websites saved in the user's vault."*
* **`activeTab` & `tabs`:**
  > *"Used to read the current tab's domain to filter matching credentials and provide instant autofill via keyboard shortcut."*
* **`storage`:**
  > *"Stores the user's self-hosted server URL and non-sensitive vault preferences locally, and holds session items in memory while unlocked."*
* **`alarms`:**
  > *"Triggers the automatic vault lock timer after inactivity to protect user data."*
* **`contextMenus`:**
  > *"Adds right-click shortcuts for inserting credentials and generating secure passwords."*

### Host Permissions Justification:
> *"The extension acts as a password manager. It needs access to web pages to locate login fields and autofill credentials upon user interaction."*

---

## 3. Asset-Checkliste

| Asset | Format | Status |
| :--- | :--- | :--- |
| `icon16.png` | 16x16 PNG | Vorhanden in `extension/` |
| `icon48.png` | 48x48 PNG | Vorhanden in `extension/` |
| `icon128.png` | 128x128 PNG | Vorhanden in `extension/` |
| **Store Kachel** | 440x280 PNG | Erstellen (Logo + Slogan) |
| **Screenshots** | 1280x800 PNG | Mindestens 1 Screenshot (empfohlen 3-4) |
| **Datenschutz** | URL | `https://github.com/pittigs/sentinelbit/blob/master/PRIVACY.md` |

---

## 4. Build & Upload Workflow

1. Baue das saubere Store-Zip:
   ```bash
   make extension-zip
   ```
   Ergebnis: `dist/sentinelbit-extension.zip`

2. Öffne die [Chrome Web Store Developer Console](https://chrome.google.com/webstore/devconsole).
3. Klicke auf **Neues Element** und lade `dist/sentinelbit-extension.zip` hoch.
4. Fülle die Store-Texte und Datenschutzangaben anhand dieses Leitfadens aus.
5. Reiche die Erweiterung zur Prüfung ein.
