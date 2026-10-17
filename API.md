# 📖 sentinelbit REST API Dokumentation (v3.0.0)

sentinelbit stellt eine schlanke, performante REST-Schnittstelle in **Go (Chi Router)** bereit.
Alle vertraulichen Tresor-Payloads werden **vor dem Senden clientseitig mit AES-256-GCM verschlüsselt** (Zero-Knowledge-Prinzip).

---

## 🌐 Basis-URL & Konventionen

* **Standard-Adresse:** `http://127.0.0.1:8000/api` (oder deine konfigurierte HTTPS-Domain)
* **Format:** `application/json` (Request & Response)
* **Authentifizierung:** Bearer-Token im HTTP-Header:
  ```http
  Authorization: Bearer <session-token-uuid>
  ```
* **CORS Support:** Vollständige Unterstützung für `chrome-extension://*`, `moz-extension://*` und Cross-Origin Preflight (`OPTIONS`).

---

## 🏥 1. System & Health Endpunkte

### `GET /api/health`
Prüft den allgemeinen Zustand des Dienstes.

* **Authentifizierung:** Keine erforderlich
* **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "service": "sentinelbit (Go)",
    "version": "3.0.0",
    "registration": "enabled"
  }
  ```

### `GET /api/ready`
Readiness-Probe zur Prüfung der SQLite-Datenbankkonnektivität (für Docker / Kubernetes / Healthchecks).

* **Authentifizierung:** Keine erforderlich
* **Response (200 OK):**
  ```json
  {
    "status": "ready",
    "database": "connected",
    "version": "3.0.0"
  }
  ```
* **Fehlerfall (503 Service Unavailable):** Wenn die Datenbank gesperrt oder nicht erreichbar ist.

---

## 🔐 2. Authentifizierung (`/api/auth`)

### `POST /api/auth/register`
Registriert ein neues Zero-Knowledge-Konto.

* **Payload:**
  ```json
  {
    "username": "alice",
    "auth_salt": "base64url-client-salt",
    "auth_hash": "64-char-hex-client-auth-key",
    "enc_salt": "base64url-enc-salt"
  }
  ```
* **Response (200 OK):** `{"status": "ok", "message": "Konto erfolgreich erstellt"}`
* **Response (403 Forbidden):** Wenn `SENTINELBIT_DISABLE_REGISTRATION=true`.

### `POST /api/auth/login-init`
Schritt 1 des Logins: Ruft die Salts des Kontos für die lokale PBKDF2-Schlüsselableitung ab.

* **Payload:**
  ```json
  {
    "username": "alice"
  }
  ```
* **Response (200 OK):**
  ```json
  {
    "auth_salt": "<client_salt>:<server_salt>",
    "enc_salt": "<enc_salt>",
    "totp_required": false
  }
  ```
  *(Bei unbekanntem Benutzer wird timing-sicher ein deterministischer Dummy-Salt zurückgegeben, um User-Enumeration zu verhindern).*

### `POST /api/auth/login-verify`
Schritt 2 des Logins: Prüft den abgeleiteten Auth-Hash und verifiziert optional 2FA/TOTP.

* **Payload:**
  ```json
  {
    "username": "alice",
    "client_auth_key": "64-char-hex-auth-key",
    "totp_code": "123456",
    "recovery_code": ""
  }
  ```
* **Response (200 OK):**
  ```json
  {
    "status": "ok",
    "token": "4e7c3b21-...",
    "user_id": "...",
    "username": "alice",
    "enc_salt": "...",
    "totp_enabled": true
  }
  ```
* **Fehler (401 Unauthorized / 429 Too Many Requests):** Bei falschem Passwort oder nach 5 Fehlversuchen (15 Min. IP+User-Sperre).

### `POST /api/auth/logout`
Invalidiert die aktive Sitzung serverseitig in RAM und SQLite.

* **Header:** `Authorization: Bearer <token>`
* **Response (200 OK):** `{"status": "ok"}`

### `GET /api/auth/me`
Gibt Informationen über den aktuell authentifizierten Benutzer zurück.

* **Header:** `Authorization: Bearer <token>`
* **Response (200 OK):**
  ```json
  {
    "user_id": "...",
    "username": "alice",
    "totp_enabled": true
  }
  ```

### `GET /api/auth/emergency-kit`
Erzeugt einen Notfall-Wiederherstellungs-Datensatz mit Tresor-Metadaten.

---

## ⏱️ 3. Zwei-Faktor-Authentifizierung (2FA TOTP)

| Methode | Pfad | Beschreibung |
| :--- | :--- | :--- |
| `POST` | `/api/auth/2fa/setup` | Erzeugt ein neues TOTP-Secret, QR-Code (Base64) und 8 Notfallcodes |
| `POST` | `/api/auth/2fa/verify` | Bestätigt den 6-stelligen Code und aktiviert 2FA für das Konto |
| `POST` | `/api/auth/2fa/disable` | Deaktiviert 2FA nach Validierung des aktuellen Codes |

---

## 🗄️ 4. Tresor-Einträge (`/api/vault`)

### `GET /api/vault/items`
Ruft alle aktiven Tresor-Einträge des Benutzers ab.

* **Response (200 OK):**
  ```json
  [
    {
      "id": "item-uuid-1",
      "type": "login",
      "title": "GitHub",
      "folder": "Entwicklung",
      "favorite": true,
      "encrypted_payload": "{\"iv\":\"...\",\"data\":\"...\"}",
      "created_at": "2026-10-11T10:00:00Z",
      "updated_at": "2026-10-11T10:00:00Z"
    }
  ]
  ```

### `POST /api/vault/items`
Erstellt einen neuen verschlüsselten Tresor-Eintrag.

* **Payload:**
  ```json
  {
    "type": "login",
    "title": "GitHub",
    "folder": "Entwicklung",
    "favorite": true,
    "encrypted_payload": "{\"iv\":\"...\",\"data\":\"...\"}"
  }
  ```

### `PUT /api/vault/items/{itemId}`
Aktualisiert einen bestehenden Eintrag (Titel, Ordner, Favoritenstatus oder Ciphertext).

### `DELETE /api/vault/items/{itemId}`
Verschiebt einen Eintrag in den Papierkorb (Soft-Delete via `deleted_at`).

### `POST /api/vault/items/{itemId}/restore`
Stellt einen gelöschten Eintrag aus dem Papierkorb wieder her.

### `GET /api/vault/trash`
Listet alle Einträge im Papierkorb auf.

### `DELETE /api/vault/trash`
Leert den Papierkorb endgültig (Hard-Delete).

---

## 🔑 5. Hardware Passkeys (`/api/passkeys`)

* **`POST /api/passkeys/generate`**: Erstellt Parameter für FIDO2 ES256 / P-256 Keypair Erstellung.
* **`GET /api/passkeys`**: Listet gespeicherte Passkey-Metadaten auf.
* **`POST /api/passkeys`**: Speichert einen neuen hardwaregestützten Passkey (verschlüsselter Private Key + COSE Public Key).
* **`DELETE /api/passkeys/{passkeyId}`**: Löscht einen hinterlegten Passkey.
* **`POST /api/passkeys/sign-test`**: Führt einen kryptografischen ECDSA Signaturtest im Browser durch.

---

## 🔄 6. Sync, E-Mail-Aliase & E2E-Sharing

### Automatisierte Backups
* `GET /api/sync/settings`: Backup-Pfad, Intervall und Rotationsregeln abrufen.
* `POST /api/sync/settings`: Einstellungen speichern (Intervall, Zielpfad, Retention).
* `POST /api/sync/now`: Sofortigen Zero-Knowledge Backup-Export anstoßen.

### E-Mail-Maskierung ("Hide My Email")
* `GET /api/aliases`: Alle aktiven Relay-Aliase abrufen.
* `POST /api/aliases`: Neuen Zufalls-Alias erzeugen.
* `DELETE /api/aliases/{aliasId}`: Alias entfernen.

### Asymmetrisches Tresor-Sharing (RSA-OAEP)
* `POST /api/share/public-key`: Öffentlichen RSA-Key des Nutzers für Empfang registrieren.
* `GET /api/share/user/{targetUsername}/public-key`: Empfänger-Key abrufen.
* `POST /api/share/send`: Asymmetrisch verschlüsseltes Passwort an anderen Nutzer senden.
* `GET /api/share/inbox`: Erhaltene geteilte Einträge abrufen.
* `DELETE /api/share/inbox/{itemId}`: Empfangenen Eintrag ablehnen/löschen.

---

## 🛡️ Bitwarden-Kompatibilität (`/identity` & `/api`)

SentinelBit implementiert die standardmäßige Bitwarden Sync- & Authentifizierungs-API. Dadurch können offizielle Bitwarden-Clients (Browser Extensions, Mobile & Desktop Apps, CLI `bw`) direkt angebunden werden:

* `GET /api/config`: Server-Konfiguration & Feature-Flags für Bitwarden-Clients.
* `POST /api/accounts/prelogin`: KDF-Parameter (PBKDF2-SHA256, 600.000 Runden).
* `POST /api/accounts/register`: Erstellung eines Kontos mit Bitwarden-Schlüsselbund.
* `POST /identity/connect/token`: OAuth2 Resource Owner Password Credentials Grant mit optionaler TOTP 2FA.
* `GET /api/accounts/profile`: Benutzerprofil & verschlüsselte Master-Keys.
* `GET /api/sync`: Vollständige Synchronisation aller Ciphers, Folders & Domains.
* `GET, POST, PUT, DELETE /api/ciphers`: Verwaltung von Logins, Notizen, Karten & Identitäten.
* `GET, POST, PUT, DELETE /api/folders`: Verwaltung von Bitwarden-Ordnern.
* `GET /notifications/hub`: WebSocket / Long-Polling Fallback.

---

## 🛡️ Sicherheits-Header der API

Jede Antwort enthält strikte Sicherheits-Header:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy: default-src 'self'; ...
Strict-Transport-Security: max-age=31536000; includeSubDomains (bei HTTPS)
```
