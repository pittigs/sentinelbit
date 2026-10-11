# 🛡️ Datenschutzerklärung / Privacy Policy – sentinelbit

**Stand / Last Updated:** Oktober 2026  
**Version:** 3.0.0  
**Geltungsbereich:** Web-Anwendung, Native Binaries, CLI & Google Chrome Browser-Erweiterung (*sentinelbit Password & Passkey Manager*)

---

## 1. Zero-Knowledge-Architektur & Grundsatz
**sentinelbit** wurde nach dem Prinzip der vollständigen **Zero-Knowledge-Kryptografie** und Datensparsamkeit entwickelt.
* Weder die Entwickler noch Dritte haben jemals Zugriff auf deine Passwörter, Notizen, 2FA-Codes, Passkeys oder deinen Master-Schlüssel.
* Sämtliche Verschlüsselungs- und Entschlüsselungsprozesse (AES-256-GCM, PBKDF2 / Web Crypto API) finden **ausschließlich lokal auf deinem Endgerät** statt.
* Der Server speichert und verarbeitet zu keinem Zeitpunkt Klartext-Geheimnisse.

---

## 2. Browser-Erweiterung (*sentinelbit Chrome Extension*)

### 2.1 Erhobene und verarbeitete Daten
Die Erweiterung verarbeitet Daten ausschließlich zur Erfüllung ihrer Kernfunktion:
* **Tresor-Einträge & Zugangsdaten:** Werden im flüchtigen Session-Speicher (`chrome.storage.session`) des Browsers vorgehalten, solange der Tresor entsperrt ist. Sie werden bei Inaktivität (Auto-Lock) oder beim Schließen des Browsers vollständig aus dem Speicher gelöscht.
* **Server-URL:** Die von dir konfigurierte Adresse deiner eigenen Server-Instanz (z. B. `http://127.0.0.1:8000` oder `https://vault.example.com`) wird lokal im Browserspeicher (`chrome.storage.local`) gesichert.
* **Keine Telemetrie / Kein Tracking:** Die Erweiterung enthält keinerlei Analyse-Tracker, Werbenetzwerke, externe Schriftarten oder Analyseskripte. Es werden keine Nutzungsstatistiken erhoben oder übertragen.

### 2.2 Berechtigungen und deren Zweck (Single Purpose Justification)
* `host_permissions: ["<all_urls>"]`: Erforderlich, um Login-Felder auf Webseiten zu erkennen und Zugangsdaten auf Anforderung des Nutzers sicher einzufügen (Autofill).
* `activeTab` & `tabs`: Ermöglicht das Ermitteln der aktuellen Domain, um passende Logins anzuzeigen und per Tastaturkürzel (`Ctrl+Shift+L`) einzufügen.
* `storage`: Speichert lokale Konfigurationen (z. B. Server-URL und Auto-Lock-Intervall) sowie die flüchtige Session.
* `alarms`: Steuert das zeitgesteuerte automatische Sperren des Tresors bei Inaktivität.
* `contextMenus`: Ermöglicht das Kontextmenü für schnelles Ausfüllen per Rechtsklick.

---

## 3. Server-Daemon & Self-Hosting
* **Verbindung:** Alle Anfragen der Clients erfolgen direkt an deine eigene sentinelbit-Instanz.
* **Audit-Logs & Backups:** Daten und Backups verbleiben auf deinem eigenen Server/Speichermedium und werden nicht an externe Cloud-Dienste weitergeleitet, sofern du dies nicht selbst konfigurierst.

---

## 4. Weitergabe von Daten an Dritte
Es erfolgt **keine Weitergabe, kein Verkauf und keine Übermittlung** personenbezogener Daten oder Zugangsdaten an Dritte.

---

## 5. Kontakt & Open Source
sentinelbit ist freie Open-Source-Software unter der MIT-Lizenz. Der Quellcode ist vollständig öffentlich einsehbar unter:
[https://github.com/pittigs/sentinelbit](https://github.com/pittigs/sentinelbit)
