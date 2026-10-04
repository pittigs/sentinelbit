"""
Automated Recurring Backup & Sync Service for SentinelBit.
Periodically exports encrypted vault snapshots to user-configured directories
(e.g., local folders, external USB drives, cloud/network shares).
Supports auto-sync on change and retention rotation.
"""
import os
import json
import time
import uuid
import glob
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

import database
import security

class BackupSyncEngine:
    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="SentinelBitBackupWorker")
        self._thread.start()
        print("[OK] SentinelBit Automatischer Backup- & Sync-Dienst gestartet.")

    def stop(self):
        self._running = False

    def _worker_loop(self):
        while self._running:
            try:
                self.check_and_run_due_syncs()
            except Exception as e:
                print(f"[BackupService] Fehler im Worker-Loop: {e}")
            time.sleep(30) # Check every 30 seconds

    def check_and_run_due_syncs(self):
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM backup_sync_settings WHERE is_active = 1")
        settings_list = cursor.fetchall()
        conn.close()

        now = datetime.now(timezone.utc)
        for s in settings_list:
            last_sync_str = s["last_synced_at"]
            interval_mins = s["interval_minutes"] or 15
            
            is_due = False
            if not last_sync_str:
                is_due = True
            else:
                try:
                    last_sync = datetime.fromisoformat(last_sync_str)
                    elapsed_seconds = (now - last_sync).total_seconds()
                    if elapsed_seconds >= (interval_mins * 60):
                        is_due = True
                except Exception:
                    is_due = True
            
            if is_due:
                self.perform_sync(s["user_id"])

    def perform_sync(self, user_id: str) -> Dict[str, Any]:
        """Perform encrypted backup export for a specific user to target directory."""
        conn = database.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM backup_sync_settings WHERE user_id = ?", (user_id,))
        settings = cursor.fetchone()
        if not settings:
            conn.close()
            return {"status": "error", "message": "Keine Sync-Einstellungen vorhanden"}

        try:
            target_dir = security.validate_backup_dir(settings["target_dir"])
        except Exception as e:
            conn.close()
            return {"status": "error", "message": f"Ungültiges Backup-Verzeichnis: {e}"}

        retention = max(1, min(settings["retention_count"] or 10, 100))

        # Fetch user info
        cursor.execute("SELECT username, enc_salt FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        if not user_row:
            conn.close()
            return {"status": "error", "message": "Benutzer nicht gefunden"}

        username = user_row["username"]
        safe_username = security.safe_filename_component(username)

        # Fetch active vault items
        cursor.execute("""
        SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
        FROM vault_items WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')
        """, (user_id,))
        items = [dict(r) for r in cursor.fetchall()]

        # Fetch passkeys
        cursor.execute("SELECT * FROM passkeys WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')", (user_id,))
        passkeys = [dict(r) for r in cursor.fetchall()]

        # Fetch aliases
        cursor.execute("SELECT * FROM email_aliases WHERE user_id = ?", (user_id,))
        aliases = [dict(r) for r in cursor.fetchall()]

        conn.close()

        now_iso = datetime.now(timezone.utc).isoformat()
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_payload = {
            "version": 2,
            "type": "SentinelBit_automated_encrypted_sync",
            "created_at": now_iso,
            "username": username,
            "enc_salt": user_row["enc_salt"],
            "items_count": len(items),
            "passkeys_count": len(passkeys),
            "items": items,
            "passkeys": passkeys,
            "email_aliases": aliases
        }

        try:
            # Ensure target directory exists
            os.makedirs(target_dir, exist_ok=True)

            # File names
            filename = f"SentinelBit_backup_{safe_username}_{timestamp_str}.json"
            filepath = os.path.join(target_dir, filename)

            # Latest copy
            latest_filepath = os.path.join(target_dir, f"SentinelBit_backup_{safe_username}_latest.json")

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(backup_payload, f, indent=2)

            with open(latest_filepath, "w", encoding="utf-8") as f:
                json.dump(backup_payload, f, indent=2)

            # Retention rotation: Keep only last N backups matching pattern
            pattern = os.path.join(target_dir, f"SentinelBit_backup_{safe_username}_*.json")
            all_backups = glob.glob(pattern)
            # Filter out the _latest file from deletion
            all_backups = [b for b in all_backups if "_latest.json" not in b]
            all_backups.sort(key=os.path.getmtime, reverse=True)

            if len(all_backups) > retention:
                for old_file in all_backups[retention:]:
                    try:
                        os.remove(old_file)
                    except Exception:
                        pass

            # Update DB settings status
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE backup_sync_settings 
            SET last_synced_at = ?, last_sync_status = 'Erfolgreich' 
            WHERE user_id = ?
            """, (now_iso, user_id))
            conn.commit()
            conn.close()

            return {
                "status": "ok",
                "message": f"Backup erfolgreich nach {filepath} exportiert",
                "synced_at": now_iso,
                "items_count": len(items),
                "filepath": filepath
            }
        except Exception as e:
            err_msg = f"Fehler beim Schreiben des Backups: {str(e)}"
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE backup_sync_settings 
            SET last_sync_status = ? 
            WHERE user_id = ?
            """, (err_msg, user_id))
            conn.commit()
            conn.close()
            return {"status": "error", "message": err_msg}

    def trigger_on_change(self, user_id: str):
        """Called automatically when an item is created/updated/deleted."""
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT sync_on_change, is_active FROM backup_sync_settings WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        if row and row["is_active"] and row["sync_on_change"]:
            # Run sync in thread so API call is not delayed
            threading.Thread(target=self.perform_sync, args=(user_id,), daemon=True).start()

# Global engine singleton
backup_engine = BackupSyncEngine()

