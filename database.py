"""
Database layer for SentinelBit Password Manager.
Uses SQLite to store users and encrypted vault items.
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

DATA_DIR = os.getenv("SENTINELBIT_DATA_DIR", os.path.dirname(__file__))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "vault.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Users table: stores user auth hash, salt, and 2FA secrets
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        auth_salt TEXT NOT NULL,
        auth_hash TEXT NOT NULL,
        enc_salt TEXT NOT NULL,
        totp_secret TEXT,
        totp_enabled INTEGER DEFAULT 0,
        recovery_codes TEXT,
        created_at TEXT NOT NULL
    )
    """)
    
    # Vault items table: stores encrypted data
    # encrypted_payload is client-side encrypted JSON with AES-256-GCM
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_items (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL, -- 'login', 'passkey', 'note', 'card'
        title TEXT NOT NULL,
        folder TEXT DEFAULT '',
        favorite INTEGER DEFAULT 0,
        encrypted_payload TEXT NOT NULL, -- AES-GCM ciphertext + IV + auth tag
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        deleted_at TEXT DEFAULT NULL, -- Soft delete timestamp for Trash
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    
    # Biometric / WebAuthn credentials for device unlock
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS webauthn_unlock_keys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        credential_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        device_name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    
    # Passkeys table (can be linked to a vault item or standalone)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        vault_item_id TEXT,
        rp_id TEXT NOT NULL,
        rp_name TEXT NOT NULL,
        username TEXT NOT NULL,
        user_handle TEXT,
        credential_id TEXT NOT NULL,
        encrypted_private_key TEXT NOT NULL,
        public_key_cose TEXT NOT NULL,
        public_key_pem TEXT,
        sign_count INTEGER DEFAULT 0,
        transports TEXT,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        deleted_at TEXT DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    
    # Backup & Sync configuration table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS backup_sync_settings (
        id TEXT PRIMARY KEY,
        user_id TEXT UNIQUE NOT NULL,
        target_dir TEXT NOT NULL,
        interval_minutes INTEGER DEFAULT 15,
        sync_on_change INTEGER DEFAULT 1,
        retention_count INTEGER DEFAULT 10,
        is_active INTEGER DEFAULT 1,
        last_synced_at TEXT,
        last_sync_status TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Sharing: Public keys for end-to-end encryption between users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_sharing_keys (
        user_id TEXT PRIMARY KEY,
        public_key_pem TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Shared vault items (encrypted with recipient's public key)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS shared_items (
        id TEXT PRIMARY KEY,
        sender_id TEXT NOT NULL,
        recipient_username TEXT NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        encrypted_payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Masked Email Aliases
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email_aliases (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        alias_email TEXT NOT NULL,
        service_name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Auto-migration for existing databases
    cursor.execute("PRAGMA table_info(vault_items)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "deleted_at" not in columns:
        cursor.execute("ALTER TABLE vault_items ADD COLUMN deleted_at TEXT DEFAULT NULL")

    cursor.execute("PRAGMA table_info(passkeys)")
    pk_columns = [row["name"] for row in cursor.fetchall()]
    if "deleted_at" not in pk_columns:
        cursor.execute("ALTER TABLE passkeys ADD COLUMN deleted_at TEXT DEFAULT NULL")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")

