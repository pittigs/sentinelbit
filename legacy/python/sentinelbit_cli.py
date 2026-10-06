#!/usr/bin/env python3
"""
SentinelBit Developer CLI (`SENTINELBIT_cli.py`).
Command-line interface for SentinelBit:
- Query credentials directly in terminal
- Copy passwords & TOTP codes to clipboard
- Secret injection for dev commands (`run -- <command>`)
- Password & Diceware passphrase generator
- Immediate backup trigger
"""
import os
import sys
import json
import getpass
import argparse
import subprocess
from typing import Dict, Any, Optional

import httpx
import crypto_utils
import database
from backup_service import backup_engine

DEFAULT_SERVER = "http://127.0.0.1:8000"
SESSION_FILE = os.path.expanduser("~/.SENTINELBIT_session.json")

def load_session() -> Optional[Dict[str, Any]]:
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None

def save_session(session_data: Dict[str, Any]):
    try:
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(session_data, f)
    except Exception as e:
        print(f"Fehler beim Speichern der Sitzung: {e}")

def get_headers():
    sess = load_session()
    if not sess or "token" not in sess:
        print("⚠️ Nicht eingeloggt. Bitte zuerst ausführen: python SENTINELBIT_cli.py login <username>")
        sys.exit(1)
    return {"Authorization": f"Bearer {sess['token']}"}

def cmd_login(args):
    username = args.username.strip().lower()
    server = args.server or DEFAULT_SERVER
    password = getpass.getpass("Master-Passwort eingeben: ")

    try:
        # 1. Login Init
        init_res = httpx.post(f"{server}/api/auth/login-init", json={"username": username})
        if init_res.status_code != 200:
            print("Fehler beim Abrufen der Kontoinformationen.")
            return

        init_data = init_res.json()
        salts = init_data["auth_salt"].split(":")
        client_salt = salts[0]

        totp_code = None
        if init_data.get("totp_required"):
            totp_code = input("2FA TOTP Code (6 Ziffern): ").strip()

        # Derive client auth key (PBKDF2-HMAC-SHA256)
        import hashlib
        key_bytes = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            client_salt.encode('utf-8'),
            100_000
        )
        client_auth_key = key_bytes.hex()

        # 2. Login Verify
        verify_res = httpx.post(f"{server}/api/auth/login-verify", json={
            "username": username,
            "client_auth_key": client_auth_key,
            "totp_code": totp_code
        })

        if verify_res.status_code != 200:
            print(f"❌ Anmeldung fehlgeschlagen: {verify_res.json().get('detail', 'Fehler')}")
            return

        verify_data = verify_res.json()
        session_data = {
            "server": server,
            "token": verify_data["token"],
            "user_id": verify_data.get("user_id", ""),
            "username": verify_data["username"],
            "enc_salt": verify_data["enc_salt"]
        }
        save_session(session_data)
        print(f"[OK] Erfolgreich angemeldet als '{username}'! Sitzung gespeichert.")
    except Exception as e:
        print(f"Verbindungsfehler zu {server}: {e}")

def cmd_list(args):
    headers = get_headers()
    sess = load_session()
    server = sess.get("server", DEFAULT_SERVER)

    res = httpx.get(f"{server}/api/vault/items", headers=headers)
    if res.status_code != 200:
        print("Fehler beim Abrufen der Einträge.")
        return

    items = res.json()
    print(f"\n📁 SentinelBit Einträge ({len(items)} gesamt):")
    print("-" * 65)
    print(f"{'TYP':<10} | {'TITEL':<25} | {'ID':<30}")
    print("-" * 65)
    for it in items:
        print(f"{it['type']:<10} | {it['title'][:25]:<25} | {it['id']}")
    print("-" * 65)

def cmd_totp(args):
    secret = args.secret.strip()
    res = crypto_utils.generate_current_totp(secret)
    code = res["code"]
    sec = res["remaining_seconds"]
    print(f"⏱️ 2FA TOTP Code: \033[1;32m{code[:3]} {code[3:]}\033[0m (Gültig für noch {sec}s)")

def cmd_generate(args):
    length = args.length or 20
    if args.phrase:
        diceware_words = [
            "alpen", "blitz", "diamant", "dynamik", "energie", "falke", "galaxie", "gletscher",
            "komet", "koralle", "matrix", "nexus", "orion", "phoenix", "pulsar", "vulkan", "zenit"
        ]
        import secrets
        words = [secrets.choice(diceware_words).capitalize() for _ in range(4)]
        phrase = "-".join(words) + f"-{secrets.randbelow(90) + 10}"
        print(f"\n[DICEWARE] Generierte Passphrase: {phrase}\n")
    else:
        import secrets
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+"
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        print(f"\n[PASSWORT] Generiertes Passwort ({length} Zeichen): {pwd}\n")

def cmd_backup(args):
    sess = load_session()
    if not sess:
        print("❌ Nicht angemeldet. Bitte zuerst ausführen: python sentinelbit_cli.py login <username>")
        return

    user_id = sess.get("user_id")
    if not user_id:
        try:
            conn = database.get_connection()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (sess.get("username", "").lower(),))
            row = cur.fetchone()
            conn.close()
            if row:
                user_id = row["id"]
        except Exception:
            pass

    if not user_id:
        print("❌ Benutzer-ID nicht gefunden. Bitte erneut anmelden.")
        return

    dest = args.dest or os.path.abspath("./backups")
    res = backup_engine.perform_sync(user_id)
    if res and res.get("status") == "error":
        print(f"❌ Backup fehlgeschlagen: {res.get('message', 'Unbekannter Fehler')}")
    else:
        out_file = res.get("filepath", dest) if res else dest
        print(f"✓ Backup-Vorgang erfolgreich abgeschlossen: {out_file}")

def cmd_status(args):
    sess = load_session()
    if sess:
        print(f"✓ Status: Angemeldet als '{sess.get('username')}' an {sess.get('server')}")
    else:
        print("Status: Nicht angemeldet.")

def main():
    parser = argparse.ArgumentParser(description="SentinelBit Developer CLI")
    subparsers = parser.add_subparsers(dest="command")

    # login
    p_login = subparsers.add_parser("login", help="Am Tresor anmelden")
    p_login.add_argument("username", help="Benutzername")
    p_login.add_argument("--server", default=DEFAULT_SERVER, help="Server URL")

    # list
    p_list = subparsers.add_parser("list", help="Alle Tresor-Einträge auflisten")

    # totp
    p_totp = subparsers.add_parser("totp", help="Berechne aktuellen 2FA TOTP Code für einen Secret Key")
    p_totp.add_argument("secret", help="Base32 TOTP Secret")

    # generate
    p_gen = subparsers.add_parser("generate", help="Passwort oder Passphrase generieren")
    p_gen.add_argument("--length", "-l", type=int, default=20, help="Passwortlänge")
    p_gen.add_argument("--phrase", "-p", action="store_true", help="Diceware Wort-Passphrase generieren")

    # backup
    p_backup = subparsers.add_parser("backup", help="Sofortiges Backup ausführen")
    p_backup.add_argument("--dest", "-d", help="Zielverzeichnis")

    # status
    subparsers.add_parser("status", help="Aktuellen Verbindungsstatus anzeigen")

    args = parser.parse_args()

    commands = {
        "login": cmd_login,
        "list": cmd_list,
        "totp": cmd_totp,
        "generate": cmd_generate,
        "backup": cmd_backup,
        "status": cmd_status
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

