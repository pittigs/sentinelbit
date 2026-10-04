"""
FastAPI Server for SentinelBit Password Manager.
Serves API endpoints and frontend single-page application.
"""
import os
import re
import time
import uuid
import json
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, Header, Depends, Request, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import database
import crypto_utils
import security
from models import (
    RegisterRequest,
    LoginInitRequest,
    LoginInitResponse,
    LoginVerifyRequest,
    LoginResponse,
    TotpSetupResponse,
    TotpVerifyRequest,
    TotpDisableRequest,
    VaultItemCreate,
    VaultItemUpdate,
    VaultItemResponse,
    PasskeyGenerateRequest,
    PasskeySaveRequest,
    PasskeySignTestRequest,
    TotpComputeRequest,
    WebAuthnKeyRegisterRequest,
    BackupSyncSettingsModel,
    EmailAliasCreate,
    ShareItemSendRequest,
    SharingPublicKeyRegister
)
from backup_service import backup_engine

database.init_db()
backup_engine.start()

app = FastAPI(title="SentinelBit API", version="1.0.0")

# CORS: only explicitly allowed origins (frontend is served same-origin, so this is rarely needed).
# Configure via SENTINELBIT_ALLOWED_ORIGINS="https://vault.example.com,http://127.0.0.1:8000"
ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv(
        "SENTINELBIT_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000"
    ).split(",") if o.strip() and o.strip() != "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,  # Auth uses Authorization: Bearer headers, not cookies
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(security.SecurityHeadersMiddleware)

# In-memory sessions: token -> {user_id, username, expires_at}
SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSION_TTL_SECONDS = int(os.getenv("SENTINELBIT_SESSION_TTL_HOURS", "12")) * 3600


def _purge_expired_sessions() -> None:
    now = time.time()
    for tok in [t for t, s in SESSIONS.items() if s.get("expires_at", 0) <= now]:
        SESSIONS.pop(tok, None)


def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Nicht authentifiziert")
    token = authorization.split(" ", 1)[1].strip()
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sitzung abgelaufen oder ungültig")
    if session.get("expires_at", 0) <= time.time():
        SESSIONS.pop(token, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sitzung abgelaufen. Bitte erneut anmelden.")
    return session

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "SentinelBit", "version": "1.0.0"}

# -------------------------------------------------------------
# Auth Endpoints
# -------------------------------------------------------------

HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@app.post("/api/auth/register")
def register(req: RegisterRequest):
    username = security.validate_username(req.username)
    if not HEX_64_RE.match(req.auth_hash or ""):
        raise HTTPException(status_code=400, detail="Ungültiges Auth-Key-Format")
    if not req.auth_salt or ":" in req.auth_salt or len(req.auth_salt) > 128 or not req.enc_salt or len(req.enc_salt) > 128:
        raise HTTPException(status_code=400, detail="Ungültiges Salt-Format")

    conn = database.get_connection()
    cursor = conn.cursor()
    
    # Check if user already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Benutzername existiert bereits")
    
    user_id = str(uuid.uuid4())
    # Hash client's auth key with server salt
    server_salt = crypto_utils.generate_salt()
    final_auth_hash = crypto_utils.hash_auth_key(req.auth_hash, server_salt)
    
    now = datetime.now(timezone.utc).isoformat()
    # auth_salt stores "client_salt:server_salt"
    combined_auth_salt = f"{req.auth_salt}:{server_salt}"
    
    cursor.execute("""
    INSERT INTO users (id, username, auth_salt, auth_hash, enc_salt, totp_secret, totp_enabled, created_at)
    VALUES (?, ?, ?, ?, ?, NULL, 0, ?)
    """, (user_id, username, combined_auth_salt, final_auth_hash, req.enc_salt, now))
    
    conn.commit()
    conn.close()
    
    return {"status": "ok", "message": "Konto erfolgreich erstellt"}

def _load_server_secret() -> bytes:
    """Persistent server secret used for deterministic dummy salts (anti user-enumeration)."""
    path = os.path.join(database.DATA_DIR, ".server_secret")
    try:
        with open(path, "rb") as f:
            data = f.read()
            if len(data) >= 32:
                return data
    except FileNotFoundError:
        pass
    data = secrets.token_bytes(32)
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return data


SERVER_SECRET = _load_server_secret()
_DUMMY_AUTH_HASH = crypto_utils.hash_auth_key("00" * 32, "dummy-salt")


def _dummy_salts(username: str):
    import hmac, hashlib, base64
    digest = hmac.new(SERVER_SECRET, username.encode("utf-8"), hashlib.sha256).digest()
    digest2 = hmac.new(SERVER_SECRET, b"srv:" + username.encode("utf-8"), hashlib.sha256).digest()
    digest3 = hmac.new(SERVER_SECRET, b"enc:" + username.encode("utf-8"), hashlib.sha256).digest()
    client_salt = digest[:16].hex()
    server_salt = base64.urlsafe_b64encode(digest2).decode("utf-8")
    enc_salt = digest3[:16].hex()
    return f"{client_salt}:{server_salt}", enc_salt


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.post("/api/auth/login-init", response_model=LoginInitResponse)
def login_init(req: LoginInitRequest):
    username = (req.username or "").strip().lower()
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT auth_salt, enc_salt FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        # Deterministic dummy salts: identical on every request -> indistinguishable from real users
        auth_salt, enc_salt = _dummy_salts(username)
        return LoginInitResponse(auth_salt=auth_salt, enc_salt=enc_salt, totp_required=False)
    
    # 2FA status is intentionally NOT revealed before the password was verified.
    # The client is told via HTTP 403 from /login-verify when a 2FA code is required.
    return LoginInitResponse(
        auth_salt=row["auth_salt"],
        enc_salt=row["enc_salt"],
        totp_required=False
    )

@app.post("/api/auth/login-verify", response_model=LoginResponse)
def login_verify(req: LoginVerifyRequest, request: Request):
    username = (req.username or "").strip().lower()
    ip_key = f"ip:{_client_ip(request)}"
    user_key = f"user:{username}"
    security.login_limiter_user.check(user_key)
    security.login_limiter_ip.check(ip_key)

    def fail(status_code: int, detail: str):
        security.login_limiter_user.fail(user_key)
        security.login_limiter_ip.fail(ip_key)
        raise HTTPException(status_code=status_code, detail=detail)

    if not HEX_64_RE.match(req.client_auth_key or ""):
        fail(401, "Ungültiger Benutzername oder Passwort")

    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, username, auth_salt, auth_hash, enc_salt, totp_secret, totp_enabled, recovery_codes 
    FROM users WHERE username = ?
    """, (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        # Do the same PBKDF2 work as for real users (prevents timing-based user enumeration)
        crypto_utils.verify_auth_key(req.client_auth_key, "dummy-salt", _DUMMY_AUTH_HASH)
        fail(401, "Ungültiger Benutzername oder Passwort")
    
    salts = user["auth_salt"].split(":")
    if len(salts) != 2:
        raise HTTPException(status_code=500, detail="Ungültiges Salt-Format im Server")
    server_salt = salts[1]
    
    # Verify auth hash
    if not crypto_utils.verify_auth_key(req.client_auth_key, server_salt, user["auth_hash"]):
        fail(401, "Ungültiger Benutzername oder Passwort")
    
    # Verify 2FA if enabled
    if user["totp_enabled"]:
        if not req.totp_code and not req.recovery_code:
            # Password correct, 2FA code missing -> tell client to ask for it (not counted as failure)
            raise HTTPException(status_code=403, detail="2FA_REQUIRED")

        verified = False
        if req.totp_code and crypto_utils.verify_totp_code(user["totp_secret"], req.totp_code):
            verified = security.totp_replay_guard.consume(user["id"], req.totp_code)
        elif req.recovery_code and user["recovery_codes"]:
            import hmac
            codes = json.loads(user["recovery_codes"])
            rec_code_clean = req.recovery_code.strip().upper()
            match = next((c for c in codes if hmac.compare_digest(c, rec_code_clean)), None)
            if match:
                codes.remove(match)
                verified = True
                conn = database.get_connection()
                conn.cursor().execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (json.dumps(codes), user["id"]))
                conn.commit()
                conn.close()
        
        if not verified:
            fail(403, "2FA-Code (TOTP) oder Wiederherstellungscode ungültig")
    
    security.login_limiter_user.reset(user_key)

    # Generate session token with absolute expiry
    _purge_expired_sessions()
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "user_id": user["id"],
        "username": user["username"],
        "expires_at": time.time() + SESSION_TTL_SECONDS
    }
    
    return LoginResponse(
        token=token,
        username=user["username"],
        enc_salt=user["enc_salt"],
        totp_enabled=bool(user["totp_enabled"])
    )

@app.get("/api/auth/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, enc_salt, totp_enabled, created_at FROM users WHERE id = ?", (user["user_id"],))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")
    
    return {
        "user_id": user["user_id"],
        "username": row["username"],
        "enc_salt": row["enc_salt"],
        "totp_enabled": bool(row["totp_enabled"]),
        "created_at": row["created_at"]
    }

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        SESSIONS.pop(token, None)
    return {"status": "ok"}

# -------------------------------------------------------------
# 2FA (TOTP) Setup Endpoints
# -------------------------------------------------------------

@app.post("/api/auth/2fa/setup", response_model=TotpSetupResponse)
def setup_2fa(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT totp_enabled FROM users WHERE id = ?", (user["user_id"],))
    row = cursor.fetchone()
    if row and row["totp_enabled"]:
        # Prevent silently replacing an active 2FA secret with a stolen session
        conn.close()
        raise HTTPException(status_code=409, detail="2FA ist bereits aktiv. Bitte zuerst deaktivieren.")

    secret = crypto_utils.generate_totp_secret()
    uri = crypto_utils.get_totp_uri(secret, user["username"])
    qr_b64 = crypto_utils.generate_totp_qr_base64(uri)
    
    # Store pending secret (only activated after successful verification)
    cursor.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["user_id"]))
    conn.commit()
    conn.close()
    
    return TotpSetupResponse(
        secret=secret,
        qr_code_base64=qr_b64,
        provisioning_uri=uri
    )

@app.post("/api/auth/2fa/verify")
def verify_and_enable_2fa(req: TotpVerifyRequest, user: Dict[str, Any] = Depends(get_current_user)):
    limiter_key = f"totp:{user['user_id']}"
    security.totp_limiter.check(limiter_key)

    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret, totp_enabled FROM users WHERE id = ?", (user["user_id"],))
    row = cursor.fetchone()
    
    if not row or not row["totp_secret"]:
        conn.close()
        raise HTTPException(status_code=400, detail="2FA-Einrichtung wurde nicht initialisiert")
    if row["totp_enabled"]:
        conn.close()
        raise HTTPException(status_code=409, detail="2FA ist bereits aktiv")
    
    secret = row["totp_secret"]
    if not crypto_utils.verify_totp_code(secret, req.code) or not security.totp_replay_guard.consume(user["user_id"], req.code):
        conn.close()
        security.totp_limiter.fail(limiter_key)
        raise HTTPException(status_code=400, detail="Ungültiger 2FA-Code. Bitte die Uhrzeit deines Geräts prüfen.")
    security.totp_limiter.reset(limiter_key)
    
    # Generate 5 recovery codes
    recovery_codes = [secrets.token_hex(4).upper() for _ in range(5)]
    cursor.execute("UPDATE users SET totp_enabled = 1, recovery_codes = ? WHERE id = ?", (json.dumps(recovery_codes), user["user_id"]))
    conn.commit()
    conn.close()
    
    return {
        "status": "ok",
        "message": "2FA erfolgreich aktiviert!",
        "recovery_codes": recovery_codes
    }

@app.post("/api/auth/2fa/disable")
def disable_2fa(req: TotpDisableRequest, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret, recovery_codes FROM users WHERE id = ?", (user["user_id"],))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden")
    
    secret = row["totp_secret"]
    limiter_key = f"totp:{user['user_id']}"
    security.totp_limiter.check(limiter_key)
    code = (req.code or "").strip()
    is_valid = crypto_utils.verify_totp_code(secret, code) and security.totp_replay_guard.consume(user["user_id"], code)
    
    if not is_valid and row["recovery_codes"]:
        import hmac
        codes = json.loads(row["recovery_codes"])
        if any(hmac.compare_digest(c, code.upper()) for c in codes):
            is_valid = True
    
    if not is_valid:
        conn.close()
        security.totp_limiter.fail(limiter_key)
        raise HTTPException(status_code=400, detail="Ungültiger Bestätigungscode")
    security.totp_limiter.reset(limiter_key)
    
    cursor.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL, recovery_codes = NULL WHERE id = ?", (user["user_id"],))
    conn.commit()
    conn.close()
    
    return {"status": "ok", "message": "2FA wurde deaktiviert"}

# -------------------------------------------------------------
# Vault Items Endpoints
# -------------------------------------------------------------

@app.get("/api/vault/items", response_model=List[VaultItemResponse])
def get_vault_items(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
    FROM vault_items WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')
    ORDER BY favorite DESC, updated_at DESC
    """, (user["user_id"],))
    rows = cursor.fetchall()
    conn.close()
    
    items = []
    for r in rows:
        items.append(VaultItemResponse(
            id=r["id"],
            type=r["type"],
            title=r["title"],
            folder=r["folder"] or "",
            favorite=bool(r["favorite"]),
            encrypted_payload=r["encrypted_payload"],
            created_at=r["created_at"],
            updated_at=r["updated_at"]
        ))
    return items

@app.get("/api/vault/trash", response_model=List[VaultItemResponse])
def get_trash_items(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
    FROM vault_items WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at != ''
    ORDER BY updated_at DESC
    """, (user["user_id"],))
    rows = cursor.fetchall()
    conn.close()
    
    items = []
    for r in rows:
        items.append(VaultItemResponse(
            id=r["id"],
            type=r["type"],
            title=r["title"],
            folder=r["folder"] or "",
            favorite=bool(r["favorite"]),
            encrypted_payload=r["encrypted_payload"],
            created_at=r["created_at"],
            updated_at=r["updated_at"]
        ))
    return items

@app.post("/api/vault/items", response_model=VaultItemResponse)
def create_vault_item(req: VaultItemCreate, user: Dict[str, Any] = Depends(get_current_user)):
    item_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO vault_items (id, user_id, type, title, folder, favorite, encrypted_payload, created_at, updated_at, deleted_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
    """, (item_id, user["user_id"], req.type, req.title, req.folder or "", 1 if req.favorite else 0, req.encrypted_payload, now, now))
    conn.commit()
    conn.close()

    # Trigger auto-backup if enabled
    backup_engine.trigger_on_change(user["user_id"])
    
    return VaultItemResponse(
        id=item_id,
        type=req.type,
        title=req.title,
        folder=req.folder or "",
        favorite=req.favorite,
        encrypted_payload=req.encrypted_payload,
        created_at=now,
        updated_at=now
    )

@app.put("/api/vault/items/{item_id}", response_model=VaultItemResponse)
def update_vault_item(item_id: str, req: VaultItemUpdate, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user["user_id"]))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Eintrag nicht gefunden")
    
    title = req.title if req.title is not None else existing["title"]
    folder = req.folder if req.folder is not None else existing["folder"]
    favorite = (1 if req.favorite else 0) if req.favorite is not None else existing["favorite"]
    payload = req.encrypted_payload if req.encrypted_payload is not None else existing["encrypted_payload"]
    now = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
    UPDATE vault_items SET title = ?, folder = ?, favorite = ?, encrypted_payload = ?, updated_at = ?
    WHERE id = ? AND user_id = ?
    """, (title, folder, favorite, payload, now, item_id, user["user_id"]))
    conn.commit()
    conn.close()

    # Trigger auto-backup if enabled
    backup_engine.trigger_on_change(user["user_id"])
    
    return VaultItemResponse(
        id=item_id,
        type=existing["type"],
        title=title,
        folder=folder or "",
        favorite=bool(favorite),
        encrypted_payload=payload,
        created_at=existing["created_at"],
        updated_at=now
    )

@app.post("/api/vault/items/{item_id}/restore")
def restore_vault_item(item_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE vault_items SET deleted_at = NULL WHERE id = ? AND user_id = ?", (item_id, user["user_id"]))
    conn.commit()
    conn.close()
    backup_engine.trigger_on_change(user["user_id"])
    return {"status": "ok", "message": "Eintrag aus dem Papierkorb wiederhergestellt"}

@app.delete("/api/vault/items/{item_id}")
def delete_vault_item(item_id: str, permanent: bool = False, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT deleted_at FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user["user_id"]))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Eintrag nicht gefunden")
    
    if permanent or (row["deleted_at"] is not None and row["deleted_at"] != ""):
        # Hard delete
        cursor.execute("DELETE FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user["user_id"]))
        cursor.execute("DELETE FROM passkeys WHERE vault_item_id = ? AND user_id = ?", (item_id, user["user_id"]))
        conn.commit()
        conn.close()
        backup_engine.trigger_on_change(user["user_id"])
        return {"status": "ok", "message": "Eintrag endgültig gelöscht"}
    else:
        # Soft delete (move to trash)
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute("UPDATE vault_items SET deleted_at = ? WHERE id = ? AND user_id = ?", (now, item_id, user["user_id"]))
        conn.commit()
        conn.close()
        backup_engine.trigger_on_change(user["user_id"])
        return {"status": "ok", "message": "Eintrag in den Papierkorb verschoben"}

@app.delete("/api/vault/trash")
def empty_trash(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_items WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at != ''", (user["user_id"],))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Papierkorb vollständig geleert"}

# -------------------------------------------------------------
# Passkey (FIDO2 / WebAuthn) Endpoints
# -------------------------------------------------------------

@app.post("/api/passkeys/generate")
def generate_passkey(req: PasskeyGenerateRequest, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Generate a cryptographic FIDO2 ECDSA P-256 (ES256) keypair for a passkey.
    Returns the raw credential_id, private key PEM, public key PEM, and COSE descriptor.
    The client then encrypts the private key using AES-256-GCM before storing it in the vault!
    """
    keypair = crypto_utils.generate_passkey_keypair()
    return {
        "rp_id": req.rp_id,
        "rp_name": req.rp_name,
        "username": req.username,
        "user_handle": req.user_handle or secrets.token_hex(16),
        "credential_id": keypair["credential_id"],
        "private_key_pem": keypair["private_key_pem"],
        "public_key_pem": keypair["public_key_pem"],
        "public_key_cose": keypair["cose_key"],
        "x": keypair["x"],
        "y": keypair["y"]
    }

@app.get("/api/passkeys")
def list_passkeys(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, vault_item_id, rp_id, rp_name, username, user_handle, credential_id, 
           encrypted_private_key, public_key_cose, public_key_pem, sign_count, transports, created_at, last_used_at
    FROM passkeys WHERE user_id = ? ORDER BY created_at DESC
    """, (user["user_id"],))
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "vault_item_id": r["vault_item_id"],
            "rp_id": r["rp_id"],
            "rp_name": r["rp_name"],
            "username": r["username"],
            "user_handle": r["user_handle"],
            "credential_id": r["credential_id"],
            "encrypted_private_key": r["encrypted_private_key"],
            "public_key_cose": r["public_key_cose"],
            "public_key_pem": r["public_key_pem"],
            "sign_count": r["sign_count"],
            "transports": json.loads(r["transports"]) if r["transports"] else ["internal", "hybrid"],
            "created_at": r["created_at"],
            "last_used_at": r["last_used_at"]
        })
    return result

@app.post("/api/passkeys")
def save_passkey(req: PasskeySaveRequest, user: Dict[str, Any] = Depends(get_current_user)):
    passkey_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO passkeys (
        id, user_id, vault_item_id, rp_id, rp_name, username, user_handle,
        credential_id, encrypted_private_key, public_key_cose, public_key_pem,
        sign_count, transports, created_at, last_used_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL)
    """, (
        passkey_id, user["user_id"], req.vault_item_id, req.rp_id, req.rp_name,
        req.username, req.user_handle or "", req.credential_id, req.encrypted_private_key,
        req.public_key_cose, req.public_key_pem or "", json.dumps(req.transports or ["internal", "hybrid"]),
        now
    ))
    conn.commit()
    conn.close()
    
    return {"status": "ok", "id": passkey_id, "message": "Passkey sicher im Tresor gespeichert"}

@app.delete("/api/passkeys/{passkey_id}")
def delete_passkey(passkey_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passkeys WHERE id = ? AND user_id = ?", (passkey_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Passkey gelöscht"}

@app.post("/api/passkeys/sign-test")
def sign_test_assertion(req: PasskeySignTestRequest, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Test/Playground endpoint:
    Signs an authenticator assertion challenge using the decrypted Passkey ECDSA private key.
    Calculates SHA256(clientDataJSON) and signs authenticatorData || hash.
    """
    try:
        res = crypto_utils.sign_webauthn_assertion(
            req.private_key_pem,
            req.client_data_json,
            req.auth_data_hex
        )
        return {
            "status": "ok",
            "assertion": res
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signierfehler: {str(e)}")

# -------------------------------------------------------------
# Utility Tools (Live TOTP calculation)
# -------------------------------------------------------------

@app.post("/api/tools/totp")
def compute_totp(req: TotpComputeRequest):
    """Calculates live 6-digit TOTP code and remaining seconds for a given secret."""
    try:
        clean_secret = req.secret.replace(" ", "").upper()
        res = crypto_utils.generate_current_totp(clean_secret)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail="Ungültiger TOTP-Schlüssel")

# -------------------------------------------------------------
# HaveIBeenPwned (HIBP) k-Anonymity Breach Check
# -------------------------------------------------------------

@app.get("/api/tools/hibp/{prefix}")
async def check_hibp_prefix(prefix: str):
    """
    k-Anonymity breach check proxy:
    Sends only the first 5 characters of the SHA-1 hash to api.pwnedpasswords.com.
    Zero-knowledge: The full hash/password is NEVER sent or exposed.
    """
    prefix = prefix.strip().upper()
    if len(prefix) != 5:
        raise HTTPException(status_code=400, detail="Prefix muss genau 5 Hex-Zeichen lang sein")
    
    import httpx
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "SentinelBit-PasswordManager-HIBP-Check"}
    
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return {"status": "ok", "prefix": prefix, "data": resp.text}
            else:
                return {"status": "error", "prefix": prefix, "data": ""}
    except Exception as e:
        return {"status": "offline_fallback", "prefix": prefix, "data": "", "error": str(e)}

# -------------------------------------------------------------
# WebAuthn / Biometric Unlock Key Endpoints
# -------------------------------------------------------------

@app.get("/api/auth/webauthn/keys")
def list_webauthn_keys(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, credential_id, device_name, created_at FROM webauthn_unlock_keys WHERE user_id = ?", (user["user_id"],))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r["id"], "credential_id": r["credential_id"], "device_name": r["device_name"], "created_at": r["created_at"]} for r in rows]

@app.post("/api/auth/webauthn/register-key")
def register_webauthn_key(req: WebAuthnKeyRegisterRequest, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    key_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO webauthn_unlock_keys (id, user_id, credential_id, public_key, device_name, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (key_id, user["user_id"], req.credential_id, req.public_key, req.device_name, now))
    conn.commit()
    conn.close()
    return {"status": "ok", "id": key_id, "message": "Biometrisches Gerät erfolgreich registriert"}

@app.delete("/api/auth/webauthn/keys/{key_id}")
def delete_webauthn_key(key_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM webauthn_unlock_keys WHERE id = ? AND user_id = ?", (key_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Geräteschlüssel entfernt"}


# -------------------------------------------------------------
# Automated Backup & Recurring Sync Endpoints
# -------------------------------------------------------------

@app.get("/api/sync/settings")
def get_sync_settings(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM backup_sync_settings WHERE user_id = ?", (user["user_id"],))
    row = cursor.fetchone()
    conn.close()

    if not row:
        default_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "backups", user["username"]))
        return {
            "target_dir": default_dir,
            "interval_minutes": 15,
            "sync_on_change": True,
            "retention_count": 10,
            "is_active": False,
            "last_synced_at": None,
            "last_sync_status": "Noch nicht eingerichtet"
        }

    return {
        "target_dir": row["target_dir"],
        "interval_minutes": row["interval_minutes"],
        "sync_on_change": bool(row["sync_on_change"]),
        "retention_count": row["retention_count"],
        "is_active": bool(row["is_active"]),
        "last_synced_at": row["last_synced_at"],
        "last_sync_status": row["last_sync_status"] or "Bereit"
    }

@app.post("/api/sync/settings")
def save_sync_settings(req: BackupSyncSettingsModel, user: Dict[str, Any] = Depends(get_current_user)):
    target_dir = security.validate_backup_dir(req.target_dir)
    retention = max(1, min(req.retention_count or 10, 100))
    interval = max(1, min(req.interval_minutes or 15, 1440))

    conn = database.get_connection()
    cursor = conn.cursor()
    setting_id = str(uuid.uuid4())

    cursor.execute("""
    INSERT INTO backup_sync_settings (id, user_id, target_dir, interval_minutes, sync_on_change, retention_count, is_active, last_sync_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'Konfiguriert')
    ON CONFLICT(user_id) DO UPDATE SET
        target_dir = excluded.target_dir,
        interval_minutes = excluded.interval_minutes,
        sync_on_change = excluded.sync_on_change,
        retention_count = excluded.retention_count,
        is_active = excluded.is_active
    """, (setting_id, user["user_id"], target_dir, interval, 1 if req.sync_on_change else 0, retention, 1 if req.is_active else 0))
    conn.commit()
    conn.close()

    # Trigger immediate sync if active
    if req.is_active:
        backup_engine.perform_sync(user["user_id"])

    return {"status": "ok", "message": "Backup- & Sync-Plan erfolgreich gespeichert"}

@app.post("/api/sync/now")
def trigger_sync_now(user: Dict[str, Any] = Depends(get_current_user)):
    res = backup_engine.perform_sync(user["user_id"])
    return res

# -------------------------------------------------------------
# Masked Email Aliases ("Hide My Email")
# -------------------------------------------------------------

@app.get("/api/aliases")
def list_aliases(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_aliases WHERE user_id = ? ORDER BY created_at DESC", (user["user_id"],))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/aliases")
def create_alias(req: EmailAliasCreate, user: Dict[str, Any] = Depends(get_current_user)):
    import secrets
    random_token = secrets.token_hex(4)
    service_slug = "".join(c for c in req.service_name.lower() if c.isalnum()) or "service"
    domain = req.custom_domain or "SentinelBit.local"
    alias_email = f"{service_slug}.{random_token}@{domain}"

    alias_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO email_aliases (id, user_id, alias_email, service_name, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (alias_id, user["user_id"], alias_email, req.service_name, now))
    conn.commit()
    conn.close()

    return {"status": "ok", "id": alias_id, "alias_email": alias_email, "service_name": req.service_name}

@app.delete("/api/aliases/{alias_id}")
def delete_alias(alias_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM email_aliases WHERE id = ? AND user_id = ?", (alias_id, user["user_id"]))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "E-Mail-Alias gelöscht"}

# -------------------------------------------------------------
# Secure Sharing (Asymmetric End-to-End Vault Item Sharing)
# -------------------------------------------------------------

@app.post("/api/share/public-key")
def register_sharing_public_key(req: SharingPublicKeyRegister, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO user_sharing_keys (user_id, public_key_pem, created_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET public_key_pem = excluded.public_key_pem
    """, (user["user_id"], req.public_key_pem, now))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Öffentlicher Sharing-Schlüssel gespeichert"}

@app.get("/api/share/user/{target_username}/public-key")
def get_recipient_public_key(target_username: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (target_username.strip().lower(),))
    target_user = cursor.fetchone()
    if not target_user:
        conn.close()
        raise HTTPException(status_code=404, detail="Empfänger-Benutzername existiert nicht")

    cursor.execute("SELECT public_key_pem FROM user_sharing_keys WHERE user_id = ?", (target_user["id"],))
    key_row = cursor.fetchone()
    conn.close()

    if not key_row:
        raise HTTPException(status_code=400, detail="Empfänger hat noch keinen Sharing-Schlüssel aktiviert")

    return {"username": target_username, "public_key_pem": key_row["public_key_pem"]}

@app.post("/api/share/send")
def send_shared_item(req: ShareItemSendRequest, user: Dict[str, Any] = Depends(get_current_user)):
    shared_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO shared_items (id, sender_id, recipient_username, type, title, encrypted_payload, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (shared_id, user["user_id"], req.recipient_username.strip().lower(), req.type, req.title, req.encrypted_payload, now))
    conn.commit()
    conn.close()

    return {"status": "ok", "message": f"Eintrag sicher für '{req.recipient_username}' freigegeben!"}

@app.get("/api/share/inbox")
def list_shared_inbox(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT s.id, s.type, s.title, s.encrypted_payload, s.created_at, u.username as sender_username
    FROM shared_items s
    JOIN users u ON s.sender_id = u.id
    WHERE s.recipient_username = ?
    ORDER BY s.created_at DESC
    """, (user["username"].strip().lower(),))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.delete("/api/share/inbox/{item_id}")
def delete_shared_inbox_item(item_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM shared_items WHERE id = ? AND recipient_username = ?", (item_id, user["username"].strip().lower()))
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Geteilter Eintrag entfernt"}

# -------------------------------------------------------------
# Emergency Kit Data Endpoint
# -------------------------------------------------------------

@app.get("/api/auth/emergency-kit")
def get_emergency_kit_data(user: Dict[str, Any] = Depends(get_current_user)):
    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, enc_salt, auth_salt, totp_enabled, recovery_codes, created_at FROM users WHERE id = ?", (user["user_id"],))
    u = cursor.fetchone()
    conn.close()

    rec_codes = json.loads(u["recovery_codes"]) if u["recovery_codes"] else []
    return {
        "username": u["username"],
        "enc_salt": u["enc_salt"],
        "auth_salt": u["auth_salt"],
        "totp_enabled": bool(u["totp_enabled"]),
        "recovery_codes": rec_codes,
        "created_at": u["created_at"],
        "generated_at": datetime.now(timezone.utc).isoformat()
    }



import os
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)

@app.get("/")
def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "SentinelBit running. Frontend not yet initialized."}

app.mount("/static", StaticFiles(directory=static_dir), name="static")

if __name__ == "__main__":
    import uvicorn
    print("Starte SentinelBit Password Manager auf http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)

