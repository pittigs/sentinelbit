"""
Cryptographic and WebAuthn/Passkey utilities for SentinelBit.
Includes:
- PBKDF2 / SHA256 hashing
- PyOTP TOTP generation & QR code generation
- FIDO2 / WebAuthn P-256 (ES256) key pair creation and assertion signing
- COSE key serialization (RFC 8152 / FIDO2 standard)
"""
import os
import base64
import hashlib
import hmac
import time
import io
import json
from typing import Tuple, Dict, Any, Optional

import pyotp
import qrcode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# -------------------------------------------------------------
# Password & Auth Hash Helpers
# -------------------------------------------------------------

def generate_salt(length: int = 32) -> str:
    """Generate cryptographically secure base64url salt."""
    return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8')

def hash_auth_key(client_auth_key_hex: str, server_salt: str, iterations: int = 100_000) -> str:
    """
    Second layer server-side hashing of client auth key (PBKDF2-HMAC-SHA256).
    The client hashes Master Password -> Client Auth Key.
    The server hashes Client Auth Key + Salt -> Auth Hash (stored in DB).
    The server NEVER receives or knows the Master Encryption Key.
    """
    key_bytes = bytes.fromhex(client_auth_key_hex)
    salt_bytes = server_salt.encode('utf-8')
    derived = hashlib.pbkdf2_hmac('sha256', key_bytes, salt_bytes, iterations)
    return derived.hex()

def verify_auth_key(client_auth_key_hex: str, server_salt: str, stored_hash: str) -> bool:
    """Constant-time verification of auth key."""
    computed_hash = hash_auth_key(client_auth_key_hex, server_salt)
    return hmac.compare_digest(computed_hash, stored_hash)

# -------------------------------------------------------------
# 2FA (TOTP) Helpers
# -------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a standard Base32 secret for TOTP (Google Authenticator, SentinelBit, 1Password compatible)."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str, issuer: str = "SentinelBit") -> str:
    """Construct otpauth:// URI."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def generate_totp_qr_base64(provisioning_uri: str) -> str:
    """Generate base64 encoded PNG for TOTP QR Code."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """Verify 6-digit TOTP code with time drift window."""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    # allows 1 step before / after for clock drift (30s)
    return totp.verify(code.strip(), valid_window=window)

def generate_current_totp(secret: str) -> Dict[str, Any]:
    """Generate current code and remaining seconds."""
    totp = pyotp.TOTP(secret)
    code = totp.now()
    remaining = 30 - (int(time.time()) % 30)
    return {
        "code": code,
        "remaining_seconds": remaining,
        "period": 30
    }

# -------------------------------------------------------------
# WebAuthn / Passkey (FIDO2) Helpers
# -------------------------------------------------------------

def generate_passkey_keypair() -> Dict[str, Any]:
    """
    Generate an Elliptic Curve P-256 (secp256r1) key pair for Passkey (ES256, alg -7).
    Returns PEM strings and raw public coordinates for COSE format.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Private key in PKCS#8 PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Public key in SubjectPublicKeyInfo (SPKI) PEM format
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Extract raw X and Y coordinates (32 bytes each)
    public_numbers = public_key.public_numbers()
    x_bytes = public_numbers.x.to_bytes(32, byteorder='big')
    y_bytes = public_numbers.y.to_bytes(32, byteorder='big')
    
    # Credential ID: 32 bytes random identifier
    raw_cred_id = os.urandom(32)
    credential_id_b64 = base64.urlsafe_b64encode(raw_cred_id).decode('utf-8').rstrip('=')
    
    # Minimal COSE Key Representation (CBOR-like dictionary structure)
    # 1: key type (2 = EC2), 3: alg (-7 = ES256), -1: crv (1 = P-256), -2: x, -3: y
    cose_data = {
        "kty": 2, # EC2
        "alg": -7, # ES256
        "crv": 1, # P-256
        "x": base64.urlsafe_b64encode(x_bytes).decode('utf-8').rstrip('='),
        "y": base64.urlsafe_b64encode(y_bytes).decode('utf-8').rstrip('=')
    }
    
    return {
        "credential_id": credential_id_b64,
        "private_key_pem": private_pem,
        "public_key_pem": public_pem,
        "cose_key": json.dumps(cose_data),
        "x": cose_data["x"],
        "y": cose_data["y"]
    }

def sign_webauthn_assertion(private_key_pem: str, client_data_json: str, auth_data_hex: str) -> Dict[str, Any]:
    """
    Sign a WebAuthn Assertion challenge according to W3C WebAuthn spec:
    Signature = sign_ECDSA_SHA256(authenticatorData || SHA256(clientDataJSON))
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    client_data_bytes = client_data_json.encode('utf-8')
    client_data_hash = hashlib.sha256(client_data_bytes).digest()
    
    auth_data_bytes = bytes.fromhex(auth_data_hex)
    data_to_sign = auth_data_bytes + client_data_hash
    
    # ECDSA-SHA256 signature (DER format standard in WebAuthn)
    signature = private_key.sign(
        data_to_sign,
        ec.ECDSA(hashes.SHA256())
    )
    
    return {
        "signature_b64": base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('='),
        "signature_hex": signature.hex(),
        "client_data_hash": client_data_hash.hex(),
        "data_signed_hex": data_to_sign.hex()
    }

