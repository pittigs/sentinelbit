"""
Pydantic data models for SentinelBit API.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class RegisterRequest(BaseModel):
    username: str
    auth_salt: str # Client-provided or derived salt
    auth_hash: str # Client's auth key hashed on client side
    enc_salt: str # Salt used client-side for deriving vault encryption key

class LoginInitRequest(BaseModel):
    username: str

class LoginInitResponse(BaseModel):
    auth_salt: str
    enc_salt: str
    totp_required: bool

class LoginVerifyRequest(BaseModel):
    username: str
    client_auth_key: str # Client computed key (hex)
    totp_code: Optional[str] = None
    recovery_code: Optional[str] = None

class LoginResponse(BaseModel):
    token: str
    username: str
    enc_salt: str
    totp_enabled: bool

class TotpSetupResponse(BaseModel):
    secret: str
    qr_code_base64: str
    provisioning_uri: str

class TotpVerifyRequest(BaseModel):
    code: str

class TotpDisableRequest(BaseModel):
    code: str

class VaultItemCreate(BaseModel):
    type: str = "login" # 'login', 'passkey', 'note', 'card'
    title: str
    folder: Optional[str] = ""
    favorite: bool = False
    encrypted_payload: str # AES-GCM ciphertext + IV + Tag

class VaultItemUpdate(BaseModel):
    title: Optional[str] = None
    folder: Optional[str] = None
    favorite: Optional[bool] = None
    encrypted_payload: Optional[str] = None

class VaultItemResponse(BaseModel):
    id: str
    type: str
    title: str
    folder: str
    favorite: bool
    encrypted_payload: str
    created_at: str
    updated_at: str

class PasskeyGenerateRequest(BaseModel):
    rp_id: str
    rp_name: str
    username: str
    user_handle: Optional[str] = None

class PasskeySaveRequest(BaseModel):
    vault_item_id: Optional[str] = None
    rp_id: str
    rp_name: str
    username: str
    user_handle: Optional[str] = None
    credential_id: str
    encrypted_private_key: str
    public_key_cose: str
    public_key_pem: Optional[str] = None
    transports: Optional[List[str]] = ["internal", "hybrid"]

class PasskeySignTestRequest(BaseModel):
    private_key_pem: str
    client_data_json: str
    auth_data_hex: str

class TotpComputeRequest(BaseModel):
    secret: str

class WebAuthnKeyRegisterRequest(BaseModel):
    credential_id: str
    public_key: str
    device_name: str

class WebAuthnChallengeResponse(BaseModel):
    challenge: str
    rp_id: str
    user_id: str

class BackupSyncSettingsModel(BaseModel):
    target_dir: str
    interval_minutes: int = 15
    sync_on_change: bool = True
    retention_count: int = 10
    is_active: bool = True

class EmailAliasCreate(BaseModel):
    service_name: str
    custom_domain: Optional[str] = None

class ShareItemSendRequest(BaseModel):
    recipient_username: str
    type: str
    title: str
    encrypted_payload: str

class SharingPublicKeyRegister(BaseModel):
    public_key_pem: str



