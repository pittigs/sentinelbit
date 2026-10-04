package models

import "time"

// Auth Models
type RegisterRequest struct {
	Username string `json:"username"`
	AuthSalt string `json:"auth_salt"`
	AuthHash string `json:"auth_hash"`
	EncSalt  string `json:"enc_salt"`
}

type LoginInitRequest struct {
	Username string `json:"username"`
}

type LoginInitResponse struct {
	AuthSalt     string `json:"auth_salt"`
	EncSalt      string `json:"enc_salt"`
	TotpRequired bool   `json:"totp_required"`
}

type LoginVerifyRequest struct {
	Username      string `json:"username"`
	ClientAuthKey string `json:"client_auth_key"`
	TotpCode      string `json:"totp_code,omitempty"`
	RecoveryCode  string `json:"recovery_code,omitempty"`
}

type LoginResponse struct {
	Status      string `json:"status"`
	Token       string `json:"token"`
	UserId      string `json:"user_id"`
	Username    string `json:"username"`
	EncSalt     string `json:"enc_salt"`
	TotpEnabled bool   `json:"totp_enabled"`
}

type TotpSetupResponse struct {
	Secret        string   `json:"secret"`
	ProvisionURI  string   `json:"provisioning_uri"`
	QRCodeBase64  string   `json:"qr_code_base64"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type TotpVerifyRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

type TotpDisableRequest struct {
	Code string `json:"code"`
}

// Vault Item Models
type VaultItemCreate struct {
	Type             string `json:"type"`
	Title            string `json:"title"`
	Folder           string `json:"folder,omitempty"`
	Favorite         bool   `json:"favorite,omitempty"`
	EncryptedPayload string `json:"encrypted_payload"`
}

type VaultItemUpdate struct {
	Type             string `json:"type,omitempty"`
	Title            string `json:"title,omitempty"`
	Folder           string `json:"folder,omitempty"`
	Favorite         *bool  `json:"favorite,omitempty"`
	EncryptedPayload string `json:"encrypted_payload,omitempty"`
}

type VaultItemResponse struct {
	ID               string  `json:"id"`
	Type             string  `json:"type"`
	Title            string  `json:"title"`
	Folder           string  `json:"folder"`
	Favorite         bool    `json:"favorite"`
	EncryptedPayload string  `json:"encrypted_payload"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
	DeletedAt        *string `json:"deleted_at,omitempty"`
}

// Passkey Models
type PasskeyGenerateRequest struct {
	RpId     string `json:"rp_id"`
	RpName   string `json:"rp_name"`
	Username string `json:"username"`
}

type PasskeySaveRequest struct {
	VaultItemId         string `json:"vault_item_id,omitempty"`
	RpId                string `json:"rp_id"`
	RpName              string `json:"rp_name"`
	Username            string `json:"username"`
	UserHandle          string `json:"user_handle,omitempty"`
	CredentialId        string `json:"credential_id"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	PublicKeyCose       string `json:"public_key_cose"`
	PublicKeyPem        string `json:"public_key_pem,omitempty"`
	Transports          string `json:"transports,omitempty"`
}

type PasskeySignTestRequest struct {
	PrivateKeyPem  string `json:"private_key_pem"`
	ClientDataJson string `json:"client_data_json"`
	AuthDataHex    string `json:"auth_data_hex"`
}

// 2FA Compute for vault items
type TotpComputeRequest struct {
	Secret string `json:"secret"`
}

// Biometric WebAuthn Unlock Models
type WebAuthnKeyRegisterRequest struct {
	CredentialId string `json:"credential_id"`
	PublicKey    string `json:"public_key"`
	DeviceName   string `json:"device_name"`
}

// Backup Settings
type BackupSyncSettingsModel struct {
	TargetDir       string `json:"target_dir"`
	IntervalMinutes int    `json:"interval_minutes"`
	SyncOnChange    bool   `json:"sync_on_change"`
	RetentionCount  int    `json:"retention_count"`
	IsActive        bool   `json:"is_active"`
}

// Email Aliases
type EmailAliasCreate struct {
	ServiceName string `json:"service_name"`
}

// Item Sharing
type ShareItemSendRequest struct {
	RecipientUsername string `json:"recipient_username"`
	Type              string `json:"type"`
	Title             string `json:"title"`
	EncryptedPayload  string `json:"encrypted_payload"`
}

type SharingPublicKeyRegister struct {
	PublicKeyPem string `json:"public_key_pem"`
}

// Session
type SessionData struct {
	UserId    string
	Username  string
	ExpiresAt time.Time
}
