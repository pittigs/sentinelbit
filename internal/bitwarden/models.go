package bitwarden

// PreloginRequest & Response
type PreloginRequest struct {
	Email string `json:"email"`
}

type PreloginResponse struct {
	Kdf           int `json:"kdf"`
	KdfIterations int `json:"kdfIterations"`
}

// Register
type RegisterKeys struct {
	PublicKey           string `json:"publicKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
}

type RegisterRequest struct {
	Email              string        `json:"email"`
	Name               string        `json:"name"`
	MasterPasswordHash string        `json:"masterPasswordHash"`
	MasterPasswordHint *string       `json:"masterPasswordHint"`
	Key                string        `json:"key"`
	Keys               *RegisterKeys `json:"keys"`
	Kdf                int           `json:"kdf"`
	KdfIterations      int           `json:"kdfIterations"`
}

// Token Response (OAuth2 password grant)
type TokenResponse struct {
	AccessToken         string  `json:"access_token"`
	ExpiresIn           int     `json:"expires_in"`
	TokenType           string  `json:"token_type"`
	RefreshToken        string  `json:"refresh_token"`
	Key                 string  `json:"Key,omitempty"`
	PrivateKey          string  `json:"PrivateKey,omitempty"`
	TwoFactorToken      *string `json:"TwoFactorToken"`
	ResetMasterPassword bool    `json:"resetMasterPassword"`
}

// Profile
type ProfileResponse struct {
	ID                 string        `json:"id"`
	Name               string        `json:"name"`
	Email              string        `json:"email"`
	EmailVerified      bool          `json:"emailVerified"`
	Premium            bool          `json:"premium"`
	MasterPasswordHint *string       `json:"masterPasswordHint"`
	Culture            string        `json:"culture"`
	TwoFactorEnabled   bool          `json:"twoFactorEnabled"`
	Key                string        `json:"key"`
	PrivateKey         string        `json:"privateKey"`
	SecurityStamp      string        `json:"securityStamp"`
	Organizations      []interface{} `json:"organizations"`
	Object             string        `json:"object"`
}

// Config
type ConfigResponse struct {
	Version       string            `json:"version"`
	GitHash       string            `json:"gitHash"`
	Server        map[string]string `json:"server"`
	Environment   map[string]string `json:"environment"`
	FeatureStates map[string]bool   `json:"featureStates"`
	Object        string            `json:"object"`
}

// Folder
type FolderModel struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RevisionDate string `json:"revisionDate"`
	Object       string `json:"object"`
}

type FolderRequest struct {
	Name string `json:"name"`
}

// Cipher
type CipherURI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

type CipherLogin struct {
	URIs                 []CipherURI `json:"uris"`
	Username             *string     `json:"username"`
	Password             *string     `json:"password"`
	PasswordRevisionDate *string     `json:"passwordRevisionDate"`
	Totp                 *string     `json:"totp"`
	AutofillOnPageLoad   *bool       `json:"autofillOnPageLoad"`
}

type CipherField struct {
	Type  int    `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CipherModel struct {
	ID                  string                 `json:"id"`
	OrganizationID      *string                `json:"organizationId"`
	FolderID            *string                `json:"folderId"`
	Type                int                    `json:"type"`
	Name                string                 `json:"name"`
	Notes               *string                `json:"notes"`
	Favorite            bool                   `json:"favorite"`
	Login               *CipherLogin           `json:"login,omitempty"`
	SecureNote          map[string]interface{} `json:"secureNote,omitempty"`
	Card                map[string]interface{} `json:"card,omitempty"`
	Identity            map[string]interface{} `json:"identity,omitempty"`
	Fields              []CipherField          `json:"fields"`
	Attachments         interface{}            `json:"attachments"`
	OrganizationUseTotp bool                   `json:"organizationUseTotp"`
	RevisionDate        string                 `json:"revisionDate"`
	DeletedDate         *string                `json:"deletedDate"`
	Reprompt            int                    `json:"reprompt"`
	Object              string                 `json:"object"`
}

// Sync
type SyncResponse struct {
	Profile     ProfileResponse `json:"profile"`
	Folders     []FolderModel   `json:"folders"`
	Collections []interface{}   `json:"collections"`
	Ciphers     []CipherModel   `json:"ciphers"`
	Domains     SyncDomains     `json:"domains"`
	Object      string          `json:"object"`
}

type SyncDomains struct {
	EquivalentDomains       interface{}   `json:"equivalentDomains"`
	GlobalEquivalentDomains []interface{} `json:"globalEquivalentDomains"`
	Object                  string        `json:"object"`
}

// User Context
type BwUserContext struct {
	UserID        string
	Username      string
	Email         string
	Key           string
	PrivateKey    string
	SecurityStamp string
	TotpEnabled   bool
	TotpSecret    string
}
