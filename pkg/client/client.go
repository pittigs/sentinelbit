package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sentinelbit/internal/crypto"
	"sentinelbit/internal/models"
)

// Client is a Zero-Knowledge Go client for the SentinelBit API
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string
	UserID     string
	Username   string
	MasterKey  []byte
}

// NewClient creates a new SentinelBit API client
func NewClient(baseURL string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Login performs zero-knowledge SRP-style authentication and derives master encryption key locally
func (c *Client) Login(username, password, totpCode string) error {
	// 1. Init login
	initPayload, _ := json.Marshal(map[string]string{"username": username})
	resp, err := c.HTTPClient.Post(c.BaseURL+"/api/auth/login-init", "application/json", bytes.NewReader(initPayload))
	if err != nil {
		return fmt.Errorf("login init failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("user not found or server error (%d)", resp.StatusCode)
	}

	var initResp models.LoginInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return err
	}

	// 2. Derive Client Auth Key & Master Key
	// Client auth key derivation with client salt (before the colon in auth_salt)
	salts := strings.Split(initResp.AuthSalt, ":")
	clientSalt := salts[0]
	serverSalt := ""
	if len(salts) > 1 {
		serverSalt = salts[1]
	}

	// Derive client auth key = PBKDF2(password, clientSalt, 100000, 32)
	clientAuthKeyBytes := crypto.DeriveMasterKey(password, clientSalt)
	clientAuthKeyHex := fmt.Sprintf("%x", clientAuthKeyBytes)

	// If serverSalt is provided, compute auth_hash = PBKDF2(clientAuthKey, serverSalt, 100000, 32)
	authHashHex, err := crypto.HashAuthKey(clientAuthKeyHex, serverSalt, 100_000)
	if err != nil {
		return err
	}

	// 3. Verify login
	verifyReq := models.LoginVerifyRequest{
		Username:      username,
		ClientAuthKey: authHashHex,
		TotpCode:      totpCode,
	}
	verifyBytes, _ := json.Marshal(verifyReq)
	vResp, err := c.HTTPClient.Post(c.BaseURL+"/api/auth/login-verify", "application/json", bytes.NewReader(verifyBytes))
	if err != nil {
		return fmt.Errorf("login verify failed: %w", err)
	}
	defer vResp.Body.Close()

	if vResp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid password or 2FA code (%d)", vResp.StatusCode)
	}

	var loginResp models.LoginResponse
	if err := json.NewDecoder(vResp.Body).Decode(&loginResp); err != nil {
		return err
	}

	c.Token = loginResp.Token
	c.UserID = loginResp.UserId
	c.Username = loginResp.Username

	// Derive Master Encryption Key
	c.MasterKey = crypto.DeriveMasterKey(password, loginResp.EncSalt)
	return nil
}

// ListItems fetches and decrypts all vault items
func (c *Client) ListItems() ([]map[string]interface{}, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/api/vault/items", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch items: status %d", resp.StatusCode)
	}

	var rawItems []models.VaultItemResponse
	if err := json.NewDecoder(resp.Body).Decode(&rawItems); err != nil {
		return nil, err
	}

	var decryptedList []map[string]interface{}
	for _, it := range rawItems {
		itemMap := map[string]interface{}{
			"id":         it.ID,
			"type":       it.Type,
			"title":      it.Title,
			"folder":     it.Folder,
			"favorite":   it.Favorite,
			"created_at": it.CreatedAt,
			"updated_at": it.UpdatedAt,
		}

		if len(c.MasterKey) > 0 {
			decData, err := crypto.DecryptVaultPayload(it.EncryptedPayload, c.MasterKey)
			if err == nil {
				itemMap["data"] = decData
			}
		}
		decryptedList = append(decryptedList, itemMap)
	}

	return decryptedList, nil
}

// CreateItem encrypts and saves a new vault item
func (c *Client) CreateItem(itemType, title, folder string, favorite bool, dataObj interface{}) (string, error) {
	if len(c.MasterKey) == 0 {
		return "", fmt.Errorf("client not logged in with master key")
	}

	encPayload, err := crypto.EncryptVaultPayload(dataObj, c.MasterKey)
	if err != nil {
		return "", fmt.Errorf("encryption error: %w", err)
	}

	createReq := models.VaultItemCreate{
		Type:             itemType,
		Title:            title,
		Folder:           folder,
		Favorite:         favorite,
		EncryptedPayload: encPayload,
	}

	bodyBytes, _ := json.Marshal(createReq)
	req, err := http.NewRequest("POST", c.BaseURL+"/api/vault/items", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server error (%d): %s", resp.StatusCode, string(b))
	}

	var res models.VaultItemResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	return res.ID, nil
}
