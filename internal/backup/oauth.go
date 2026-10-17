package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type OAuthState struct {
	UserID       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	CreatedAt    time.Time
}

var (
	oauthPendingStates = make(map[string]*OAuthState)
	oauthMu            sync.Mutex
)

// GenerateOAuthState creates a short-lived state token for the OAuth flow
func GenerateOAuthState(userID, clientID, clientSecret, redirectURI string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	state := hex.EncodeToString(b)

	oauthMu.Lock()
	defer oauthMu.Unlock()

	now := time.Now()
	for k, v := range oauthPendingStates {
		if now.Sub(v.CreatedAt) > 15*time.Minute {
			delete(oauthPendingStates, k)
		}
	}

	oauthPendingStates[state] = &OAuthState{
		UserID:       userID,
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: strings.TrimSpace(clientSecret),
		RedirectURI:  redirectURI,
		CreatedAt:    now,
	}

	return state
}

// GetOAuthAuthURL generates the Google OAuth consent URL with offline access
func GetOAuthAuthURL(state string) (string, error) {
	oauthMu.Lock()
	pending, ok := oauthPendingStates[state]
	oauthMu.Unlock()

	if !ok {
		return "", errors.New("ungültiger oder abgelaufener OAuth-State")
	}

	conf := &oauth2.Config{
		ClientID:     pending.ClientID,
		ClientSecret: pending.ClientSecret,
		RedirectURL:  pending.RedirectURI,
		Scopes:       []string{"https://www.googleapis.com/auth/drive"},
		Endpoint:     google.Endpoint,
	}

	// AccessTypeOffline forces refresh_token to be returned
	// ApprovalForce ensures consent screen appears so Google doesn't omit the refresh_token
	return conf.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce), nil
}

// ExchangeOAuthCode exchanges the authorization code for a permanent refresh token
func ExchangeOAuthCode(ctx context.Context, state, code string) (string, string, error) {
	oauthMu.Lock()
	pending, ok := oauthPendingStates[state]
	if ok {
		delete(oauthPendingStates, state)
	}
	oauthMu.Unlock()

	if !ok {
		return "", "", errors.New("ungültiger oder abgelaufener OAuth-State. Bitte versuche es erneut.")
	}

	conf := &oauth2.Config{
		ClientID:     pending.ClientID,
		ClientSecret: pending.ClientSecret,
		RedirectURL:  pending.RedirectURI,
		Scopes:       []string{"https://www.googleapis.com/auth/drive"},
		Endpoint:     google.Endpoint,
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return "", "", fmt.Errorf("Token-Austausch mit Google fehlgeschlagen: %w", err)
	}

	if token.RefreshToken == "" {
		return "", "", errors.New("Google hat keinen Refresh-Token zurückgegeben. Bitte die Autorisierung erneut starten.")
	}

	credsObj := map[string]string{
		"client_id":     pending.ClientID,
		"client_secret": pending.ClientSecret,
		"refresh_token": token.RefreshToken,
		"type":          "authorized_user",
	}

	credsBytes, err := json.MarshalIndent(credsObj, "", "  ")
	if err != nil {
		return "", "", err
	}

	return pending.UserID, string(credsBytes), nil
}
