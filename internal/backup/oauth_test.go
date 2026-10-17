package backup

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthStateLifecycle(t *testing.T) {
	userID := "user-123"
	clientID := "client-abc.apps.googleusercontent.com"
	clientSecret := "secret-xyz"
	redirectURI := "https://vault.pittigs.eu/api/sync/gdrive/callback"

	state := GenerateOAuthState(userID, clientID, clientSecret, redirectURI)
	if state == "" {
		t.Fatalf("expected non-empty state")
	}

	authURL, err := GetOAuthAuthURL(state)
	if err != nil {
		t.Fatalf("unexpected error getting auth URL: %v", err)
	}

	if !strings.Contains(authURL, "accounts.google.com") {
		t.Errorf("expected Google auth URL, got %s", authURL)
	}
	if !strings.Contains(authURL, "client_id="+clientID) {
		t.Errorf("auth URL missing client_id: %s", authURL)
	}
	if !strings.Contains(authURL, "redirect_uri="+url.QueryEscape(redirectURI)) {
		t.Errorf("auth URL missing redirect_uri: %s", authURL)
	}
	if !strings.Contains(authURL, "access_type=offline") {
		t.Errorf("auth URL missing offline access: %s", authURL)
	}

	// Test invalid state
	_, err = GetOAuthAuthURL("non-existent-state")
	if err == nil {
		t.Errorf("expected error for non-existent state, got nil")
	}
}

func TestOAuthStateCleanup(t *testing.T) {
	oauthMu.Lock()
	oauthPendingStates["expired-state"] = &OAuthState{
		UserID:       "old-user",
		ClientID:     "id",
		ClientSecret: "sec",
		RedirectURI:  "uri",
		CreatedAt:    time.Now().Add(-20 * time.Minute),
	}
	oauthMu.Unlock()

	// Generating a new state triggers cleanup of >15m entries
	_ = GenerateOAuthState("new-user", "id", "sec", "uri")

	oauthMu.Lock()
	_, exists := oauthPendingStates["expired-state"]
	oauthMu.Unlock()

	if exists {
		t.Errorf("expected expired state to be pruned")
	}
}
