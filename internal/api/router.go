package api

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"sentinelbit/internal/config"
	"sentinelbit/internal/security"
	"sentinelbit/static"
)

// SetupRouter creates and configures the complete HTTP Chi router
func SetupRouter(database *sql.DB, cfg *config.Config) *chi.Mux {
	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	r.Use(security.SecurityHeadersMiddleware)

	// API Routes
	r.Route("/api", func(api chi.Router) {
		api.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			regStatus := "enabled"
			if cfg != nil && cfg.DisableRegistration {
				regStatus = "disabled"
			}
			JSONResponse(w, map[string]string{
				"status":       "healthy",
				"service":      "sentinelbit (Go)",
				"version":      "2.1.0",
				"registration": regStatus,
			}, http.StatusOK)
		})

		// Auth
		api.Route("/auth", func(auth chi.Router) {
			auth.Post("/register", HandleRegister(database, cfg))
			auth.Post("/login-init", HandleLoginInit(database))
			auth.Post("/login-verify", HandleLoginVerify(database))
			auth.Post("/logout", HandleLogout(database))
			auth.Get("/me", RequireAuth(HandleAuthMe))
			auth.Get("/emergency-kit", RequireAuth(HandleEmergencyKit(database)))

			// 2FA TOTP
			auth.Post("/2fa/setup", RequireAuth(Handle2faSetup(database)))
			auth.Post("/2fa/verify", RequireAuth(Handle2faVerify(database)))
			auth.Post("/2fa/disable", RequireAuth(Handle2faDisable(database)))

			// WebAuthn device unlock keys
			auth.Get("/webauthn/keys", RequireAuth(HandleListWebAuthnKeys(database)))
			auth.Post("/webauthn/register-key", RequireAuth(HandleRegisterWebAuthnKey(database)))
			auth.Delete("/webauthn/keys/{keyId}", RequireAuth(HandleDeleteWebAuthnKey(database)))
		})

		// Vault Items
		api.Route("/vault", func(vault chi.Router) {
			vault.Get("/items", RequireAuth(HandleListVaultItems(database)))
			vault.Post("/items", RequireAuth(HandleCreateVaultItem(database)))
			vault.Delete("/items/all", RequireAuth(HandleClearVault(database)))
			vault.Put("/items/{itemId}", RequireAuth(HandleUpdateVaultItem(database)))
			vault.Delete("/items/{itemId}", RequireAuth(HandleDeleteVaultItem(database)))
			vault.Post("/items/{itemId}/restore", RequireAuth(HandleRestoreVaultItem(database)))
			vault.Get("/trash", RequireAuth(HandleListTrashItems(database)))
			vault.Delete("/trash", RequireAuth(HandleEmptyTrash(database)))
		})

		// Passkeys (FIDO2)
		api.Route("/passkeys", func(pk chi.Router) {
			pk.Post("/generate", RequireAuth(HandlePasskeyGenerate))
			pk.Get("/", RequireAuth(HandleListPasskeys(database)))
			pk.Post("/", RequireAuth(HandleSavePasskey(database)))
			pk.Delete("/{passkeyId}", RequireAuth(HandleDeletePasskey(database)))
			pk.Post("/sign-test", RequireAuth(HandlePasskeySignTest))
		})

		// Tools
		api.Post("/tools/totp", HandleComputeTotp)
		api.Get("/tools/hibp/{prefix}", HandleCheckHIBP)

		// Sync & Backup
		api.Get("/sync/settings", RequireAuth(HandleGetSyncSettings(database)))
		api.Post("/sync/settings", RequireAuth(HandleSaveSyncSettings(database)))
		api.Post("/sync/now", RequireAuth(HandleTriggerSyncNow))

		// Aliases
		api.Get("/aliases", RequireAuth(HandleListAliases(database)))
		api.Post("/aliases", RequireAuth(HandleCreateAlias(database)))
		api.Delete("/aliases/{aliasId}", RequireAuth(HandleDeleteAlias(database)))

		// Item Sharing
		api.Post("/share/public-key", RequireAuth(HandleRegisterSharePublicKey(database)))
		api.Get("/share/user/{targetUsername}/public-key", RequireAuth(HandleGetRecipientPublicKey(database)))
		api.Post("/share/send", RequireAuth(HandleSendSharedItem(database)))
		api.Get("/share/inbox", RequireAuth(HandleListSharedInbox(database)))
		api.Delete("/share/inbox/{itemId}", RequireAuth(HandleDeleteSharedInboxItem(database)))
	})

	// Static frontend: Use local disk if static/index.html exists (for live dev/customization),
	// otherwise serve from compiled-in embedded assets (for 100% standalone single binary).
	staticDir := filepath.Join(".", "static")
	localIndex := filepath.Join(staticDir, "index.html")

	if _, err := os.Stat(localIndex); err == nil {
		fs := http.FileServer(http.Dir(staticDir))
		r.Handle("/static/*", http.StripPrefix("/static/", fs))
		r.Get("/sw.js", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(staticDir, "sw.js"))
		})
		r.Get("/manifest.webmanifest", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(staticDir, "manifest.webmanifest"))
		})
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, localIndex)
		})
	} else {
		// Embedded filesystem fallback
		embeddedFS := http.FileServer(http.FS(static.EmbeddedFiles))
		r.Handle("/static/*", http.StripPrefix("/static/", embeddedFS))
		r.Get("/sw.js", func(w http.ResponseWriter, r *http.Request) {
			content, err := static.EmbeddedFiles.ReadFile("sw.js")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(content)
		})
		r.Get("/manifest.webmanifest", func(w http.ResponseWriter, r *http.Request) {
			content, err := static.EmbeddedFiles.ReadFile("manifest.webmanifest")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/manifest+json")
			_, _ = w.Write(content)
		})
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			content, err := static.EmbeddedFiles.ReadFile("index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(content)
		})
	}

	return r
}
