package bitwarden

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sentinelbit/internal/config"
)

// SetupIdentityRouter creates the router mounted under /identity
func SetupIdentityRouter(database *sql.DB) http.Handler {
	r := chi.NewRouter()
	r.Post("/connect/token", HandleToken(database))
	return r
}

// RegisterBitwardenRoutes attaches Bitwarden compatibility routes to /api
func RegisterBitwardenRoutes(api chi.Router, database *sql.DB, cfg *config.Config) {
	// Config & Prelogin
	api.Get("/config", HandleConfig(cfg))
	api.Post("/accounts/prelogin", HandlePrelogin(database))
	api.Post("/accounts/register", HandleRegister(database, cfg))

	// Authenticated Accounts & Sync
	authMw := RequireBwAuth(database)

	api.With(authMw).Get("/accounts/profile", HandleProfile())
	api.With(authMw).Post("/accounts/security-stamp", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{}, http.StatusOK)
	})
	api.With(authMw).Get("/sync", HandleSync(database))

	// Ciphers
	api.Route("/ciphers", func(c chi.Router) {
		c.Use(authMw)
		c.Get("/", HandleGetCiphers(database))
		c.Post("/", HandleCreateCipher(database))
		c.Put("/{id}", HandleUpdateCipher(database))
		c.Delete("/{id}", HandleDeleteCipher(database))
		c.Delete("/{id}/delete", HandleHardDeleteCipher(database))
		c.Put("/{id}/restore", HandleRestoreCipher(database))
	})

	// Folders
	api.Route("/folders", func(f chi.Router) {
		f.Use(authMw)
		f.Get("/", HandleGetFolders(database))
		f.Post("/", HandleCreateFolder(database))
		f.Put("/{id}", HandleUpdateFolder(database))
		f.Delete("/{id}", HandleDeleteFolder(database))
	})

	// Two-Factor & Collections
	api.With(authMw).Get("/two-factor", HandleTwoFactorProviders())
	api.Get("/collections", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{"data": []interface{}{}, "object": "list"}, http.StatusOK)
	})

	// Devices
	api.Post("/devices/knowndevice", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, true, http.StatusOK)
	})
	api.Put("/devices/identifier/{id}", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{}, http.StatusOK)
	})
}
