package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HandleServerTime returns server UTC unix time in milliseconds for NTP clock-drift correction (#67)
func HandleServerTime() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UTC()
		JSONResponse(w, map[string]interface{}{
			"server_time_ms": now.UnixMilli(),
			"rfc3339":        now.Format(time.RFC3339),
		}, http.StatusOK)
	}
}

// HandleOpenAPISpec returns the OpenAPI 3.1 JSON specification (#48)
func HandleOpenAPISpec() http.HandlerFunc {
	spec := map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]interface{}{
			"title":       "SentinelBit Zero-Knowledge Vault API",
			"version":     "3.0.0",
			"description": "Zero-knowledge, pure-Go password manager and passkey sync API.",
		},
		"paths": map[string]interface{}{
			"/api/health": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Health Check",
					"description": "Returns system health and version",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "System is healthy"},
					},
				},
			},
			"/api/time": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Server Time",
					"description": "Returns current server timestamp in ms for TOTP drift correction",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Current server time"},
					},
				},
			},
			"/api/auth/login-init": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Initiate SRP-style Login",
					"requestBody": map[string]interface{}{
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"username": map[string]interface{}{"type": "string"},
									},
								},
							},
						},
					},
				},
			},
			"/api/vault/items": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "List Vault Items",
				},
				"post": map[string]interface{}{
					"summary": "Create Vault Item",
				},
			},
			"/api/vault/re-encrypt": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Atomically re-encrypt vault items with new Master Password",
				},
			},
			"/api/send": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Create Burn-after-Reading Secure Send item",
				},
			},
			"/api/webhooks": map[string]interface{}{
				"get":  map[string]interface{}{"summary": "List registered webhooks"},
				"post": map[string]interface{}{"summary": "Create new webhook"},
			},
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		JSONResponse(w, spec, http.StatusOK)
	}
}

// HandleSwaggerUI serves an interactive API documentation interface (#48)
func HandleSwaggerUI() http.HandlerFunc {
	html := `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelBit API Reference (OpenAPI 3.1)</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  <style>
    body { margin: 0; background: #0f172a; color: #f8fafc; font-family: sans-serif; }
    .topbar { display: none; }
    .swagger-ui { filter: invert(88%) hue-rotate(180deg); }
    .swagger-ui .wrapper { max-width: 1200px; padding: 20px; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/api/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ]
      });
    };
  </script>
</body>
</html>`
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	}
}

// HandleStreamVaultExport streams vault items in chunks with zero memory allocation buffers (#50)
func HandleStreamVaultExport(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"sentinelbit-vault-stream.json\"")

		flusher, ok := w.(http.Flusher)

		rows, err := db.Query(`
			SELECT id, type, title, folder, favorite, encrypted_payload, created_at, updated_at
			FROM vault_items
			WHERE user_id = ? AND (deleted_at IS NULL OR deleted_at = '')
			ORDER BY created_at ASC
		`, user.UserId)
		if err != nil {
			HTTPError(w, "Query error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		_, _ = fmt.Fprint(w, `{"format":"sentinelbit_stream","version":"3.0.0","items":[`)
		if ok {
			flusher.Flush()
		}

		first := true
		enc := json.NewEncoder(w)

		for rows.Next() {
			var id, itemType, title, folder, payload, createdAt, updatedAt string
			var fav int
			if err := rows.Scan(&id, &itemType, &title, &folder, &fav, &payload, &createdAt, &updatedAt); err == nil {
				if !first {
					_, _ = fmt.Fprint(w, ",")
				}
				first = false
				item := map[string]interface{}{
					"id":                id,
					"type":              itemType,
					"title":             title,
					"folder":            folder,
					"favorite":          fav == 1,
					"encrypted_payload": payload,
					"created_at":        createdAt,
					"updated_at":        updatedAt,
				}
				_ = enc.Encode(item)
				if ok {
					flusher.Flush()
				}
			}
		}

		_, _ = fmt.Fprint(w, `]}`)
		if ok {
			flusher.Flush()
		}
	}
}
