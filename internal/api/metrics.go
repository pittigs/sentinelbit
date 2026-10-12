package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"runtime"
	"strings"
)

// HandlePrometheusMetrics exports standard Prometheus text format metrics
func HandlePrometheusMetrics(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		numGoroutines := runtime.NumGoroutine()

		dbStats := db.Stats()

		var usersCount int
		_ = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&usersCount)

		var vaultItemsCount int
		_ = db.QueryRow("SELECT COUNT(*) FROM vault_items WHERE deleted_at IS NULL OR deleted_at = ''").Scan(&vaultItemsCount)

		var passkeysCount int
		_ = db.QueryRow("SELECT COUNT(*) FROM passkeys WHERE deleted_at IS NULL OR deleted_at = ''").Scan(&passkeysCount)

		var sb strings.Builder
		sb.WriteString("# HELP sentinelbit_build_info SentinelBit build and version info\n")
		sb.WriteString("# TYPE sentinelbit_build_info gauge\n")
		sb.WriteString("sentinelbit_build_info{version=\"3.0.0\",service=\"sentinelbit\"} 1\n\n")

		sb.WriteString("# HELP sentinelbit_goroutines Current active goroutines\n")
		sb.WriteString("# TYPE sentinelbit_goroutines gauge\n")
		fmt.Fprintf(&sb, "sentinelbit_goroutines %d\n\n", numGoroutines)

		sb.WriteString("# HELP sentinelbit_memory_alloc_bytes Current allocated heap memory in bytes\n")
		sb.WriteString("# TYPE sentinelbit_memory_alloc_bytes gauge\n")
		fmt.Fprintf(&sb, "sentinelbit_memory_alloc_bytes %d\n\n", mem.Alloc)

		sb.WriteString("# HELP sentinelbit_db_open_connections Currently open SQLite connections\n")
		sb.WriteString("# TYPE sentinelbit_db_open_connections gauge\n")
		fmt.Fprintf(&sb, "sentinelbit_db_open_connections %d\n\n", dbStats.OpenConnections)

		sb.WriteString("# HELP sentinelbit_db_in_use_connections In-use SQLite connections\n")
		sb.WriteString("# TYPE sentinelbit_db_in_use_connections gauge\n")
		fmt.Fprintf(&sb, "sentinelbit_db_in_use_connections %d\n\n", dbStats.InUse)

		sb.WriteString("# HELP sentinelbit_users_total Total registered user accounts\n")
		sb.WriteString("# TYPE sentinelbit_users_total gauge\n")
		fmt.Fprintf(&sb, "sentinelbit_users_total %d\n\n", usersCount)

		sb.WriteString("# HELP sentinelbit_vault_items_total Total active vault items\n")
		sb.WriteString("# TYPE sentinelbit_vault_items_total gauge\n")
		fmt.Fprintf(&sb, "sentinelbit_vault_items_total %d\n\n", vaultItemsCount)

		sb.WriteString("# HELP sentinelbit_passkeys_total Total active FIDO2 passkeys\n")
		sb.WriteString("# TYPE sentinelbit_passkeys_total gauge\n")
		fmt.Fprintf(&sb, "sentinelbit_passkeys_total %d\n", passkeysCount)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sb.String()))
	}
}
