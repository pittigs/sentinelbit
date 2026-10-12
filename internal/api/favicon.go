package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sentinelbit/internal/db"
)

var validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// HandleFaviconProxy serves a privacy-preserving cached favicon or clean SVG monogram (#59)
func HandleFaviconProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawDomain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
		// Strip schema and path if present
		rawDomain = strings.TrimPrefix(rawDomain, "https://")
		rawDomain = strings.TrimPrefix(rawDomain, "http://")
		if idx := strings.Index(rawDomain, "/"); idx != -1 {
			rawDomain = rawDomain[:idx]
		}
		if idx := strings.Index(rawDomain, ":"); idx != -1 {
			rawDomain = rawDomain[:idx]
		}

		if rawDomain == "" || !validDomainRegex.MatchString(rawDomain) {
			serveDefaultMonogram(w, "?")
			return
		}

		// Cache path
		cacheDir := filepath.Join(db.GetDataDir(), "favicons")
		_ = os.MkdirAll(cacheDir, 0755)

		hash := sha256.Sum256([]byte(rawDomain))
		cacheFile := filepath.Join(cacheDir, hex.EncodeToString(hash[:16])+".png")

		// 1. Check disk cache (valid for 30 days)
		if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < 30*24*time.Hour {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
			http.ServeFile(w, r, cacheFile)
			return
		}

		// 2. Fetch remote favicon with strict timeout and size limit
		client := &http.Client{Timeout: 2 * time.Second}
		remoteURL := fmt.Sprintf("https://%s/favicon.ico", rawDomain)
		req, _ := http.NewRequestWithContext(r.Context(), "GET", remoteURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SentinelBitFavicon/1.0)")

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK && resp.ContentLength < 128*1024 {
			defer resp.Body.Close()
			data, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
			if err == nil && len(data) > 32 {
				_ = os.WriteFile(cacheFile, data, 0644)
				w.Header().Set("Content-Type", "image/x-icon")
				w.Header().Set("Cache-Control", "public, max-age=604800")
				_, _ = w.Write(data)
				return
			}
		}

		// 3. Fallback: serve sleek SVG monogram
		letter := strings.ToUpper(string(rawDomain[0]))
		serveDefaultMonogram(w, letter)
	}
}

func serveDefaultMonogram(w http.ResponseWriter, letter string) {
	colors := []string{"#3b82f6", "#8b5cf6", "#ec4899", "#10b981", "#f59e0b", "#06b6d4"}
	colorIndex := 0
	if len(letter) > 0 {
		colorIndex = int(letter[0]) % len(colors)
	}
	bgColor := colors[colorIndex]

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
  <rect width="32" height="32" rx="8" fill="%s"/>
  <text x="50%%" y="52%%" dominant-baseline="central" text-anchor="middle" fill="#ffffff" font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif" font-weight="700" font-size="16">%s</text>
</svg>`, bgColor, letter)

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(svg))
}
