package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"sentinelbit/internal/crypto"
	"sentinelbit/internal/models"
)

func CleanTotpSecretStr(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		if u, err := url.Parse(raw); err == nil {
			if s := u.Query().Get("secret"); s != "" {
				raw = s
			}
		}
	} else if strings.Contains(raw, "secret=") {
		parts := strings.Split(raw, "secret=")
		if len(parts) > 1 {
			raw = strings.Split(parts[1], "&")[0]
		}
	}
	raw = strings.ToUpper(raw)
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, "-", "")
	raw = strings.TrimRight(raw, "=")
	return raw
}

func HandleComputeTotp(w http.ResponseWriter, r *http.Request) {
	var req models.TotpComputeRequest
	if err := jsonDecode(r, &req); err != nil {
		HTTPError(w, "Ungültiges JSON", http.StatusBadRequest)
		return
	}

	clean := CleanTotpSecretStr(req.Secret)
	code, rem, err := crypto.GenerateCurrentTotp(clean)
	if err != nil {
		HTTPError(w, "Ungültiger TOTP-Schlüssel", http.StatusBadRequest)
		return
	}

	JSONResponse(w, map[string]interface{}{
		"code":              code,
		"remaining_seconds": rem,
		"period":            30,
	}, http.StatusOK)
}

func HandleCheckHIBP(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimSpace(chi.URLParam(r, "prefix")))
	if len(prefix) != 5 {
		HTTPError(w, "Prefix muss genau 5 Hex-Zeichen lang sein", http.StatusBadRequest)
		return
	}

	targetUrl := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	client := &http.Client{Timeout: 6 * time.Second}
	req, _ := http.NewRequest("GET", targetUrl, nil)
	req.Header.Set("User-Agent", "sentinelbit-Go-HIBP-Check")

	resp, err := client.Do(req)
	if err != nil {
		JSONResponse(w, map[string]string{
			"status": "offline_fallback",
			"prefix": prefix,
			"data":   "",
			"error":  err.Error(),
		}, http.StatusOK)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	JSONResponse(w, map[string]string{
		"status": "ok",
		"prefix": prefix,
		"data":   string(bodyBytes),
	}, http.StatusOK)
}

func jsonDecode(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}
