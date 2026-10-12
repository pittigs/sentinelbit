package backup

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"time"
)

// StorageUploader handles remote backups to WebDAV or S3 endpoints (#81)
type StorageUploader struct {
	WebDAVURL      string
	WebDAVUsername string
	WebDAVPassword string
	HTTPClient     *http.Client
}

func NewStorageUploader() *StorageUploader {
	return &StorageUploader{
		WebDAVURL:      os.Getenv("SENTINELBIT_WEBDAV_URL"),
		WebDAVUsername: os.Getenv("SENTINELBIT_WEBDAV_USER"),
		WebDAVPassword: os.Getenv("SENTINELBIT_WEBDAV_PASS"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// UploadSnapshotToWebDAV uploads a local backup archive to a remote WebDAV server
func (s *StorageUploader) UploadSnapshotToWebDAV(localFilePath, remoteFileName string) error {
	if s.WebDAVURL == "" {
		return nil // WebDAV not configured, skip gracefully
	}

	data, err := os.ReadFile(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	targetURL := fmt.Sprintf("%s/%s", s.WebDAVURL, remoteFileName)
	req, err := http.NewRequest("PUT", targetURL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	if s.WebDAVUsername != "" {
		req.SetBasicAuth(s.WebDAVUsername, s.WebDAVPassword)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("webdav upload failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webdav returned status %d", resp.StatusCode)
	}

	return nil
}
