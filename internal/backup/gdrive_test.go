package backup

import (
	"os"
	"testing"
)

func TestExtractFolderID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain folder id",
			input:    "1a2B3c4D5e6F7g8H9i0J",
			expected: "1a2B3c4D5e6F7g8H9i0J",
		},
		{
			name:     "plain folder id with whitespace",
			input:    "  1a2B3c4D5e6F7g8H9i0J  ",
			expected: "1a2B3c4D5e6F7g8H9i0J",
		},
		{
			name:     "google drive web url",
			input:    "https://drive.google.com/drive/folders/1ABCxyz789",
			expected: "1ABCxyz789",
		},
		{
			name:     "google drive url with user index and query params",
			input:    "https://drive.google.com/drive/u/1/folders/1ABCxyz789?usp=drive_link&resourcekey=0-xyz",
			expected: "1ABCxyz789",
		},
		{
			name:     "google drive url with subpath or hash",
			input:    "https://drive.google.com/drive/folders/1ABCxyz789/sub#details",
			expected: "1ABCxyz789",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractFolderID(tc.input)
			if got != tc.expected {
				t.Errorf("ExtractFolderID(%q) = %q, expected %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestGDriveUploader_EnvFallback(t *testing.T) {
	os.Setenv("SENTINELBIT_GDRIVE_FOLDER_ID", "env-folder-id-123")
	os.Setenv("SENTINELBIT_GDRIVE_CREDENTIALS", `{"type": "service_account"}`)
	defer func() {
		os.Unsetenv("SENTINELBIT_GDRIVE_FOLDER_ID")
		os.Unsetenv("SENTINELBIT_GDRIVE_CREDENTIALS")
	}()

	uploader := NewGDriveUploader("", "")
	if uploader.FolderID != "env-folder-id-123" {
		t.Errorf("expected FolderID to fallback to env, got %s", uploader.FolderID)
	}
	if !uploader.IsConfigured() {
		t.Errorf("expected uploader to be configured via env var")
	}
}
