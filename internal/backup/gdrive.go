package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

// ExtractFolderID cleans up user input in case they paste the full Google Drive URL
func ExtractFolderID(input string) string {
	input = strings.TrimSpace(input)
	if strings.Contains(input, "folders/") {
		parts := strings.Split(input, "folders/")
		if len(parts) > 1 {
			id := strings.Split(parts[1], "?")[0]
			id = strings.Split(id, "/")[0]
			id = strings.Split(id, "#")[0]
			return strings.TrimSpace(id)
		}
	}
	return input
}

// GDriveUploader handles native upload, rotation and health verification on Google Drive
type GDriveUploader struct {
	Credentials string // File path or JSON content
	FolderID    string // Google Drive Folder ID
}

func NewGDriveUploader(credentials, folderID string) *GDriveUploader {
	creds := strings.TrimSpace(credentials)
	if creds == "" {
		creds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS")
	}
	if creds == "" {
		creds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_FILE")
	}
	if creds == "" {
		creds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_JSON")
	}

	fID := ExtractFolderID(folderID)
	if fID == "" {
		fID = ExtractFolderID(os.Getenv("SENTINELBIT_GDRIVE_FOLDER_ID"))
	}

	return &GDriveUploader{
		Credentials: creds,
		FolderID:    fID,
	}
}

// IsConfigured checks if credentials or Google Application Default Credentials exist
func (g *GDriveUploader) IsConfigured() bool {
	if g.Credentials != "" {
		return true
	}
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		return true
	}
	return false
}

func (g *GDriveUploader) getService(ctx context.Context) (*drive.Service, error) {
	var opts []option.ClientOption

	creds := strings.TrimSpace(g.Credentials)
	if creds == "" {
		creds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS")
	}
	if creds == "" {
		creds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_FILE")
	}
	if creds == "" {
		creds = os.Getenv("SENTINELBIT_GDRIVE_CREDENTIALS_JSON")
	}

	if creds != "" {
		if strings.HasPrefix(creds, "{") {
			// Direct JSON payload
			opts = append(opts, option.WithCredentialsJSON([]byte(creds)))
		} else {
			// File path
			if _, err := os.Stat(creds); err != nil {
				return nil, fmt.Errorf("Google Drive Anmeldedatei nicht gefunden (%s): %w", creds, err)
			}
			opts = append(opts, option.WithCredentialsFile(creds))
		}
	} else if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		opts = append(opts, option.WithCredentialsFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")))
	} else {
		return nil, errors.New("keine Google Drive Anmeldedaten angegeben (weder Service-Account-JSON noch Datei-Pfad)")
	}

	opts = append(opts, option.WithScopes(drive.DriveScope))
	return drive.NewService(ctx, opts...)
}

// TestConnection verifies access to Google Drive and the target folder
func (g *GDriveUploader) TestConnection(ctx context.Context) (string, error) {
	srv, err := g.getService(ctx)
	if err != nil {
		return "", fmt.Errorf("Google Drive Client konnte nicht initialisiert werden: %w", err)
	}

	folderID := g.FolderID
	if folderID == "" {
		folderID = ExtractFolderID(os.Getenv("SENTINELBIT_GDRIVE_FOLDER_ID"))
	}

	if folderID != "" {
		folder, err := srv.Files.Get(folderID).Fields("id, name, mimeType, trashed").Do()
		if err != nil {
			return "", fmt.Errorf("Google Drive Ordner (ID: %s) nicht erreichbar. Bitte sicherstellen, dass der Ordner für die Service-Account-E-Mail freigegeben ist: %w", folderID, err)
		}
		if folder.Trashed {
			return "", fmt.Errorf("Google Drive Ordner '%s' befindet sich im Papierkorb", folder.Name)
		}
		return fmt.Sprintf("Verbindung erfolgreich! Google Drive Ordner '%s' (ID: %s) erreichbar.", folder.Name, folder.Id), nil
	}

	about, err := srv.About.Get().Fields("user(displayName, emailAddress)").Do()
	if err != nil {
		return "", fmt.Errorf("Verbindung zu Google Drive fehlgeschlagen: %w", err)
	}
	return fmt.Sprintf("Verbindung erfolgreich! Verbunden als %s (%s).", about.User.DisplayName, about.User.EmailAddress), nil
}

// UploadBackup uploads the local backup file to Google Drive and prunes old versions
func (g *GDriveUploader) UploadBackup(ctx context.Context, localFilePath, safeUsername string, retentionCount int) error {
	srv, err := g.getService(ctx)
	if err != nil {
		return err
	}

	folderID := g.FolderID
	if folderID == "" {
		folderID = ExtractFolderID(os.Getenv("SENTINELBIT_GDRIVE_FOLDER_ID"))
	}

	f, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("lokale Backup-Datei konnte nicht geöffnet werden: %w", err)
	}
	defer f.Close()

	fileName := filepath.Base(localFilePath)
	driveFile := &drive.File{
		Name:     fileName,
		MimeType: "application/json",
	}
	if folderID != "" {
		driveFile.Parents = []string{folderID}
	}

	if _, err := srv.Files.Create(driveFile).Media(f).Do(); err != nil {
		return fmt.Errorf("Upload nach Google Drive fehlgeschlagen: %w", err)
	}

	// Also upload or overwrite _latest.json in Google Drive
	latestLocalPath := filepath.Join(filepath.Dir(localFilePath), fmt.Sprintf("SentinelBit_backup_%s_latest.json", safeUsername))
	if latestData, err := os.Open(latestLocalPath); err == nil {
		defer latestData.Close()
		latestName := fmt.Sprintf("SentinelBit_backup_%s_latest.json", safeUsername)
		queryLatest := fmt.Sprintf("name = '%s' and trashed = false", latestName)
		if folderID != "" {
			queryLatest = fmt.Sprintf("'%s' in parents and %s", folderID, queryLatest)
		}

		res, err := srv.Files.List().Q(queryLatest).Fields("files(id)").PageSize(1).Do()
		if err == nil && len(res.Files) > 0 {
			_, _ = srv.Files.Update(res.Files[0].Id, nil).Media(latestData).Do()
		} else {
			latestDriveFile := &drive.File{
				Name:     latestName,
				MimeType: "application/json",
			}
			if folderID != "" {
				latestDriveFile.Parents = []string{folderID}
			}
			_, _ = srv.Files.Create(latestDriveFile).Media(latestData).Do()
		}
	}

	// Retention cleanup on Google Drive
	if retentionCount > 0 {
		query := fmt.Sprintf("name contains 'SentinelBit_backup_%s_' and trashed = false", safeUsername)
		if folderID != "" {
			query = fmt.Sprintf("'%s' in parents and %s", folderID, query)
		}
		listCall := srv.Files.List().Q(query).Fields("files(id, name, createdTime)").OrderBy("createdTime desc").PageSize(100)
		fileList, err := listCall.Do()
		if err == nil {
			var timestampedFiles []*drive.File
			for _, file := range fileList.Files {
				if !strings.HasSuffix(file.Name, "_latest.json") {
					timestampedFiles = append(timestampedFiles, file)
				}
			}
			if len(timestampedFiles) > retentionCount {
				for _, oldFile := range timestampedFiles[retentionCount:] {
					_ = srv.Files.Delete(oldFile.Id).Do()
				}
			}
		}
	}

	return nil
}
