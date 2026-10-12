package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type TeamVaultModel struct {
	ID          string `json:"id"`
	OwnerID     string `json:"owner_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	Role        string `json:"role,omitempty"`
}

type TeamMemberModel struct {
	ID        string `json:"id"`
	VaultID   string `json:"vault_id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username,omitempty"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at"`
}

type EmergencyContactModel struct {
	ID             string  `json:"id"`
	UserID         string  `json:"user_id"`
	ContactEmail   string  `json:"contact_email"`
	WaitTimeDays   int     `json:"wait_time_days"`
	Status         string  `json:"status"`
	CreatedAt      string  `json:"created_at"`
	LastActivityAt *string `json:"last_activity_at,omitempty"`
}

type AuditLogModel struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	IPAddress    string `json:"ip_address"`
	Details      string `json:"details"`
	CreatedAt    string `json:"created_at"`
}

// LogSecurityAudit logs an event to the audit_logs table
func LogSecurityAudit(database *sql.DB, userID, action, resourceType, resourceID, ip, details string) {
	if database == nil || userID == "" {
		return
	}
	logID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = database.Exec(`
		INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, ip_address, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, logID, userID, action, resourceType, resourceID, ip, details, now)
}

// HandleListTeams lists team vaults accessible to the user
func HandleListTeams(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query(`
			SELECT v.id, v.owner_id, v.name, v.description, v.created_at,
			       CASE WHEN v.owner_id = ? THEN 'owner' ELSE m.role END as role
			FROM team_vaults v
			LEFT JOIN team_members m ON v.id = m.vault_id AND m.user_id = ?
			WHERE v.owner_id = ? OR m.user_id = ?
			ORDER BY v.created_at DESC
		`, user.UserId, user.UserId, user.UserId, user.UserId)
		if err != nil {
			HTTPError(w, "Query error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		teams := make([]TeamVaultModel, 0)
		for rows.Next() {
			var t TeamVaultModel
			var desc sql.NullString
			if err := rows.Scan(&t.ID, &t.OwnerID, &t.Name, &desc, &t.CreatedAt, &t.Role); err == nil {
				t.Description = desc.String
				teams = append(teams, t)
			}
		}

		JSONResponse(w, teams, http.StatusOK)
	}
}

// HandleCreateTeam creates a new shared team vault
func HandleCreateTeam(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			HTTPError(w, "Name is required", http.StatusBadRequest)
			return
		}

		teamID := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)

		_, err := db.Exec(`
			INSERT INTO team_vaults (id, owner_id, name, description, created_at)
			VALUES (?, ?, ?, ?, ?)
		`, teamID, user.UserId, req.Name, req.Description, now)
		if err != nil {
			HTTPError(w, "Failed to create team vault", http.StatusInternalServerError)
			return
		}

		LogSecurityAudit(db, user.UserId, "team:create", "team_vault", teamID, r.RemoteAddr, "Created team vault: "+req.Name)

		JSONResponse(w, TeamVaultModel{
			ID:          teamID,
			OwnerID:     user.UserId,
			Name:        req.Name,
			Description: req.Description,
			CreatedAt:   now,
			Role:        "owner",
		}, http.StatusCreated)
	}
}

// HandleListEmergencyContacts returns configured emergency access contacts
func HandleListEmergencyContacts(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, user_id, contact_email, wait_time_days, status, created_at, last_activity_at
			FROM emergency_contacts
			WHERE user_id = ?
			ORDER BY created_at DESC
		`, user.UserId)
		if err != nil {
			HTTPError(w, "Query error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		contacts := make([]EmergencyContactModel, 0)
		for rows.Next() {
			var c EmergencyContactModel
			var lastAct sql.NullString
			if err := rows.Scan(&c.ID, &c.UserID, &c.ContactEmail, &c.WaitTimeDays, &c.Status, &c.CreatedAt, &lastAct); err == nil {
				if lastAct.Valid {
					c.LastActivityAt = &lastAct.String
				}
				contacts = append(contacts, c)
			}
		}

		JSONResponse(w, contacts, http.StatusOK)
	}
}

// HandleCreateEmergencyContact adds an emergency recovery contact
func HandleCreateEmergencyContact(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		var req struct {
			ContactEmail string `json:"contact_email"`
			WaitTimeDays int    `json:"wait_time_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ContactEmail == "" {
			HTTPError(w, "Valid email required", http.StatusBadRequest)
			return
		}
		if req.WaitTimeDays <= 0 {
			req.WaitTimeDays = 30
		}

		contactID := uuid.New().String()
		now := time.Now().UTC().Format(time.RFC3339)

		_, err := db.Exec(`
			INSERT INTO emergency_contacts (id, user_id, contact_email, wait_time_days, status, created_at)
			VALUES (?, ?, ?, ?, 'pending', ?)
		`, contactID, user.UserId, req.ContactEmail, req.WaitTimeDays, now)
		if err != nil {
			HTTPError(w, "Failed to save emergency contact", http.StatusInternalServerError)
			return
		}

		LogSecurityAudit(db, user.UserId, "emergency:add", "emergency_contact", contactID, r.RemoteAddr, "Added contact: "+req.ContactEmail)

		JSONResponse(w, EmergencyContactModel{
			ID:           contactID,
			UserID:       user.UserId,
			ContactEmail: req.ContactEmail,
			WaitTimeDays: req.WaitTimeDays,
			Status:       "pending",
			CreatedAt:    now,
		}, http.StatusCreated)
	}
}

// HandleDeleteEmergencyContact removes an emergency contact
func HandleDeleteEmergencyContact(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		contactID := chi.URLParam(r, "contactId")

		_, err := db.Exec("DELETE FROM emergency_contacts WHERE id = ? AND user_id = ?", contactID, user.UserId)
		if err != nil {
			HTTPError(w, "Failed to delete contact", http.StatusInternalServerError)
			return
		}

		LogSecurityAudit(db, user.UserId, "emergency:delete", "emergency_contact", contactID, r.RemoteAddr, "Deleted emergency contact")
		JSONResponse(w, map[string]string{"status": "deleted"}, http.StatusOK)
	}
}

// HandleListAuditLogs returns recent audit trail events for user (#78)
func HandleListAuditLogs(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromCtx(r)
		rows, err := db.Query(`
			SELECT id, user_id, action, resource_type, resource_id, ip_address, details, created_at
			FROM audit_logs
			WHERE user_id = ?
			ORDER BY created_at DESC
			LIMIT 50
		`, user.UserId)
		if err != nil {
			HTTPError(w, "Query error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		logs := make([]AuditLogModel, 0)
		for rows.Next() {
			var l AuditLogModel
			var ip, details sql.NullString
			if err := rows.Scan(&l.ID, &l.UserID, &l.Action, &l.ResourceType, &l.ResourceID, &ip, &details, &l.CreatedAt); err == nil {
				l.IPAddress = ip.String
				l.Details = details.String
				logs = append(logs, l)
			}
		}

		JSONResponse(w, logs, http.StatusOK)
	}
}
