package handlers

import (
	"net/http"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
)

// enroll.go — user-facing enrollment endpoints, called from the my.lisaos.dev
// Services page via the gateway. Auth comes from the standard WithAuth path:
// gateway injection (X-Auth-User-ID + X-Internal-Secret) for UI clicks, or a
// cd_live_* bearer for programmatic callers. Never internal-secret only —
// enrollment must carry a real user identity.

// POST /api/enroll
// Creates a tenant row (a first "Default" API key) if none exists.
// Idempotent — returns {enabled:true, created:false} when the user already
// has keys. On fresh enrollment returns the plaintext api_key once (shown
// in the Services page reveal panel, never stored client-side).
func EnrollDelivery(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "authentication required"})
		return
	}

	var existing int64
	database.DB.Model(&models.APIKey{}).Where("user_id = ?", userID).Count(&existing)
	if existing > 0 {
		WriteJSON(w, 200, map[string]any{"enabled": true, "created": false})
		return
	}

	plaintext, hash, prefix := models.GenerateAPIKey()
	key := models.APIKey{
		UserID:    userID,
		Name:      "Default",
		KeyHash:   hash,
		KeyPrefix: prefix,
		Scopes:    "send",
		CreatedAt: time.Now(),
	}
	if err := database.DB.Create(&key).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "failed to create key"})
		return
	}
	WriteJSON(w, 201, map[string]any{
		"enabled": true,
		"created": true,
		"api_key": plaintext, // plaintext, shown once
	})
}

// DELETE /api/enroll
// Revokes every api_key for this user. Domains + message history are kept
// (audit trail, re-enroll resumes where they left off). A separate "purge"
// endpoint can be added later for true hard delete.
func UnenrollDelivery(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "authentication required"})
		return
	}
	if err := database.DB.Where("user_id = ?", userID).Delete(&models.APIKey{}).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "failed to revoke keys"})
		return
	}
	WriteJSON(w, 200, map[string]any{"enabled": false})
}
