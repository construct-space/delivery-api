package handlers

import (
	"net/http"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
)

// internal.go — server-to-server endpoints, never reachable from browsers.
// Gated by X-Internal-Secret (matches Cfg.InternalSharedSecret). Used by
// accounts-api to derive scope flags; never forwarded by the gateway.

func requireInternalSecret(w http.ResponseWriter, r *http.Request) bool {
	if Cfg == nil || Cfg.InternalSharedSecret == "" {
		WriteJSON(w, 503, map[string]string{"error": "internal endpoints disabled"})
		return false
	}
	if !secretEquals(r.Header.Get("X-Internal-Secret"), Cfg.InternalSharedSecret) {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return false
	}
	return true
}

// GET /internal/tenant-status?user_id=<uuid>
// Reports whether the given user has been enrolled as a delivery tenant.
// "Enrolled" == at least one api_key row exists for this user_id.
// Accounts' /api/me/scope calls this on every request to surface delivery
// as an enableable capability.
func InternalTenantStatus(w http.ResponseWriter, r *http.Request) {
	if !requireInternalSecret(w, r) {
		return
	}
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		WriteJSON(w, 400, map[string]string{"error": "user_id required"})
		return
	}
	var count int64
	if err := database.DB.Model(&models.APIKey{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "query failed"})
		return
	}
	WriteJSON(w, 200, map[string]any{"enabled": count > 0})
}
