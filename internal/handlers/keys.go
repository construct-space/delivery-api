package handlers

import (
	"net/http"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
)

// CreateAPIKey handles POST /api/keys
func CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := parseBody(r, &req); err != nil || req.Name == "" {
		WriteJSON(w, 400, map[string]string{"error": "name is required"})
		return
	}

	userID := GetUserIDFromContext(r)
	plaintext, hash, prefix := models.GenerateAPIKey()

	key := models.APIKey{
		UserID:    userID,
		Name:      req.Name,
		KeyHash:   hash,
		KeyPrefix: prefix,
		Scopes:    "send",
	}

	if err := database.DB.Create(&key).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "failed to create key"})
		return
	}

	WriteJSON(w, 201, map[string]any{
		"id":   key.ID,
		"name": key.Name,
		"key":  plaintext, // shown once
	})
}

// ListAPIKeys handles GET /api/keys
func ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	var keys []models.APIKey
	database.DB.Where("user_id = ?", userID).Order("created_at desc").Find(&keys)
	WriteJSON(w, 200, map[string]any{"keys": keys})
}
