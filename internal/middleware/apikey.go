package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
)

type contextKey string

const (
	CtxUserID   contextKey = "user_id"
	CtxAPIKeyID contextKey = "api_key_id"
)

// APIKeyAuth validates the Authorization: Bearer cd_live_xxx header.
func APIKeyAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"missing api key"}`, http.StatusUnauthorized)
			return
		}

		key := strings.TrimPrefix(auth, "Bearer ")
		hash := models.HashAPIKey(key)

		var apiKey models.APIKey
		if err := database.DB.Where("key_hash = ?", hash).First(&apiKey).Error; err != nil {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}

		if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
			http.Error(w, `{"error":"api key expired"}`, http.StatusUnauthorized)
			return
		}

		// Update last used
		now := time.Now()
		database.DB.Model(&apiKey).Update("last_used_at", now)

		ctx := context.WithValue(r.Context(), CtxUserID, apiKey.UserID)
		ctx = context.WithValue(ctx, CtxAPIKeyID, apiKey.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ServiceAuth validates a static service-to-service API key.
func ServiceAuth(serviceKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+serviceKey {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserID extracts user ID from context.
func GetUserID(r *http.Request) string {
	if v, ok := r.Context().Value(CtxUserID).(string); ok {
		return v
	}
	return ""
}

// GetAPIKeyID extracts API key ID from context.
func GetAPIKeyID(r *http.Request) uint {
	if v, ok := r.Context().Value(CtxAPIKeyID).(uint); ok {
		return v
	}
	return 0
}
