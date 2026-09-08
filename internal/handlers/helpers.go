package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"construct/delivery/internal/config"
	"construct/delivery/internal/middleware"
)

var Cfg *config.Config

// secretEquals compares two secrets in constant time so a wrong
// X-Internal-Secret can't be recovered byte-by-byte via response timing.
func secretEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func parseBody(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// WithAuth wraps a handler and accepts three identity sources, tried in order:
//  1. Gateway injection — my.lisaos.dev's nginx validates the user's
//     session against accounts, then forwards X-Auth-User-ID + X-Internal-Secret.
//     Delivery trusts the gateway when X-Internal-Secret matches and adopts the
//     user id verbatim. This is how the tenant UI (my/spaces/delivery) talks to
//     delivery without delivery having to run its own login flow.
//  2. Session cookie — legacy path from when delivery had its own OAuth login.
//     Kept for now so we don't break anything that still uses it.
//  3. Tenant API key (Bearer cd_live_…) — programmatic callers (Ghost, apps,
//     accounts/source sending transactional mail).
func WithAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Gateway-injected identity. Require the shared secret to prevent
		// any origin from spoofing X-Auth-User-ID; only the trusted gateway
		// has the secret.
		if userID := gatewayUserID(r); userID != "" {
			r = r.WithContext(context.WithValue(r.Context(), sessionUserIDKey, userID))
			next(w, r)
			return
		}

		// 2. Session cookie (legacy).
		if userID := GetSessionUserID(r); userID != "" {
			r = r.WithContext(context.WithValue(r.Context(), sessionUserIDKey, userID))
			next(w, r)
			return
		}

		// 3. Tenant API key.
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer cd_live_") {
			middleware.APIKeyAuth(http.HandlerFunc(next)).ServeHTTP(w, r)
			return
		}

		// 4. cat_* identity bearer — direct from the desktop app or any SDK
		// caller skipping the my.lisaos.dev gateway. Delivery validates
		// it against accounts /internal/validate-token (same call the
		// gateway makes via auth_request) and adopts the resolved user id.
		// This is the path that lets useDelivery() in a space hit
		// delivery.lisaos.dev directly without a gateway hop.
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer cat_") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if userID, ok := validateCatToken(token); ok {
				r = r.WithContext(context.WithValue(r.Context(), sessionUserIDKey, userID))
				next(w, r)
				return
			}
		}

		WriteJSON(w, 401, map[string]string{"error": "authentication required"})
	}
}

// WithAuthOrQueryToken is WithAuth but also accepts ?token=cat_… in the URL
// query, used by the WebSocket handshake — browsers/Tauri webview/Flutter
// can't set custom headers on a `WebSocket` constructor, so the bearer rides
// in the URL. The token is rewritten into the Authorization header before
// WithAuth runs, so all of WithAuth's existing paths apply unchanged.
func WithAuthOrQueryToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			if t := r.URL.Query().Get("token"); t != "" {
				r.Header.Set("Authorization", "Bearer "+t)
			}
		}
		WithAuth(next).ServeHTTP(w, r)
	}
}

// gatewayUserID returns the caller's user id if the request carries a valid
// X-Internal-Secret from the my.lisaos.dev gateway; otherwise "".
// An empty INTERNAL_SHARED_SECRET means gateway auth is disabled — never trust
// a missing-on-both-sides configuration.
func gatewayUserID(r *http.Request) string {
	if Cfg == nil || Cfg.InternalSharedSecret == "" {
		return ""
	}
	if !secretEquals(r.Header.Get("X-Internal-Secret"), Cfg.InternalSharedSecret) {
		return ""
	}
	return r.Header.Get("X-Auth-User-ID")
}

type ctxKey string

const sessionUserIDKey ctxKey = "session_user_id"

// GetUserIDFromContext returns user ID from either session or API key context.
func GetUserIDFromContext(r *http.Request) string {
	// From session
	if v, ok := r.Context().Value(sessionUserIDKey).(string); ok && v != "" {
		return v
	}
	// From API key middleware
	return middleware.GetUserID(r)
}
