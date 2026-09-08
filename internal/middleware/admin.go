package middleware

import (
	"crypto/subtle"
	"net/http"
	"os"
)

// AdminAuth accepts requests with a matching X-Internal-Secret header.
// The secret is read from INTERNAL_SHARED_SECRET at call time (after config.Load).
func AdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := os.Getenv("INTERNAL_SHARED_SECRET")
		// Constant-time compare; fail closed when the secret is unset.
		if secret == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Secret")), []byte(secret)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
