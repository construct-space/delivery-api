package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// validateCatToken accepts a `cat_*` identity bearer (issued by accounts'
// OAuth flow, used by the desktop app and SDK callers) and resolves it to
// the user's UUID by calling accounts' /api/accounts/me endpoint with the
// same bearer. A 200 response means the token is valid; the JSON body
// includes the user id we need.
//
// Why /api/accounts/me and not /internal/validate-token: validate-token
// is gated behind the gateway's auth_request and isn't exposed publicly,
// so a cross-VPS service like delivery can't reach it directly. /me is
// the public path that returns the same identity, just driven by the
// caller's Authorization header instead of injected X-Auth-* values.
//
// Results are cached briefly so a burst of sends from one space doesn't
// hit accounts on every email. Cache is keyed on the full token, lives in
// memory, and expires after the TTL — there's no invalidation on logout
// because a) the window is small and b) accounts already kills the token
// in its own DB on logout, so a stale hit would just succeed once more
// before the cache entry ages out.
func validateCatToken(token string) (userID string, ok bool) {
	if Cfg == nil || Cfg.AccountsURL == "" {
		return "", false
	}
	if cached, ok := catTokenCache.lookup(token); ok {
		return cached, true
	}

	url := strings.TrimRight(Cfg.AccountsURL, "/") + "/api/accounts/me"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := catTokenHTTPClient.Do(req)
	if err != nil {
		return "", false
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", false
	}

	var body struct {
		ID   string `json:"id"`
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", false
	}
	uid := body.ID
	if uid == "" {
		uid = body.UUID
	}
	if uid == "" {
		return "", false
	}
	catTokenCache.store(token, uid)
	return uid, true
}

var catTokenHTTPClient = &http.Client{Timeout: 5 * time.Second}

const catTokenCacheTTL = 60 * time.Second

type catTokenEntry struct {
	userID  string
	expires time.Time
}

type catTokenCacheT struct {
	mu sync.RWMutex
	m  map[string]catTokenEntry
}

func (c *catTokenCacheT) lookup(token string) (string, bool) {
	c.mu.RLock()
	e, ok := c.m[token]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.userID, true
}

func (c *catTokenCacheT) store(token, userID string) {
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]catTokenEntry)
	}
	c.m[token] = catTokenEntry{userID: userID, expires: time.Now().Add(catTokenCacheTTL)}
	c.mu.Unlock()
}

var catTokenCache = &catTokenCacheT{}
