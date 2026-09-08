package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	statesMu sync.Mutex
	states   = make(map[string]time.Time)
)

func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSessionToken() string {
	b := make([]byte, 48)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Sessions stored in memory (simple for now)
var (
	sessionsMu sync.RWMutex
	sessions   = make(map[string]*SessionData)
)

type SessionData struct {
	UserID    string
	Name      string
	Email     string
	ExpiresAt time.Time
}

// LoginRedirect redirects to Construct OAuth
func LoginRedirect(w http.ResponseWriter, r *http.Request) {
	state := generateState()

	statesMu.Lock()
	states[state] = time.Now().Add(10 * time.Minute)
	now := time.Now()
	for k, exp := range states {
		if now.After(exp) {
			delete(states, k)
		}
	}
	statesMu.Unlock()

	params := url.Values{
		"client_id":     {Cfg.OAuthClientID},
		"redirect_uri":  {Cfg.OAuthRedirectURI},
		"response_type": {"code"},
		"scope":         {"profile email"},
		"state":         {state},
	}

	http.Redirect(w, r, Cfg.OAuthURL+"/oauth/authorize?"+params.Encode(), http.StatusFound)
}

// AuthCallback handles OAuth callback
func AuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Redirect(w, r, Cfg.AppURL+"/?error=missing_code", http.StatusFound)
		return
	}

	statesMu.Lock()
	exp, exists := states[state]
	if exists {
		delete(states, state)
	}
	statesMu.Unlock()

	if !exists || time.Now().After(exp) {
		http.Redirect(w, r, Cfg.AppURL+"/?error=invalid_state", http.StatusFound)
		return
	}

	// Exchange code for token
	tokenData, err := exchangeCode(code)
	if err != nil {
		http.Redirect(w, r, Cfg.AppURL+"/?error=token_exchange", http.StatusFound)
		return
	}

	accessToken, _ := tokenData["access_token"].(string)
	if accessToken == "" {
		http.Redirect(w, r, Cfg.AppURL+"/?error=no_token", http.StatusFound)
		return
	}

	// Fetch user info
	userInfo, err := fetchUserInfo(accessToken)
	if err != nil {
		http.Redirect(w, r, Cfg.AppURL+"/?error=user_info", http.StatusFound)
		return
	}

	userID, _ := userInfo["id"].(string)
	if userID == "" {
		http.Redirect(w, r, Cfg.AppURL+"/?error=bad_user", http.StatusFound)
		return
	}

	name, _ := userInfo["name"].(string)
	email, _ := userInfo["email"].(string)
	if name == "" {
		first, _ := userInfo["first_name"].(string)
		last, _ := userInfo["last_name"].(string)
		name = first + " " + last
	}

	// Create session
	token := generateSessionToken()
	sessionsMu.Lock()
	sessions[token] = &SessionData{
		UserID:    userID,
		Name:      name,
		Email:     email,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   Cfg.IsSecure(),
		MaxAge:   30 * 24 * 60 * 60,
	})

	http.Redirect(w, r, Cfg.AppURL+"/dashboard", http.StatusFound)
}

// AuthMe returns current user
func AuthMe(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	if s == nil {
		WriteJSON(w, 200, map[string]any{"authenticated": false})
		return
	}

	WriteJSON(w, 200, map[string]any{
		"authenticated": true,
		"user": map[string]any{
			"id":    s.UserID,
			"name":  s.Name,
			"email": s.Email,
		},
	})
}

// AuthLogout clears session
func AuthLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		sessionsMu.Lock()
		delete(sessions, c.Value)
		sessionsMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, Cfg.AppURL, http.StatusFound)
}

// getSession returns session from cookie
func getSession(r *http.Request) *SessionData {
	c, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	sessionsMu.RLock()
	s, ok := sessions[c.Value]
	sessionsMu.RUnlock()

	if !ok || time.Now().After(s.ExpiresAt) {
		return nil
	}
	return s
}

// GetSessionUserID returns user ID from session (for dashboard endpoints)
func GetSessionUserID(r *http.Request) string {
	s := getSession(r)
	if s == nil {
		return ""
	}
	return s.UserID
}

func exchangeCode(code string) (map[string]any, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     Cfg.OAuthClientID,
		"client_secret": Cfg.OAuthClientSecret,
		"redirect_uri":  Cfg.OAuthRedirectURI,
	})

	resp, err := http.Post(Cfg.OAuthURL+"/oauth/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token exchange failed: %d", resp.StatusCode)
	}
	return result, nil
}

func fetchUserInfo(accessToken string) (map[string]any, error) {
	req, _ := http.NewRequest("GET", Cfg.OAuthURL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("user info failed: %d", resp.StatusCode)
	}
	return result, nil
}
