package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
	"construct/delivery/internal/push"
	"construct/delivery/internal/sse"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/google/uuid"
)

// Wired from main.go. Nil-safe — handlers degrade gracefully if a piece is
// not configured (e.g. SSE works without push, push works without SSE).
var (
	NotifHub        *sse.Hub
	NotifDispatcher *push.Dispatcher
	NotifWebPush    *push.WebPush
)

// ─── service-to-service: emit a notification ──────────────────────────────

type notifyRequest struct {
	UserID string          `json:"user_id"`
	Source string          `json:"source"`
	Type   string          `json:"type"`
	Title  string          `json:"title"`
	Body   string          `json:"body"`
	Link   string          `json:"link,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// ServiceNotify is called by other Construct services (accounts, source,
// billing, oracle…) over the private network with X-Internal-Secret. It
// inserts the notification, fans it out to SSE + push, and returns the row.
func ServiceNotify(w http.ResponseWriter, r *http.Request) {
	if !requireInternalSecret(w, r) {
		return
	}
	var req notifyRequest
	if err := parseBody(r, &req); err != nil {
		WriteJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}
	if req.UserID == "" || req.Type == "" || req.Title == "" {
		WriteJSON(w, 400, map[string]string{"error": "user_id, type, title required"})
		return
	}

	prefs := loadPrefs(req.UserID)
	if !prefs.InAppEnabled && !prefs.WebPushEnabled && !prefs.MobileEnabled {
		WriteJSON(w, 200, map[string]any{"skipped": true, "reason": "user has all channels disabled"})
		return
	}
	if isMuted(prefs, req.Type) {
		WriteJSON(w, 200, map[string]any{"skipped": true, "reason": "type muted"})
		return
	}

	n := &models.Notification{
		ExternalID: uuid.NewString(),
		UserID:     req.UserID,
		Source:     req.Source,
		Type:       req.Type,
		Title:      req.Title,
		Body:       req.Body,
		Link:       req.Link,
		CreatedAt:  time.Now(),
	}
	if len(req.Data) > 0 {
		s := string(req.Data)
		n.Data = &s
	}
	if err := database.DB.Create(n).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "insert failed"})
		return
	}

	if prefs.InAppEnabled && NotifHub != nil {
		NotifHub.Publish(req.UserID, sse.Event{Type: "notification", Notification: n})
		if c, err := unreadCount(req.UserID); err == nil {
			NotifHub.Publish(req.UserID, sse.Event{Type: "unread_count", UnreadCount: &c})
		}
	}

	if NotifDispatcher != nil {
		payload, _ := json.Marshal(map[string]any{
			"id":     n.ExternalID,
			"title":  n.Title,
			"body":   n.Body,
			"link":   n.Link,
			"type":   n.Type,
			"source": n.Source,
		})
		send := *NotifDispatcher
		if !prefs.WebPushEnabled {
			send.Web = nil
		}
		if !prefs.MobileEnabled {
			send.Mobile = nil
		}
		send.Send(n, payload)
	}

	WriteJSON(w, 201, n)
}

// ─── user-facing: self-notify ─────────────────────────────────────────────

type selfNotifyRequest struct {
	Source string          `json:"source"`
	Type   string          `json:"type"`
	Title  string          `json:"title"`
	Body   string          `json:"body"`
	Link   string          `json:"link,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// SelfNotify lets the authenticated user write a notification addressed
// to themselves. Use case: the desktop app, after running a remote
// `assistant.ask` from another device, posts the answer here so it
// lands in the asker's inbox on every signed-in surface (mobile, web).
//
// Same DB row + fan-out as ServiceNotify; user_id is taken from the
// auth context so a client can't impersonate someone else.
func SelfNotify(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req selfNotifyRequest
	if err := parseBody(r, &req); err != nil {
		WriteJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}
	if req.Title == "" {
		WriteJSON(w, 400, map[string]string{"error": "title required"})
		return
	}
	if req.Type == "" {
		req.Type = "self.message"
	}
	if req.Source == "" {
		req.Source = "self"
	}

	prefs := loadPrefs(userID)
	if isMuted(prefs, req.Type) {
		WriteJSON(w, 200, map[string]any{"skipped": true, "reason": "type muted"})
		return
	}

	n := &models.Notification{
		ExternalID: uuid.NewString(),
		UserID:     userID,
		Source:     req.Source,
		Type:       req.Type,
		Title:      req.Title,
		Body:       req.Body,
		Link:       req.Link,
		CreatedAt:  time.Now(),
	}
	if len(req.Data) > 0 {
		s := string(req.Data)
		n.Data = &s
	}
	if err := database.DB.Create(n).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "insert failed"})
		return
	}

	if prefs.InAppEnabled && NotifHub != nil {
		NotifHub.Publish(userID, sse.Event{Type: "notification", Notification: n})
		if c, err := unreadCount(userID); err == nil {
			NotifHub.Publish(userID, sse.Event{Type: "unread_count", UnreadCount: &c})
		}
	}

	if NotifDispatcher != nil {
		payload, _ := json.Marshal(map[string]any{
			"id":     n.ExternalID,
			"title":  n.Title,
			"body":   n.Body,
			"link":   n.Link,
			"type":   n.Type,
			"source": n.Source,
		})
		send := *NotifDispatcher
		if !prefs.WebPushEnabled {
			send.Web = nil
		}
		if !prefs.MobileEnabled {
			send.Mobile = nil
		}
		send.Send(n, payload)
	}

	WriteJSON(w, 201, n)
}

// ─── user-facing: list / count / read / delete ────────────────────────────

func ListNotifications(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	q := database.DB.Where("user_id = ?", userID).Order("created_at desc")
	if r.URL.Query().Get("unread") == "true" {
		q = q.Where("read_at IS NULL")
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	q = q.Limit(limit)
	if since := r.URL.Query().Get("since_id"); since != "" {
		var pivot models.Notification
		if err := database.DB.Where("external_id = ?", since).First(&pivot).Error; err == nil {
			q = q.Where("created_at > ?", pivot.CreatedAt)
		}
	}
	var rows []models.Notification
	q.Find(&rows)
	WriteJSON(w, 200, map[string]any{"notifications": rows})
}

func UnreadCount(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	c, err := unreadCount(userID)
	if err != nil {
		WriteJSON(w, 500, map[string]string{"error": "query failed"})
		return
	}
	WriteJSON(w, 200, map[string]any{"unread": c})
}

func MarkRead(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	id := r.PathValue("id")
	now := time.Now()
	res := database.DB.Model(&models.Notification{}).
		Where("external_id = ? AND user_id = ? AND read_at IS NULL", id, userID).
		Update("read_at", now)
	if res.RowsAffected == 0 {
		WriteJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	publishUnread(userID)
	WriteJSON(w, 200, map[string]any{"ok": true})
}

func MarkAllRead(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	now := time.Now()
	database.DB.Model(&models.Notification{}).
		Where("user_id = ? AND read_at IS NULL", userID).
		Update("read_at", now)
	publishUnread(userID)
	WriteJSON(w, 200, map[string]any{"ok": true})
}

func DeleteNotification(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	id := r.PathValue("id")
	res := database.DB.Where("external_id = ? AND user_id = ?", id, userID).Delete(&models.Notification{})
	if res.RowsAffected == 0 {
		WriteJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	publishUnread(userID)
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// ─── SSE stream ───────────────────────────────────────────────────────────

func StreamNotifications(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	if NotifHub == nil {
		WriteJSON(w, 503, map[string]string{"error": "stream unavailable"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		WriteJSON(w, 500, map[string]string{"error": "streaming unsupported"})
		return
	}
	// The delivery server keeps a finite WriteTimeout for normal JSON APIs;
	// SSE is intentionally long-lived, so clear the per-request write deadline.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)

	connID, ch, unsub := NotifHub.Subscribe(userID)
	defer unsub()

	// Initial hello with current unread count + the subscriber's
	// conn id so REST publishers (operator) can opt out of echoing
	// to themselves via X-Sender-Conn-Id.
	writeSSE(w, "hello", map[string]any{"conn_id": connID})
	if c, err := unreadCount(userID); err == nil {
		writeSSE(w, "unread_count", map[string]any{"unread": c})
		flusher.Flush()
	}

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case evt, open := <-ch:
			if !open {
				return
			}
			writeSSE(w, evt.Type, evt)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, event string, data any) {
	b, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
}

// ─── WebSocket stream ─────────────────────────────────────────────────────
//
// Same hub, same envelope as the SSE stream — clients pick whichever
// transport their platform handles best. Cloudflare's edge is more
// forgiving with WS than with long-lived SSE responses, so the desktop
// app uses this path.
//
// Message envelope (server → client):
//
//	{ "type": "notification" | "unread_count" | "ping",
//	  "notification": { … } | null,
//	  "unread_count": <number> | null }
//
// Auth: WithAuthOrQueryToken reads ?token=cat_… because browser/Tauri
// webview WebSocket constructors can't set Authorization headers.
func WSStreamNotifications(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	if NotifHub == nil {
		WriteJSON(w, 503, map[string]string{"error": "stream unavailable"})
		return
	}

	// OriginPatterns: we accept any origin because the desktop app and
	// Flutter clients send Origin: null or app-specific values, and the
	// auth check above already validates the bearer token. Browsers
	// hitting from my.lisaos.dev go through the gateway, which
	// rewrites Origin anyway.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer c.CloseNow()

	// 5-minute server-side read deadline that we keep extending on every
	// pong / client message. If the connection wedges silently we tear
	// it down so the client backoff loop reconnects.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	connID, ch, unsub := NotifHub.Subscribe(userID)
	defer unsub()

	// Hello frame so the client knows its conn id (used in
	// X-Sender-Conn-Id when publishing via the REST relay so it
	// doesn't echo back to itself).
	_ = wsjson.Write(ctx, c, map[string]any{
		"type":    "hello",
		"conn_id": connID,
	})

	// Initial unread count so the bell renders immediately without a
	// separate REST round-trip.
	if cnt, err := unreadCount(userID); err == nil {
		_ = wsjson.Write(ctx, c, map[string]any{
			"type":         "unread_count",
			"unread_count": cnt,
		})
	}

	// Reader goroutine: drains client messages so the WS library's
	// pong machinery stays alive. Cancels ctx on close/error so the
	// writer loop exits. (Used to process {register, operator} frames
	// for the device-bus relay — that traffic moved to source-api on
	// 2026-05-20 along with the operator-presence concept.)
	go func() {
		defer cancel()
		for {
			var discard map[string]any
			if err := wsjson.Read(ctx, c, &discard); err != nil {
				return
			}
		}
	}()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, open := <-ch:
			if !open {
				return
			}
			if err := wsjson.Write(ctx, c, evt); err != nil {
				return
			}
		case <-heartbeat.C:
			pingCtx, pcancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.Ping(pingCtx)
			pcancel()
			if err != nil {
				return
			}
		}
	}
}

// ─── web push subscription management ─────────────────────────────────────

func VAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	if NotifWebPush == nil || !NotifWebPush.Enabled() {
		WriteJSON(w, 503, map[string]string{"error": "web push not configured"})
		return
	}
	WriteJSON(w, 200, map[string]string{"public_key": NotifWebPush.PublicKey()})
}

type webPushSubRequest struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	UserAgent string `json:"user_agent,omitempty"`
}

func RegisterWebPush(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req webPushSubRequest
	if err := parseBody(r, &req); err != nil || req.Endpoint == "" || req.Keys.P256dh == "" || req.Keys.Auth == "" {
		WriteJSON(w, 400, map[string]string{"error": "endpoint and keys required"})
		return
	}
	now := time.Now()
	sub := models.WebPushSubscription{
		UserID:    userID,
		Endpoint:  req.Endpoint,
		P256dh:    req.Keys.P256dh,
		Auth:      req.Keys.Auth,
		UserAgent: req.UserAgent,
		CreatedAt: now,
		LastUsed:  now,
	}
	// On endpoint conflict, replace the existing row (same browser
	// re-subscribing — possibly under a different user_id after re-login).
	database.DB.Where("endpoint = ?", req.Endpoint).Delete(&models.WebPushSubscription{})
	if err := database.DB.Create(&sub).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "save failed"})
		return
	}
	WriteJSON(w, 201, map[string]any{"ok": true})
}

func UnregisterWebPush(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if err := parseBody(r, &req); err != nil || req.Endpoint == "" {
		WriteJSON(w, 400, map[string]string{"error": "endpoint required"})
		return
	}
	database.DB.Where("user_id = ? AND endpoint = ?", userID, req.Endpoint).Delete(&models.WebPushSubscription{})
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// ─── mobile device tokens (FCM) ───────────────────────────────────────────

type deviceTokenRequest struct {
	Platform   string `json:"platform"`
	Token      string `json:"token"`
	AppVersion string `json:"app_version,omitempty"`
}

func RegisterDevice(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req deviceTokenRequest
	if err := parseBody(r, &req); err != nil || req.Token == "" {
		WriteJSON(w, 400, map[string]string{"error": "token required"})
		return
	}
	if req.Platform != "ios" && req.Platform != "android" {
		WriteJSON(w, 400, map[string]string{"error": "platform must be ios or android"})
		return
	}
	now := time.Now()
	t := models.DeviceToken{
		UserID:     userID,
		Platform:   req.Platform,
		Token:      req.Token,
		AppVersion: req.AppVersion,
		CreatedAt:  now,
		LastUsed:   now,
	}
	database.DB.Where("token = ?", req.Token).Delete(&models.DeviceToken{})
	if err := database.DB.Create(&t).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "save failed"})
		return
	}
	WriteJSON(w, 201, map[string]any{"ok": true})
}

func UnregisterDevice(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := parseBody(r, &req); err != nil || req.Token == "" {
		WriteJSON(w, 400, map[string]string{"error": "token required"})
		return
	}
	database.DB.Where("user_id = ? AND token = ?", userID, req.Token).Delete(&models.DeviceToken{})
	WriteJSON(w, 200, map[string]any{"ok": true})
}

// ─── preferences ──────────────────────────────────────────────────────────

func GetPreferences(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	WriteJSON(w, 200, loadPrefs(userID))
}

type prefsUpdate struct {
	InAppEnabled   *bool    `json:"in_app_enabled,omitempty"`
	WebPushEnabled *bool    `json:"web_push_enabled,omitempty"`
	MobileEnabled  *bool    `json:"mobile_enabled,omitempty"`
	EmailFallback  *bool    `json:"email_fallback,omitempty"`
	MutedTypes     []string `json:"muted_types,omitempty"`
}

func UpdatePreferences(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	if userID == "" {
		WriteJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	var req prefsUpdate
	if err := parseBody(r, &req); err != nil {
		WriteJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}
	p := loadPrefs(userID)
	if req.InAppEnabled != nil {
		p.InAppEnabled = *req.InAppEnabled
	}
	if req.WebPushEnabled != nil {
		p.WebPushEnabled = *req.WebPushEnabled
	}
	if req.MobileEnabled != nil {
		p.MobileEnabled = *req.MobileEnabled
	}
	if req.EmailFallback != nil {
		p.EmailFallback = *req.EmailFallback
	}
	if req.MutedTypes != nil {
		b, _ := json.Marshal(req.MutedTypes)
		s := string(b)
		p.MutedTypes = &s
	}
	p.UpdatedAt = time.Now()
	database.DB.Save(&p)
	WriteJSON(w, 200, p)
}

// ─── helpers ──────────────────────────────────────────────────────────────

func loadPrefs(userID string) models.NotificationPreference {
	var p models.NotificationPreference
	if err := database.DB.Where("user_id = ?", userID).First(&p).Error; err != nil {
		p = models.NotificationPreference{
			UserID:         userID,
			InAppEnabled:   true,
			WebPushEnabled: true,
			MobileEnabled:  true,
			EmailFallback:  false,
			UpdatedAt:      time.Now(),
		}
	}
	return p
}

func isMuted(p models.NotificationPreference, t string) bool {
	if p.MutedTypes == nil {
		return false
	}
	var muted []string
	if err := json.Unmarshal([]byte(*p.MutedTypes), &muted); err != nil {
		return false
	}
	return slices.Contains(muted, t)
}

func unreadCount(userID string) (int64, error) {
	var c int64
	err := database.DB.Model(&models.Notification{}).
		Where("user_id = ? AND read_at IS NULL", userID).Count(&c).Error
	return c, err
}

func publishUnread(userID string) {
	if NotifHub == nil {
		return
	}
	c, err := unreadCount(userID)
	if err != nil {
		return
	}
	NotifHub.Publish(userID, sse.Event{Type: "unread_count", UnreadCount: &c})
}
