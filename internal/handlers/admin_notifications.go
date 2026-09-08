package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
	"construct/delivery/internal/sse"

	"github.com/google/uuid"
)

// admin_notifications.go — staff-facing reads + a debug "send test" endpoint.
// Mirrors the shape of admin.go (server-side pagination, {data,total,page,limit}
// for lists). Auth is supplied by adminAuth middleware in main.go.

// GET /api/admin/notifications
//
// Filters: ?user_id, ?source, ?type, ?unread=true, ?since=<iso8601>
// Pagination: ?page (>=1, default 1), ?limit (default 25, max 200).
func AdminListNotifications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}

	query := database.DB.Model(&models.Notification{})
	if v := q.Get("user_id"); v != "" {
		query = query.Where("user_id = ?", v)
	}
	if v := q.Get("source"); v != "" {
		query = query.Where("source = ?", v)
	}
	if v := q.Get("type"); v != "" {
		query = query.Where("type = ?", v)
	}
	if q.Get("unread") == "true" {
		query = query.Where("read_at IS NULL")
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			query = query.Where("created_at >= ?", t)
		}
	}

	var total int64
	query.Count(&total)

	var rows []models.Notification
	query.Order("created_at desc").Offset((page - 1) * limit).Limit(limit).Find(&rows)

	WriteJSON(w, 200, map[string]any{
		"data":  rows,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// GET /api/admin/notifications/stats
//
// One-shot aggregates for the operations dashboard: totals, read/unread split,
// counts by source and type, push surface inventory, last-24h volume.
func AdminNotificationStats(w http.ResponseWriter, r *http.Request) {
	var total, unread, last24h int64
	database.DB.Model(&models.Notification{}).Count(&total)
	database.DB.Model(&models.Notification{}).Where("read_at IS NULL").Count(&unread)
	database.DB.Model(&models.Notification{}).
		Where("created_at >= ?", time.Now().Add(-24*time.Hour)).Count(&last24h)

	type bucket struct {
		Key   string `json:"key"`
		Count int64  `json:"count"`
	}
	bySource := []bucket{}
	database.DB.Model(&models.Notification{}).
		Select("source as key, COUNT(*) as count").
		Group("source").Order("count desc").Limit(20).Scan(&bySource)

	byType := []bucket{}
	database.DB.Model(&models.Notification{}).
		Select("type as key, COUNT(*) as count").
		Group("type").Order("count desc").Limit(20).Scan(&byType)

	var webSubs, devTokens int64
	database.DB.Model(&models.WebPushSubscription{}).Count(&webSubs)
	database.DB.Model(&models.DeviceToken{}).Count(&devTokens)

	var iosTokens, androidTokens int64
	database.DB.Model(&models.DeviceToken{}).Where("platform = ?", "ios").Count(&iosTokens)
	database.DB.Model(&models.DeviceToken{}).Where("platform = ?", "android").Count(&androidTokens)

	WriteJSON(w, 200, map[string]any{
		"total":     total,
		"unread":    unread,
		"last_24h":  last24h,
		"read":      total - unread,
		"by_source": bySource,
		"by_type":   byType,
		"push_surfaces": map[string]any{
			"web_subscriptions": webSubs,
			"device_tokens":     devTokens,
			"ios":               iosTokens,
			"android":           androidTokens,
		},
	})
}

// POST /api/admin/notifications/test
//
// Debug/support tool: emit a notification to a target user as if a service
// had called /internal/notify. Same fanout path (DB → SSE → web push →
// mobile push) so staff can verify the user's surfaces are wired correctly.
// Source defaults to "oracle" so test events are easy to filter out later.
type adminTestNotifyRequest struct {
	UserID string          `json:"user_id"`
	Source string          `json:"source"`
	Type   string          `json:"type"`
	Title  string          `json:"title"`
	Body   string          `json:"body"`
	Link   string          `json:"link,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

func AdminSendTestNotification(w http.ResponseWriter, r *http.Request) {
	var req adminTestNotifyRequest
	if err := parseBody(r, &req); err != nil {
		WriteJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}
	if req.UserID == "" || req.Title == "" {
		WriteJSON(w, 400, map[string]string{"error": "user_id and title required"})
		return
	}
	if req.Source == "" {
		req.Source = "oracle"
	}
	if req.Type == "" {
		req.Type = "test.message"
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

	if NotifHub != nil {
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
		NotifDispatcher.Send(n, payload)
	}

	WriteJSON(w, 201, n)
}
