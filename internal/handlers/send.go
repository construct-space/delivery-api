package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"construct/delivery/internal/database"
	"construct/delivery/internal/middleware"
	"construct/delivery/internal/models"
	"construct/delivery/internal/queue"

	"github.com/google/uuid"
)

var MessageQueue *queue.Queue

type sendRequest struct {
	From    string            `json:"from"`
	To      string            `json:"to"`
	Subject string            `json:"subject"`
	HTML    string            `json:"html"`
	Text    string            `json:"text"`
	Headers map[string]string `json:"headers,omitempty"`
	Tags    []string          `json:"tags,omitempty"`
	// Layout wraps `html` in a server-rendered chrome before sending.
	// Default is the Construct-branded card (mark + Rubik + footer);
	// pass "none" to send the body as-is for callers shipping pre-styled
	// HTML. See template.go for available layouts.
	Layout string `json:"layout,omitempty"`
	// Space is the wordmark rendered next to the Construct mark in the
	// default layout (e.g. "Weather", "Notes"). Auto-uppercased; defaults
	// to "Construct" when empty. Has no effect when Layout is "none".
	Space string `json:"space,omitempty"`
	// Attachments. Each `content` is a base64-encoded payload. Capped at
	// 10 attachments and 15 MB total decoded size to stay under typical
	// downstream SMTP relay limits (25 MB minus headers + base64 overhead).
	Attachments []sendAttachment `json:"attachments,omitempty"`
}

type sendAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	// Content is base64-encoded. Caller is responsible for the encoding —
	// browsers can call `btoa()` on a binary string or use FileReader's
	// readAsDataURL and strip the prefix.
	Content string `json:"content"`
}

const (
	maxAttachments         = 10
	maxAttachmentBytesEach = 10 * 1024 * 1024 // 10 MB per file
	maxAttachmentBytesTotal = 15 * 1024 * 1024 // 15 MB total decoded
)

// SendEmail handles POST /api/emails
func SendEmail(w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if err := parseBody(r, &req); err != nil {
		WriteJSON(w, 400, map[string]string{"error": "invalid request body"})
		return
	}

	if req.To == "" || req.Subject == "" || (req.HTML == "" && req.Text == "") {
		WriteJSON(w, 400, map[string]string{"error": "to, subject, and html or text are required"})
		return
	}

	// Attachment validation. Decode each base64 payload here so a malformed
	// attachment is caught before persistence — the queue worker treats
	// stored data as trusted to keep its hot path fast.
	if len(req.Attachments) > maxAttachments {
		WriteJSON(w, 400, map[string]string{"error": fmt.Sprintf("too many attachments (max %d)", maxAttachments)})
		return
	}
	totalBytes := 0
	for i, att := range req.Attachments {
		if att.Filename == "" {
			WriteJSON(w, 400, map[string]string{"error": fmt.Sprintf("attachment %d: filename is required", i+1)})
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(att.Content)
		if err != nil {
			WriteJSON(w, 400, map[string]string{"error": fmt.Sprintf("attachment %s: invalid base64", att.Filename)})
			return
		}
		if len(decoded) > maxAttachmentBytesEach {
			WriteJSON(w, 400, map[string]string{"error": fmt.Sprintf("attachment %s exceeds %d MB", att.Filename, maxAttachmentBytesEach/1024/1024)})
			return
		}
		totalBytes += len(decoded)
	}
	if totalBytes > maxAttachmentBytesTotal {
		WriteJSON(w, 400, map[string]string{"error": fmt.Sprintf("attachments exceed total %d MB", maxAttachmentBytesTotal/1024/1024)})
		return
	}

	userID := GetUserIDFromContext(r)

	// v1 policy: every authenticated caller sends From the shared
	// Construct-owned domain. Caller-supplied `from` is intentionally
	// ignored — custom domains will become a paid upgrade later. The
	// shared row carries the DKIM keys; tenant emails sign with that
	// key but stay attributed to userID for tracking, suppression, and
	// quota.
	shared := sharedSendingDomain()
	if shared == "" {
		WriteJSON(w, 503, map[string]string{"error": "shared sending domain not configured"})
		return
	}
	req.From = "Construct <noreply@" + shared + ">"
	var domain models.SendingDomain
	if err := database.DB.Where("domain = ? AND status = ?", shared, "verified").First(&domain).Error; err != nil {
		WriteJSON(w, 503, map[string]string{"error": "shared sending domain not configured: " + shared})
		return
	}

	// Check suppression list
	var suppCount int64
	database.DB.Model(&models.Suppression{}).Where("user_id = ? AND email = ?", userID, req.To).Count(&suppCount)
	if suppCount > 0 {
		WriteJSON(w, 400, map[string]string{"error": "recipient is suppressed (previous bounce or complaint)"})
		return
	}

	// Parse from name
	fromEmail, fromName := parseFrom(req.From)

	// Serialize headers and tags
	var headersJSON *string
	if len(req.Headers) > 0 {
		b, _ := json.Marshal(req.Headers)
		s := string(b)
		headersJSON = &s
	}

	var tags *string
	if len(req.Tags) > 0 {
		s := strings.Join(req.Tags, ",")
		tags = &s
	}

	// Server-rendered layout wraps the caller's html in a branded shell.
	// Default is the Construct chrome (mark + Rubik + footer); pass
	// `layout: "none"` to bypass for pre-styled bodies. `space` becomes
	// the wordmark next to the mark — defaults to "Construct" so platform
	// mail (password resets etc.) keeps the existing chrome unchanged.
	htmlBody := applyLayout(req.Layout, req.Space, req.Subject, req.HTML)

	// Serialize attachments. Already validated above; stored as the
	// caller-supplied base64 so the queue worker can rebuild the
	// envelope without re-encoding.
	var attachmentsJSON *string
	if len(req.Attachments) > 0 {
		b, _ := json.Marshal(req.Attachments)
		s := string(b)
		attachmentsJSON = &s
	}

	// Create message
	msg := models.Message{
		ExternalID:  uuid.New().String(),
		UserID:      userID,
		DomainID:    domain.ID,
		APIKeyID:    middleware.GetAPIKeyID(r), // 0 if session auth
		FromEmail:   fromEmail,
		FromName:    fromName,
		ToEmail:     req.To,
		Subject:     req.Subject,
		HTMLBody:    nilIfEmpty(htmlBody),
		TextBody:    nilIfEmpty(req.Text),
		Headers:     headersJSON,
		Tags:        tags,
		Attachments: attachmentsJSON,
		Status:      "queued",
	}

	if err := database.DB.Create(&msg).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "failed to create message"})
		return
	}

	// Add queued event
	database.DB.Create(&models.MessageEvent{
		MessageID: msg.ID,
		Type:      "queued",
	})

	// Enqueue for delivery
	MessageQueue.Enqueue(msg.ID)

	WriteJSON(w, 202, map[string]any{
		"id":         msg.ExternalID,
		"status":     "queued",
		"created_at": msg.CreatedAt,
	})
}

// ServiceSend handles POST /api/service/send (internal service-to-service)
func ServiceSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From     string            `json:"from"`
		To       string            `json:"to"`
		Subject  string            `json:"subject"`
		HTML     string            `json:"html"`
		Text     string            `json:"text"`
		Template string            `json:"template,omitempty"`
		Data     map[string]string `json:"data,omitempty"`
		Tags     []string          `json:"tags,omitempty"`
	}
	if err := parseBody(r, &req); err != nil {
		WriteJSON(w, 400, map[string]string{"error": "invalid request body"})
		return
	}

	if req.To == "" || req.Subject == "" {
		WriteJSON(w, 400, map[string]string{"error": "to and subject are required"})
		return
	}

	if req.From == "" {
		req.From = "Construct <noreply@lisaos.dev>"
	}

	// For service-to-service, find domain by from address (no user scope)
	fromDomain := extractDomain(req.From)
	var domain models.SendingDomain
	if err := database.DB.Where("domain = ? AND status = ?", fromDomain, "verified").First(&domain).Error; err != nil {
		WriteJSON(w, 400, map[string]string{"error": "sending domain not configured: " + fromDomain})
		return
	}

	fromEmail, fromName := parseFrom(req.From)

	var tags *string
	if len(req.Tags) > 0 {
		s := strings.Join(req.Tags, ",")
		tags = &s
	}

	msg := models.Message{
		ExternalID: uuid.New().String(),
		UserID:     domain.UserID,
		DomainID:   domain.ID,
		FromEmail:  fromEmail,
		FromName:   fromName,
		ToEmail:    req.To,
		Subject:    req.Subject,
		HTMLBody:   nilIfEmpty(req.HTML),
		TextBody:   nilIfEmpty(req.Text),
		Tags:       tags,
		Status:     "queued",
	}

	if err := database.DB.Create(&msg).Error; err != nil {
		WriteJSON(w, 500, map[string]string{"error": "failed to create message"})
		return
	}

	MessageQueue.Enqueue(msg.ID)

	WriteJSON(w, 202, map[string]any{
		"id":     msg.ExternalID,
		"status": "queued",
	})
}

// GetMessage handles GET /api/emails/{id}
func GetMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := GetUserIDFromContext(r)

	var msg models.Message
	query := database.DB.Where("external_id = ?", id)
	if userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if err := query.First(&msg).Error; err != nil {
		WriteJSON(w, 404, map[string]string{"error": "message not found"})
		return
	}

	// Load events
	var events []models.MessageEvent
	database.DB.Where("message_id = ?", msg.ID).Order("created_at asc").Find(&events)

	WriteJSON(w, 200, map[string]any{
		"message": msg,
		"events":  events,
	})
}

// ListMessages handles GET /api/messages
func ListMessages(w http.ResponseWriter, r *http.Request) {
	userID := GetUserIDFromContext(r)
	var msgs []models.Message
	database.DB.Where("user_id = ?", userID).Order("created_at desc").Limit(100).Find(&msgs)
	WriteJSON(w, 200, map[string]any{"messages": msgs})
}

func extractDomain(from string) string {
	// Handle "Name <email@domain>" format
	if idx := strings.LastIndex(from, "<"); idx >= 0 {
		from = from[idx+1:]
		from = strings.TrimRight(from, ">")
	}
	if idx := strings.LastIndex(from, "@"); idx >= 0 {
		return from[idx+1:]
	}
	return from
}

func parseFrom(from string) (email, name string) {
	if idx := strings.LastIndex(from, "<"); idx >= 0 {
		name = strings.TrimSpace(from[:idx])
		email = strings.Trim(from[idx+1:], "<> ")
	} else {
		email = from
	}
	return
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
