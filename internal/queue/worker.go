package queue

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"construct/delivery/internal/database"
	"construct/delivery/internal/models"
	smtpPkg "construct/delivery/internal/smtp"
)

// Queue is an in-process, DB-backed message queue.
type Queue struct {
	pending    chan uint
	sender     *smtpPkg.Sender
	maxPerHour int
	sentCount  atomic.Int64
	lastReset  time.Time
}

func New(sender *smtpPkg.Sender, maxPerHour int) *Queue {
	return &Queue{
		pending:    make(chan uint, 10000),
		sender:     sender,
		maxPerHour: maxPerHour,
		lastReset:  time.Now(),
	}
}

// Enqueue adds a message ID to the queue.
func (q *Queue) Enqueue(messageID uint) {
	q.pending <- messageID
}

// Start launches worker goroutines and recovers queued messages from DB.
func (q *Queue) Start(workers int) {
	// Recover unfinished messages
	var msgs []models.Message
	database.DB.Where("status IN ?", []string{"queued", "sending"}).
		Where("next_retry_at IS NULL OR next_retry_at <= ?", time.Now()).
		Find(&msgs)

	for _, m := range msgs {
		q.pending <- m.ID
	}
	if len(msgs) > 0 {
		log.Printf("[queue] Recovered %d pending messages", len(msgs))
	}

	// Start workers
	for i := 0; i < workers; i++ {
		go q.worker(i)
	}

	// Retry scheduler — checks for messages needing retry every 30s
	go q.retryScheduler()

	log.Printf("[queue] Started %d workers (max %d/hour)", workers, q.maxPerHour)
}

func (q *Queue) worker(id int) {
	for msgID := range q.pending {
		q.process(msgID)
	}
}

func (q *Queue) process(msgID uint) {
	// Rate limiting (warmup)
	if q.maxPerHour > 0 {
		if time.Since(q.lastReset) > time.Hour {
			q.sentCount.Store(0)
			q.lastReset = time.Now()
		}
		if q.sentCount.Load() >= int64(q.maxPerHour) {
			// Re-queue for later
			go func() {
				time.Sleep(time.Minute)
				q.pending <- msgID
			}()
			return
		}
	}

	var msg models.Message
	if err := database.DB.First(&msg, msgID).Error; err != nil {
		log.Printf("[queue] Message %d not found: %v", msgID, err)
		return
	}

	if msg.Status == "sent" || msg.Status == "delivered" || msg.Status == "failed" {
		return // already processed
	}

	// Update status to sending
	database.DB.Model(&msg).Update("status", "sending")

	// Load domain for DKIM info
	var domain models.SendingDomain
	database.DB.First(&domain, msg.DomainID)

	// Build the email message
	var headers map[string]string
	if msg.Headers != nil {
		json.Unmarshal([]byte(*msg.Headers), &headers)
	}

	htmlBody := ""
	if msg.HTMLBody != nil {
		htmlBody = *msg.HTMLBody
	}
	textBody := ""
	if msg.TextBody != nil {
		textBody = *msg.TextBody
	}

	// Decode stored attachments. The send handler validated base64 + size
	// caps before persistence, so an error here is unexpected; we log and
	// drop the offending attachment rather than failing the whole send so
	// one bad blob doesn't permanently park a message in the queue.
	var attachments []smtpPkg.Attachment
	if msg.Attachments != nil && *msg.Attachments != "" {
		var stored []struct {
			Filename    string `json:"filename"`
			ContentType string `json:"content_type"`
			Content     string `json:"content"`
		}
		if err := json.Unmarshal([]byte(*msg.Attachments), &stored); err == nil {
			for _, a := range stored {
				decoded, err := base64.StdEncoding.DecodeString(a.Content)
				if err != nil {
					log.Printf("[queue] message %s: skipping attachment %s — base64 decode failed: %v", msg.ExternalID, a.Filename, err)
					continue
				}
				attachments = append(attachments, smtpPkg.Attachment{
					Filename:    a.Filename,
					ContentType: a.ContentType,
					Content:     decoded,
				})
			}
		}
	}

	// Check if this is a raw relay message (starts with headers like "From:" or "DKIM-Signature:")
	var rawMsg []byte
	if htmlBody != "" && (strings.HasPrefix(htmlBody, "From:") || strings.HasPrefix(htmlBody, "DKIM-") || strings.HasPrefix(htmlBody, "Received:") || strings.HasPrefix(htmlBody, "MIME-Version:")) {
		// Raw SMTP relay message — already a complete email, just sign and send
		rawMsg = []byte(htmlBody)
	} else {
		rawMsg = smtpPkg.BuildMessage(msg.FromEmail, msg.FromName, msg.ToEmail, msg.Subject, htmlBody, textBody, headers, attachments)
	}

	// Send
	err := q.sender.Send(msg.FromEmail, msg.ToEmail, rawMsg)

	now := time.Now()
	if err == nil {
		// Success
		database.DB.Model(&msg).Updates(map[string]any{
			"status":  "sent",
			"sent_at": now,
		})
		addEvent(msg.ID, "sent", nil)
		q.sentCount.Add(1)
		log.Printf("[queue] Sent message %s to %s", msg.ExternalID, msg.ToEmail)
	} else if smtpErr, ok := err.(*smtpPkg.SMTPError); ok && !smtpErr.Permanent && msg.Retries < 3 {
		// Temporary failure — retry with backoff
		backoff := time.Duration(1<<uint(msg.Retries)) * 5 * time.Minute
		nextRetry := now.Add(backoff)
		database.DB.Model(&msg).Updates(map[string]any{
			"status":       "queued",
			"retries":      msg.Retries + 1,
			"next_retry_at": nextRetry,
			"error":        smtpErr.Error(),
		})
		errStr := smtpErr.Error()
		addEvent(msg.ID, "deferred", &errStr)
		log.Printf("[queue] Deferred message %s (retry %d in %v): %v", msg.ExternalID, msg.Retries+1, backoff, err)
	} else {
		// Permanent failure
		errStr := err.Error()
		database.DB.Model(&msg).Updates(map[string]any{
			"status": "failed",
			"error":  errStr,
		})
		addEvent(msg.ID, "failed", &errStr)

		// Add to suppression list if it's a bounce
		if smtpErr, ok := err.(*smtpPkg.SMTPError); ok && smtpErr.Permanent {
			database.DB.Create(&models.Suppression{
				UserID: msg.UserID,
				Email:  msg.ToEmail,
				Reason: "bounce",
				Source: smtpErr.Error(),
			})
			addEvent(msg.ID, "bounced", &errStr)
		}

		log.Printf("[queue] Failed message %s to %s: %v", msg.ExternalID, msg.ToEmail, err)
	}
}

func (q *Queue) retryScheduler() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		var msgs []models.Message
		database.DB.Where("status = ? AND next_retry_at <= ?", "queued", time.Now()).
			Limit(100).Find(&msgs)
		for _, m := range msgs {
			q.pending <- m.ID
		}
	}
}

func addEvent(messageID uint, eventType string, data *string) {
	database.DB.Create(&models.MessageEvent{
		MessageID: messageID,
		Type:      eventType,
		Data:      data,
	})
}

// Stats returns current queue stats.
func (q *Queue) Stats() map[string]any {
	return map[string]any{
		"pending":        len(q.pending),
		"sent_this_hour": q.sentCount.Load(),
		"max_per_hour":   q.maxPerHour,
	}
}
