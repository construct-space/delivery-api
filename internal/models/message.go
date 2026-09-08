package models

import "time"

type Message struct {
	ID          uint       `gorm:"primaryKey" json:"-"`
	ExternalID  string     `gorm:"size:36;uniqueIndex;not null" json:"id"` // UUID, exposed as "id" in API
	// TODO(backfill): messages.user_id was previously BIGINT. AutoMigrate adds VARCHAR(36).
	UserID      string     `gorm:"size:36;not null;index" json:"-"`
	DomainID    uint       `gorm:"not null;index" json:"domain_id"`
	APIKeyID    uint       `gorm:"index" json:"-"`
	FromEmail   string     `gorm:"size:255;not null" json:"from"`
	FromName    string     `gorm:"size:255" json:"from_name,omitempty"`
	ToEmail     string     `gorm:"size:255;not null;index" json:"to"`
	Subject     string     `gorm:"size:500;not null" json:"subject"`
	HTMLBody    *string    `gorm:"type:text" json:"-"`
	TextBody    *string    `gorm:"type:text" json:"-"`
	Headers     *string    `gorm:"type:text" json:"headers,omitempty"`
	TemplateID  *uint      `gorm:"index" json:"template_id,omitempty"`
	Tags        *string    `gorm:"size:500" json:"tags,omitempty"`
	// Attachments is a JSON array of {filename, content_type, content_b64} as
	// the caller supplied it. Stored alongside the message so the queue
	// worker can rebuild the multipart/mixed envelope without a second
	// fetch; row-per-attachment can come later if we need per-attachment
	// download URLs or scan results.
	Attachments *string    `gorm:"type:text" json:"-"`
	Status      string     `gorm:"size:50;default:queued;index" json:"status"` // queued, sending, sent, delivered, bounced, complained, failed
	Retries     int        `gorm:"default:0" json:"retries"`
	NextRetryAt *time.Time `json:"-"`
	Error       *string    `gorm:"type:text" json:"error,omitempty"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type MessageEvent struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	MessageID uint      `gorm:"not null;index" json:"message_id"`
	Type      string    `gorm:"size:50;not null;index" json:"type"` // queued, sent, delivered, bounced, complained, opened, clicked
	Data      *string   `gorm:"type:text" json:"data,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
