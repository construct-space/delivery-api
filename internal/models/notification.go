package models

import "time"

// Notification is a single delivered notification for a Construct user.
// Created by other services calling POST /api/service/notify, then fanned
// out to in-app (SSE), web push, and mobile push channels in parallel.
type Notification struct {
	ID         uint       `gorm:"primaryKey" json:"-"`
	ExternalID string     `gorm:"size:36;uniqueIndex;not null" json:"id"`
	UserID     string     `gorm:"size:36;not null;index:idx_notif_user_created,priority:1" json:"-"`
	Source     string     `gorm:"size:64;not null" json:"source"`
	Type       string     `gorm:"size:128;not null;index" json:"type"`
	Title      string     `gorm:"size:255;not null" json:"title"`
	Body       string     `gorm:"type:text" json:"body"`
	Link       string     `gorm:"size:500" json:"link,omitempty"`
	Data       *string    `gorm:"type:text" json:"data,omitempty"`
	ReadAt     *time.Time `json:"read_at,omitempty"`
	CreatedAt  time.Time  `gorm:"index:idx_notif_user_created,priority:2,sort:desc" json:"created_at"`
}

type NotificationPreference struct {
	UserID         string    `gorm:"size:36;primaryKey" json:"user_id"`
	InAppEnabled   bool      `gorm:"default:true" json:"in_app_enabled"`
	WebPushEnabled bool      `gorm:"default:true" json:"web_push_enabled"`
	MobileEnabled  bool      `gorm:"default:true" json:"mobile_enabled"`
	EmailFallback  bool      `gorm:"default:false" json:"email_fallback"`
	MutedTypes     *string   `gorm:"type:text" json:"muted_types,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// WebPushSubscription is one browser registration. Endpoint is the canonical
// unique key; the same browser session re-registering replaces the row.
type WebPushSubscription struct {
	ID        uint      `gorm:"primaryKey" json:"-"`
	UserID    string    `gorm:"size:36;not null;index" json:"-"`
	Endpoint  string    `gorm:"type:text;uniqueIndex;not null" json:"endpoint"`
	P256dh    string    `gorm:"size:255;not null" json:"-"`
	Auth      string    `gorm:"size:255;not null" json:"-"`
	UserAgent string    `gorm:"size:500" json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

// DeviceToken is one mobile device registration. Token is the FCM
// registration token (used for both Android and iOS via FCM).
type DeviceToken struct {
	ID         uint      `gorm:"primaryKey" json:"-"`
	UserID     string    `gorm:"size:36;not null;index" json:"-"`
	Platform   string    `gorm:"size:16;not null" json:"platform"`
	Token      string    `gorm:"type:text;uniqueIndex;not null" json:"token"`
	AppVersion string    `gorm:"size:32" json:"app_version,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   time.Time `json:"last_used"`
}
