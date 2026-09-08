package models

import "time"

// TODO(backfill): templates.user_id was previously BIGINT. AutoMigrate adds VARCHAR(36).
type Template struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    string    `gorm:"size:36;not null;index" json:"user_id"`
	Name      string    `gorm:"size:255;not null" json:"name"`
	Subject   string    `gorm:"size:500" json:"subject"`
	HTMLBody  string    `gorm:"type:text" json:"html_body"`
	TextBody  string    `gorm:"type:text" json:"text_body"`
	Variables *string   `gorm:"type:text" json:"variables,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TODO(backfill): suppressions.user_id was previously BIGINT. AutoMigrate adds VARCHAR(36).
type Suppression struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    string    `gorm:"size:36;not null;index" json:"user_id"`
	Email     string    `gorm:"size:255;not null;index" json:"email"`
	Reason    string    `gorm:"size:50;not null" json:"reason"` // bounce, complaint, manual
	Source    string    `gorm:"size:100" json:"source"`
	CreatedAt time.Time `json:"created_at"`
}
