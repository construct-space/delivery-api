package models

import "time"

// TODO(backfill): sending_domains.user_id was previously BIGINT. AutoMigrate adds VARCHAR(36).
// Manually backfill from accounts (numeric id → UUID), then drop the old column.
type SendingDomain struct {
	ID                 uint       `gorm:"primaryKey" json:"id"`
	UserID             string     `gorm:"size:36;not null;index" json:"user_id"`
	Domain             string     `gorm:"uniqueIndex;size:255;not null" json:"domain"`
	Status             string     `gorm:"size:50;default:pending" json:"status"` // pending, verified, failed
	DKIMPrivateKey     string     `gorm:"type:text" json:"-"`
	DKIMPublicKey      string     `gorm:"type:text" json:"dkim_public_key"`
	DKIMSelector       string     `gorm:"size:100;default:cd" json:"dkim_selector"`
	SPFVerified        bool       `gorm:"default:false" json:"spf_verified"`
	DKIMVerified       bool       `gorm:"default:false" json:"dkim_verified"`
	DMARCVerified      bool       `gorm:"default:false" json:"dmarc_verified"`
	ReturnPathVerified bool       `gorm:"default:false" json:"return_path_verified"`
	LastVerifiedAt     *time.Time `json:"last_verified_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}
