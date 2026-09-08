package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// TODO(backfill): api_keys.user_id was previously BIGINT. AutoMigrate adds VARCHAR(36).
// Manually backfill from accounts (numeric id → UUID), then drop the old column.
type APIKey struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	UserID     string     `gorm:"size:36;not null;index" json:"user_id"`
	Name       string     `gorm:"size:255;not null" json:"name"`
	KeyHash    string     `gorm:"size:128;uniqueIndex;not null" json:"-"`
	KeyPrefix  string     `gorm:"size:16;not null" json:"key_prefix"`
	DomainID   *uint      `gorm:"index" json:"domain_id,omitempty"`
	Scopes     string     `gorm:"size:500;default:send" json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// GenerateAPIKey creates a new API key and returns the plaintext (shown once)
func GenerateAPIKey() (plaintext string, hash string, prefix string) {
	b := make([]byte, 32)
	rand.Read(b)
	plaintext = "cd_live_" + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(plaintext))
	hash = hex.EncodeToString(h[:])
	prefix = plaintext[:16]
	return
}

// HashAPIKey returns the SHA-256 hash of a key for lookup
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
