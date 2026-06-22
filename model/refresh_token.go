package model

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken maps to the refresh_tokens table.
// TokenHash is the SHA-256 hex digest of the raw token; the raw value is never stored.
type RefreshToken struct {
	ID         uuid.UUID  `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID     uuid.UUID  `gorm:"column:user_id;type:uuid;not null;index"`
	OrgID      *uuid.UUID `gorm:"column:org_id;type:uuid"`
	TokenHash  string     `gorm:"column:token_hash;type:varchar(64);uniqueIndex;not null"`
	ExpiresAt  time.Time  `gorm:"column:expires_at;not null"`
	RevokedAt  *time.Time `gorm:"column:revoked_at"`
	DeviceInfo *string    `gorm:"column:device_info;type:varchar(500)"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null;default:now()"`
}

// TableName overrides the default pluralized name GORM would otherwise infer.
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
