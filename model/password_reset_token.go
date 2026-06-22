package model

import (
	"time"

	"github.com/google/uuid"
)

// PasswordResetToken maps to the password_reset_tokens table.
// TokenHash is the SHA-256 hex digest of the raw token; tokens expire after 1 hour and are single-use.
type PasswordResetToken struct {
	ID        uuid.UUID  `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID  `gorm:"column:user_id;type:uuid;not null"`
	TokenHash string     `gorm:"column:token_hash;type:varchar(64);uniqueIndex;not null"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null"`
	UsedAt    *time.Time `gorm:"column:used_at"`
	CreatedAt time.Time  `gorm:"column:created_at;not null;default:now()"`
}

// TableName overrides the default pluralized name GORM would otherwise infer.
func (PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}
