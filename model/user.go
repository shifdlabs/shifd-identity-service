package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User maps to the users table.
type User struct {
	ID              uuid.UUID      `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()"`
	Email           string         `gorm:"column:email;type:varchar(255);uniqueIndex;not null"`
	PasswordHash    string         `gorm:"column:password_hash;type:varchar(255);not null"`
	Name            string         `gorm:"column:name;type:varchar(255);not null"`
	Phone           *string        `gorm:"column:phone;type:varchar(50)"`
	IsPlatformAdmin bool           `gorm:"column:is_platform_admin;not null;default:false"`
	EmailVerifiedAt *time.Time     `gorm:"column:email_verified_at"`
	IsLocked        bool           `gorm:"column:is_locked;not null;default:false"`
	LockTimestamp   *time.Time     `gorm:"column:lock_timestamp"`
	CreatedAt       time.Time      `gorm:"column:created_at;not null;default:now()"`
	UpdatedAt       time.Time      `gorm:"column:updated_at;not null;default:now()"`
	DeletedAt       gorm.DeletedAt `gorm:"column:deleted_at;index"`
}

// TableName overrides the default pluralized name GORM would otherwise infer.
func (User) TableName() string {
	return "users"
}
