package model

import (
	"time"

	"github.com/google/uuid"
)

// FailedLoginAttempt maps to the failed_login_attempts table, used for brute force protection.
type FailedLoginAttempt struct {
	ID          uuid.UUID `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()"`
	Email       string    `gorm:"column:email;type:varchar(255);not null;index:idx_failed_login_email_time"`
	IPAddress   *string   `gorm:"column:ip_address;type:varchar(45)"`
	AttemptedAt time.Time `gorm:"column:attempted_at;not null;default:now();index:idx_failed_login_email_time"`
}

// TableName overrides the default pluralized name GORM would otherwise infer.
func (FailedLoginAttempt) TableName() string {
	return "failed_login_attempts"
}
