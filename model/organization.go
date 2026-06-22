package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Organization maps to the organizations table.
type Organization struct {
	ID        uuid.UUID       `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()"`
	Name      string          `gorm:"column:name;type:varchar(255);not null"`
	Slug      string          `gorm:"column:slug;type:varchar(255);uniqueIndex;not null"`
	Metadata  json.RawMessage `gorm:"column:metadata;type:jsonb"`
	CreatedAt time.Time       `gorm:"column:created_at;not null;default:now()"`
	UpdatedAt time.Time       `gorm:"column:updated_at;not null;default:now()"`
	DeletedAt gorm.DeletedAt  `gorm:"column:deleted_at;index"`
}

// TableName overrides the default pluralized name GORM would otherwise infer.
func (Organization) TableName() string {
	return "organizations"
}
