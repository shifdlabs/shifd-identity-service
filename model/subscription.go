package model

import (
	"time"

	"github.com/google/uuid"
)

// Plan values for Subscription.Plan.
const (
	SubscriptionPlanStandard        = "standard"
	SubscriptionPlanProfessional    = "professional"
	SubscriptionPlanEnterprise      = "enterprise"
	SubscriptionPlanLargeEnterprise = "large_enterprise"
)

// Status values for Subscription.Status.
const (
	SubscriptionStatusPending   = "pending"
	SubscriptionStatusActive    = "active"
	SubscriptionStatusExpired   = "expired"
	SubscriptionStatusCancelled = "cancelled"
	SubscriptionStatusSuspended = "suspended"
)

// ProductShifdApproval is the product_id value for the Shifd Approval product.
const ProductShifdApproval = "shifd-approval"

// Subscription maps to the subscriptions table.
type Subscription struct {
	ID        uuid.UUID `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()"`
	OrgID     uuid.UUID `gorm:"column:org_id;type:uuid;not null;index:idx_subscriptions_org_product"`
	ProductID string    `gorm:"column:product_id;type:varchar(100);not null;index:idx_subscriptions_org_product"`
	Plan      string    `gorm:"column:plan;type:varchar(100);not null;default:standard"`
	Status    string    `gorm:"column:status;type:varchar(50);not null;default:active"`
	StartedAt time.Time `gorm:"column:started_at;not null;default:now()"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null"`
	Notes     *string   `gorm:"column:notes;type:text"`
	UserLimit *int      `gorm:"column:user_limit"`
	CreatedAt time.Time `gorm:"column:created_at;not null;default:now()"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null;default:now()"`
}

// TableName overrides the default pluralized name GORM would otherwise infer.
func (Subscription) TableName() string {
	return "subscriptions"
}
