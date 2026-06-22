package model

import (
	"time"

	"github.com/google/uuid"
)

// Role values for OrgMembership.Role.
const (
	OrgRoleOwner  = "owner"
	OrgRoleAdmin  = "admin"
	OrgRoleMember = "member"
)

// Status values for OrgMembership.Status.
const (
	OrgMembershipStatusInvited   = "invited"
	OrgMembershipStatusActive    = "active"
	OrgMembershipStatusSuspended = "suspended"
)

// OrgMembership maps to the org_memberships table.
type OrgMembership struct {
	ID        uuid.UUID  `gorm:"column:id;type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID  `gorm:"column:user_id;type:uuid;not null;uniqueIndex:idx_org_memberships_user_org"`
	OrgID     uuid.UUID  `gorm:"column:org_id;type:uuid;not null;uniqueIndex:idx_org_memberships_user_org"`
	Role      string     `gorm:"column:role;type:varchar(50);not null;default:member"`
	Status    string     `gorm:"column:status;type:varchar(50);not null;default:active"`
	InvitedBy *uuid.UUID `gorm:"column:invited_by;type:uuid"`
	InvitedAt *time.Time `gorm:"column:invited_at"`
	JoinedAt  *time.Time `gorm:"column:joined_at"`
	CreatedAt time.Time  `gorm:"column:created_at;not null;default:now()"`
}

// TableName overrides the default pluralized name GORM would otherwise infer.
func (OrgMembership) TableName() string {
	return "org_memberships"
}
