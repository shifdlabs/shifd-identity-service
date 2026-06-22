package repository

import (
	"context"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OrgMembershipRepository handles DB operations for the org_memberships table.
type OrgMembershipRepository struct {
	db *gorm.DB
}

func NewOrgMembershipRepository(db *gorm.DB) *OrgMembershipRepository {
	return &OrgMembershipRepository{db: db}
}

func (r *OrgMembershipRepository) Create(ctx context.Context, membership *model.OrgMembership) error {
	return r.db.WithContext(ctx).Create(membership).Error
}

func (r *OrgMembershipRepository) FindByUserAndOrg(ctx context.Context, userID, orgID uuid.UUID) (*model.OrgMembership, error) {
	var membership model.OrgMembership
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND org_id = ?", userID, orgID).
		First(&membership).Error; err != nil {
		return nil, err
	}
	return &membership, nil
}

func (r *OrgMembershipRepository) FindAllByOrgID(ctx context.Context, orgID uuid.UUID) ([]model.OrgMembership, error) {
	var memberships []model.OrgMembership
	if err := r.db.WithContext(ctx).Where("org_id = ?", orgID).Find(&memberships).Error; err != nil {
		return nil, err
	}
	return memberships, nil
}

func (r *OrgMembershipRepository) FindAllByUserID(ctx context.Context, userID uuid.UUID) ([]model.OrgMembership, error) {
	var memberships []model.OrgMembership
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&memberships).Error; err != nil {
		return nil, err
	}
	return memberships, nil
}

func (r *OrgMembershipRepository) Update(ctx context.Context, membership *model.OrgMembership) error {
	return r.db.WithContext(ctx).Save(membership).Error
}

func (r *OrgMembershipRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&model.OrgMembership{}, "id = ?", id).Error
}
