package repository

import (
	"context"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OrganizationRepository handles DB operations for the organizations table.
type OrganizationRepository struct {
	db *gorm.DB
}

func NewOrganizationRepository(db *gorm.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

func (r *OrganizationRepository) Create(ctx context.Context, org *model.Organization) error {
	return r.db.WithContext(ctx).Create(org).Error
}

func (r *OrganizationRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.Organization, error) {
	var org model.Organization
	if err := r.db.WithContext(ctx).First(&org, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &org, nil
}

func (r *OrganizationRepository) FindBySlug(ctx context.Context, slug string) (*model.Organization, error) {
	var org model.Organization
	if err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&org).Error; err != nil {
		return nil, err
	}
	return &org, nil
}

func (r *OrganizationRepository) Update(ctx context.Context, org *model.Organization) error {
	return r.db.WithContext(ctx).Save(org).Error
}

// ListPaginated returns a page of organizations ordered newest-first, plus
// the total count across all pages.
func (r *OrganizationRepository) ListPaginated(ctx context.Context, offset, limit int) ([]model.Organization, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.Organization{})

	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var orgs []model.Organization
	if err := base.Session(&gorm.Session{}).Order("created_at DESC").Offset(offset).Limit(limit).Find(&orgs).Error; err != nil {
		return nil, 0, err
	}
	return orgs, total, nil
}
