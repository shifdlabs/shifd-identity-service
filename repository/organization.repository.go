package repository

import (
	"context"
	"time"

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
// the total count across all pages. plan, when non-empty, filters to orgs
// that have an ACTIVE, non-expired subscription on that plan (e.g. "trial")
// — the same "active subscription" definition used everywhere else in SIS.
func (r *OrganizationRepository) ListPaginated(ctx context.Context, offset, limit int, plan string) ([]model.Organization, int64, error) {
	now := time.Now().UTC()
	base := r.db.WithContext(ctx).Model(&model.Organization{})
	if plan != "" {
		activeOnPlan := r.db.Model(&model.Subscription{}).
			Select("org_id").
			Where("plan = ? AND status = ? AND expires_at > ?", plan, model.SubscriptionStatusActive, now)
		base = base.Where("id IN (?)", activeOnPlan)
	}

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

// OrgSubscription is the one subscription that decides how an org reads in a
// list: the active one lapsing soonest, or — when none is active — the last one
// to end, whatever state it ended in. An org only ever has one product today
// (shifd-approval), so in practice this is just "the org's subscription".
type OrgSubscription struct {
	OrgID     uuid.UUID `gorm:"column:org_id"`
	ProductID string    `gorm:"column:product_id"`
	Plan      string    `gorm:"column:plan"`
	Status    string    `gorm:"column:status"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	UserLimit *int      `gorm:"column:user_limit"`
}

// SubscriptionSummaryByOrgIDs returns that subscription per org id, in one
// query for the whole page. Orgs with no subscription row at all are absent
// from the map — callers render those as "no subscription", not as expired.
func (r *OrganizationRepository) SubscriptionSummaryByOrgIDs(ctx context.Context, orgIDs []uuid.UUID) (map[uuid.UUID]OrgSubscription, error) {
	summary := make(map[uuid.UUID]OrgSubscription, len(orgIDs))
	if len(orgIDs) == 0 {
		return summary, nil
	}

	var rows []OrgSubscription
	if err := r.db.WithContext(ctx).Raw(`
		SELECT DISTINCT ON (org_id) org_id, product_id, plan, status, expires_at, user_limit
		  FROM subscriptions
		 WHERE org_id IN ?
		 ORDER BY org_id,
		          (status = ?) DESC,
		          CASE WHEN status = ? THEN expires_at END ASC,
		          expires_at DESC`,
		orgIDs, model.SubscriptionStatusActive, model.SubscriptionStatusActive,
	).Scan(&rows).Error; err != nil {
		return nil, err
	}

	for _, row := range rows {
		summary[row.OrgID] = row
	}
	return summary, nil
}
