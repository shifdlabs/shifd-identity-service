package repository

import (
	"context"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SubscriptionRepository handles DB operations for the subscriptions table.
type SubscriptionRepository struct {
	db *gorm.DB
}

func NewSubscriptionRepository(db *gorm.DB) *SubscriptionRepository {
	return &SubscriptionRepository{db: db}
}

func (r *SubscriptionRepository) Create(ctx context.Context, sub *model.Subscription) error {
	return r.db.WithContext(ctx).Create(sub).Error
}

func (r *SubscriptionRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.Subscription, error) {
	var sub model.Subscription
	if err := r.db.WithContext(ctx).First(&sub, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &sub, nil
}

// FindActiveByOrgAndProduct returns the active, non-expired subscription for the given org and product.
func (r *SubscriptionRepository) FindActiveByOrgAndProduct(ctx context.Context, orgID uuid.UUID, productID string) (*model.Subscription, error) {
	var sub model.Subscription
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND product_id = ? AND status = ? AND expires_at > ?",
			orgID, productID, model.SubscriptionStatusActive, time.Now().UTC()).
		First(&sub).Error
	if err != nil {
		return nil, err
	}
	return &sub, nil
}

func (r *SubscriptionRepository) FindAllByOrgID(ctx context.Context, orgID uuid.UUID) ([]model.Subscription, error) {
	var subs []model.Subscription
	if err := r.db.WithContext(ctx).Where("org_id = ?", orgID).Find(&subs).Error; err != nil {
		return nil, err
	}
	return subs, nil
}

func (r *SubscriptionRepository) Update(ctx context.Context, sub *model.Subscription) error {
	return r.db.WithContext(ctx).Save(sub).Error
}
