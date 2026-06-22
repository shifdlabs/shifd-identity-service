package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Sentinel errors returned by SubscriptionService.
var (
	ErrSubscriptionNotFound      = errors.New("subscription not found")
	ErrInvalidSubscriptionStatus = errors.New("status must be one of: pending, active, expired, cancelled, suspended")
)

// SubscriptionService implements subscription CRUD and the active-product
// lookup used to populate the JWT "products" claim.
type SubscriptionService struct {
	subscriptionRepo *repository.SubscriptionRepository
}

func NewSubscriptionService(subscriptionRepo *repository.SubscriptionRepository) *SubscriptionService {
	return &SubscriptionService{subscriptionRepo: subscriptionRepo}
}

// CreateSubscription creates a new subscription for orgID, always starting
// in "active" status per the platform admin subscription-creation flow.
func (s *SubscriptionService) CreateSubscription(ctx context.Context, orgID uuid.UUID, productID, plan string, expiresAt time.Time) (*model.Subscription, error) {
	sub := &model.Subscription{
		OrgID:     orgID,
		ProductID: productID,
		Plan:      plan,
		Status:    model.SubscriptionStatusActive,
		ExpiresAt: expiresAt,
	}

	if err := s.subscriptionRepo.Create(ctx, sub); err != nil {
		return nil, fmt.Errorf("subscription: failed to create subscription: %w", err)
	}
	return sub, nil
}

// GetActiveSubscription returns the active, non-expired subscription for
// orgID and productID, or nil if there is none (not an error case).
func (s *SubscriptionService) GetActiveSubscription(ctx context.Context, orgID uuid.UUID, productID string) (*model.Subscription, error) {
	sub, err := s.subscriptionRepo.FindActiveByOrgAndProduct(ctx, orgID, productID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("subscription: failed to look up active subscription: %w", err)
	}
	return sub, nil
}

// UpdateSubscription updates the status, expiry, and/or plan of an existing
// subscription. Pass "" / a zero time.Time to leave a field unchanged.
func (s *SubscriptionService) UpdateSubscription(ctx context.Context, subID uuid.UUID, status string, expiresAt time.Time, plan string) (*model.Subscription, error) {
	sub, err := s.subscriptionRepo.FindByID(ctx, subID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSubscriptionNotFound
		}
		return nil, fmt.Errorf("subscription: failed to look up subscription: %w", err)
	}

	if status != "" {
		if !isValidSubscriptionStatus(status) {
			return nil, ErrInvalidSubscriptionStatus
		}
		sub.Status = status
	}
	if !expiresAt.IsZero() {
		sub.ExpiresAt = expiresAt
	}
	if plan != "" {
		sub.Plan = plan
	}
	sub.UpdatedAt = time.Now().UTC()

	if err := s.subscriptionRepo.Update(ctx, sub); err != nil {
		return nil, fmt.Errorf("subscription: failed to update subscription: %w", err)
	}
	return sub, nil
}

// ListByOrg returns every subscription for orgID, regardless of status.
func (s *SubscriptionService) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]model.Subscription, error) {
	subs, err := s.subscriptionRepo.FindAllByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("subscription: failed to list subscriptions: %w", err)
	}
	return subs, nil
}

// GetActiveProductsForOrg returns the product_id of every ACTIVE, non-expired
// subscription for orgID. AuthService.Login/Refresh use this to populate the
// JWT "products" claim per the CLAUDE.md JWT Claims Structure.
func (s *SubscriptionService) GetActiveProductsForOrg(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	subs, err := s.subscriptionRepo.FindAllByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("subscription: failed to list subscriptions: %w", err)
	}

	now := time.Now().UTC()
	products := make([]string, 0, len(subs))
	for _, sub := range subs {
		if sub.Status == model.SubscriptionStatusActive && sub.ExpiresAt.After(now) {
			products = append(products, sub.ProductID)
		}
	}
	return products, nil
}

func isValidSubscriptionStatus(status string) bool {
	switch status {
	case model.SubscriptionStatusPending, model.SubscriptionStatusActive, model.SubscriptionStatusExpired,
		model.SubscriptionStatusCancelled, model.SubscriptionStatusSuspended:
		return true
	default:
		return false
	}
}
