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
	ErrNoActiveSubscription      = errors.New("no active subscription found")
)

// UserLimitReachedError indicates an org's active member count has already
// reached its subscription's user_limit seat cap.
type UserLimitReachedError struct {
	Current int
	Limit   int
}

func (e *UserLimitReachedError) Error() string {
	return fmt.Sprintf("user limit reached: %d/%d active members", e.Current, e.Limit)
}

// SubscriptionService implements subscription CRUD and the active-product
// lookup used to populate the JWT "products" claim.
type SubscriptionService struct {
	subscriptionRepo *repository.SubscriptionRepository
	membershipRepo   *repository.OrgMembershipRepository
}

func NewSubscriptionService(subscriptionRepo *repository.SubscriptionRepository, membershipRepo *repository.OrgMembershipRepository) *SubscriptionService {
	return &SubscriptionService{subscriptionRepo: subscriptionRepo, membershipRepo: membershipRepo}
}

// defaultUserLimitForPlan returns the default seat limit for a plan, or nil
// for plans with no limit (e.g. large_enterprise).
func defaultUserLimitForPlan(plan string) *int {
	limit := func(n int) *int { return &n }
	switch plan {
	case model.SubscriptionPlanStandard:
		return limit(50)
	case model.SubscriptionPlanProfessional:
		return limit(200)
	case model.SubscriptionPlanEnterprise:
		return limit(1000)
	case model.SubscriptionPlanLargeEnterprise:
		return nil
	default:
		return nil
	}
}

// CreateSubscription creates a new subscription for orgID, always starting
// in "active" status per the platform admin subscription-creation flow.
// userLimit overrides the plan's default seat limit when non-nil.
func (s *SubscriptionService) CreateSubscription(ctx context.Context, orgID uuid.UUID, productID, plan string, expiresAt time.Time, userLimit *int) (*model.Subscription, error) {
	if userLimit == nil {
		userLimit = defaultUserLimitForPlan(plan)
	}

	sub := &model.Subscription{
		OrgID:     orgID,
		ProductID: productID,
		Plan:      plan,
		Status:    model.SubscriptionStatusActive,
		ExpiresAt: expiresAt,
		UserLimit: userLimit,
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

// ListActiveByOrg returns the ACTIVE, non-expired subscriptions for orgID.
// This is the single definition of "active subscription" reused by the
// products claim and by the per-org views.
func (s *SubscriptionService) ListActiveByOrg(ctx context.Context, orgID uuid.UUID) ([]model.Subscription, error) {
	subs, err := s.subscriptionRepo.FindAllByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("subscription: failed to list subscriptions: %w", err)
	}

	now := time.Now().UTC()
	active := make([]model.Subscription, 0, len(subs))
	for _, sub := range subs {
		if sub.Status == model.SubscriptionStatusActive && sub.ExpiresAt.After(now) {
			active = append(active, sub)
		}
	}
	return active, nil
}

// EnforceUserLimit checks whether orgID can add one more active member under
// its current shifd-approval subscription. It returns ErrNoActiveSubscription
// if orgID has no active subscription for that product, or a
// *UserLimitReachedError if the subscription has a seat cap (UserLimit) that
// orgID's active member count has already reached. A nil UserLimit
// (unlimited) always passes. Callers should run this immediately before
// creating the new org_membership row.
func (s *SubscriptionService) EnforceUserLimit(ctx context.Context, orgID uuid.UUID) error {
	sub, err := s.GetActiveSubscription(ctx, orgID, model.ProductShifdApproval)
	if err != nil {
		return err
	}
	if sub == nil {
		return ErrNoActiveSubscription
	}
	if sub.UserLimit == nil {
		return nil
	}

	count, err := s.membershipRepo.CountActiveByOrgID(ctx, orgID)
	if err != nil {
		return fmt.Errorf("subscription: failed to count active members: %w", err)
	}
	if count >= int64(*sub.UserLimit) {
		return &UserLimitReachedError{Current: int(count), Limit: *sub.UserLimit}
	}
	return nil
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
