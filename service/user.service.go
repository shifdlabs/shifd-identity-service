package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ErrInvalidName is returned when a profile update would set an empty name
// (users.name is NOT NULL).
var ErrInvalidName = errors.New("name cannot be empty")

// UserOrg is one entry in ListUserOrgs: an org the user belongs to, the user's
// role and membership status in it, and that org's active subscriptions.
type UserOrg struct {
	Org                 *model.Organization
	Role                string
	MembershipStatus    string
	ActiveSubscriptions []model.Subscription
}

// UserService implements the authenticated user's own-profile operations
// behind /api/me/*.
type UserService struct {
	userRepo            *repository.UserRepository
	orgMembershipRepo   *repository.OrgMembershipRepository
	orgRepo             *repository.OrganizationRepository
	subscriptionService *SubscriptionService
}

func NewUserService(
	userRepo *repository.UserRepository,
	orgMembershipRepo *repository.OrgMembershipRepository,
	orgRepo *repository.OrganizationRepository,
	subscriptionService *SubscriptionService,
) *UserService {
	return &UserService{
		userRepo:            userRepo,
		orgMembershipRepo:   orgMembershipRepo,
		orgRepo:             orgRepo,
		subscriptionService: subscriptionService,
	}
}

// GetProfile returns the user's own profile.
func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("user: failed to look up user: %w", err)
	}
	return user, nil
}

// UpdateProfile updates the user's name and/or phone. A nil pointer leaves the
// field unchanged; a non-nil phone with an empty string clears the phone.
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, name, phone *string) (*model.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("user: failed to look up user: %w", err)
	}

	if name != nil {
		trimmed := strings.TrimSpace(*name)
		if trimmed == "" {
			return nil, ErrInvalidName
		}
		user.Name = trimmed
	}
	if phone != nil {
		if trimmed := strings.TrimSpace(*phone); trimmed == "" {
			user.Phone = nil
		} else {
			user.Phone = &trimmed
		}
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("user: failed to update profile: %w", err)
	}
	return user, nil
}

// ChangePassword verifies currentPassword, then sets newPassword (bcrypt cost
// 12, min length enforced). Existing sessions are intentionally left intact:
// this request carries no refresh token to spare, and revoking every session
// of an authenticated user who knows their current password would only log
// them out of the device they just used. (Forgot/reset-password, where the
// account may be compromised, does revoke all sessions.)
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("user: failed to look up user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCredentials
	}
	if len(newPassword) < minPasswordLength {
		return ErrPasswordTooShort
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("user: failed to hash new password: %w", err)
	}
	user.PasswordHash = string(hashed)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("user: failed to update password: %w", err)
	}
	return nil
}

// ListUserOrgs returns every org the user belongs to (any membership status),
// each with the user's role/status and the org's active subscriptions.
//
// One org + one subscription lookup per membership; fine for the handful of
// orgs a user typically belongs to. Soft-deleted orgs are skipped silently.
func (s *UserService) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]UserOrg, error) {
	memberships, err := s.orgMembershipRepo.FindAllByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user: failed to list memberships: %w", err)
	}

	result := make([]UserOrg, 0, len(memberships))
	for _, m := range memberships {
		org, err := s.orgRepo.FindByID(ctx, m.OrgID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue // org soft-deleted; don't surface it
			}
			return nil, fmt.Errorf("user: failed to look up org %s: %w", m.OrgID, err)
		}

		activeSubs, err := s.subscriptionService.ListActiveByOrg(ctx, m.OrgID)
		if err != nil {
			return nil, fmt.Errorf("user: failed to list subscriptions for org %s: %w", m.OrgID, err)
		}

		result = append(result, UserOrg{
			Org:                 org,
			Role:                m.Role,
			MembershipStatus:    m.Status,
			ActiveSubscriptions: activeSubs,
		})
	}
	return result, nil
}
