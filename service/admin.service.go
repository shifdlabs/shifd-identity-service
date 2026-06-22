package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const defaultPageLimit = 20

// AdminOrgDetail is returned by AdminService.GetOrgDetail: the org plus every
// member and subscription regardless of status — platform admins see
// everything, unlike the tenant-facing OrgService.GetOrgByID which only
// reports active counts/subscriptions to a member.
type AdminOrgDetail struct {
	Org           *model.Organization
	Members       []OrgMember
	Subscriptions []model.Subscription
}

// AdminService implements the platform admin API's business logic. Every
// method here is reachable only after the admin middleware has already
// re-verified users.is_platform_admin from the DB, so none of these methods
// re-check org-level roles the way OrgService's tenant-facing methods do.
type AdminService struct {
	orgRepo          *repository.OrganizationRepository
	membershipRepo   *repository.OrgMembershipRepository
	userRepo         *repository.UserRepository
	refreshTokenRepo *repository.RefreshTokenRepository
	subscriptionSvc  *SubscriptionService
	orgService       *OrgService
}

func NewAdminService(
	orgRepo *repository.OrganizationRepository,
	membershipRepo *repository.OrgMembershipRepository,
	userRepo *repository.UserRepository,
	refreshTokenRepo *repository.RefreshTokenRepository,
	subscriptionSvc *SubscriptionService,
	orgService *OrgService,
) *AdminService {
	return &AdminService{
		orgRepo:          orgRepo,
		membershipRepo:   membershipRepo,
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		subscriptionSvc:  subscriptionSvc,
		orgService:       orgService,
	}
}

// ListOrgs returns a page of organizations ordered newest-first.
func (s *AdminService) ListOrgs(ctx context.Context, page, limit int) ([]model.Organization, int64, error) {
	offset, limit := normalizePagination(page, limit)
	orgs, total, err := s.orgRepo.ListPaginated(ctx, offset, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: failed to list organizations: %w", err)
	}
	return orgs, total, nil
}

// CreateOrgForOwner creates an organization with ownerEmail (an existing
// user) as owner. It delegates the actual create-org-plus-owner-membership
// transaction to OrgService.CreateOrg rather than duplicating it.
func (s *AdminService) CreateOrgForOwner(ctx context.Context, name, slug, ownerEmail string) (*model.Organization, error) {
	owner, err := s.userRepo.FindByEmail(ctx, normalizeEmail(ownerEmail))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("admin: failed to look up owner: %w", err)
	}

	return s.orgService.CreateOrg(ctx, owner.ID, name, slug)
}

// GetOrgDetail returns orgID plus every member and subscription, regardless
// of status.
func (s *AdminService) GetOrgDetail(ctx context.Context, orgID uuid.UUID) (*AdminOrgDetail, error) {
	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("admin: failed to look up organization: %w", err)
	}

	memberships, err := s.membershipRepo.FindAllByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("admin: failed to list memberships: %w", err)
	}
	members := make([]OrgMember, 0, len(memberships))
	for _, m := range memberships {
		user, err := s.userRepo.FindByID(ctx, m.UserID)
		if err != nil {
			return nil, fmt.Errorf("admin: failed to look up user %s: %w", m.UserID, err)
		}
		members = append(members, OrgMember{
			UserID:    m.UserID,
			Email:     user.Email,
			Name:      user.Name,
			Role:      m.Role,
			Status:    m.Status,
			InvitedAt: m.InvitedAt,
			JoinedAt:  m.JoinedAt,
		})
	}

	subs, err := s.subscriptionSvc.ListByOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("admin: failed to list subscriptions: %w", err)
	}

	return &AdminOrgDetail{Org: org, Members: members, Subscriptions: subs}, nil
}

// ListUsers returns a page of users ordered newest-first, optionally filtered
// by a case-insensitive partial match on email.
func (s *AdminService) ListUsers(ctx context.Context, page, limit int, emailSearch string) ([]model.User, int64, error) {
	offset, limit := normalizePagination(page, limit)
	users, total, err := s.userRepo.ListPaginated(ctx, offset, limit, emailSearch)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: failed to list users: %w", err)
	}
	return users, total, nil
}

// ForceLogout revokes every refresh token for userID, ending all of that
// user's active sessions.
func (s *AdminService) ForceLogout(ctx context.Context, userID uuid.UUID) error {
	if err := s.refreshTokenRepo.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("admin: failed to revoke refresh tokens: %w", err)
	}
	return nil
}

// normalizePagination guards the repository layer against non-positive page
// or limit values reaching the DB (e.g. via a malformed query param).
func normalizePagination(page, limit int) (offset, normalizedLimit int) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = defaultPageLimit
	}
	return (page - 1) * limit, limit
}
