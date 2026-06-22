package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// inviteExpiry mirrors the "Invite tokens... expire after 48 hours" rule in
// CLAUDE.md. org_memberships has no separate token/expiry column, so an
// "invited" membership is treated as expired once InvitedAt is this old.
const inviteExpiry = 48 * time.Hour

// slugPattern enforces "lowercase, alphanumeric and hyphens only, min 3 chars".
var slugPattern = regexp.MustCompile(`^[a-z0-9-]{3,}$`)

// Sentinel errors returned by OrgService. ErrForbidden (membership required)
// is reused from auth.service.go; the rest are specific to org operations.
var (
	ErrInvalidSlug             = errors.New("slug must be lowercase letters, numbers, and hyphens only, at least 3 characters")
	ErrSlugAlreadyExists       = errors.New("organization slug already taken")
	ErrOrgNotFound             = errors.New("organization not found")
	ErrUserNotFound            = errors.New("user not found")
	ErrAlreadyMember           = errors.New("user is already a member of this organization")
	ErrMembershipNotFound      = errors.New("membership not found")
	ErrInviteNotFound          = errors.New("no pending invite found for this user and organization")
	ErrInviteExpired           = errors.New("invite has expired")
	ErrInsufficientPermissions = errors.New("requires owner or admin role in this organization")
	ErrCannotRemoveOwner       = errors.New("cannot remove the organization owner")
	ErrCannotModifyOwner       = errors.New("owner role or status cannot be changed by an admin")
	ErrInvalidRole             = errors.New(`role must be "admin" or "member"`)
	ErrInvalidStatus           = errors.New(`status must be "active" or "suspended"`)
)

// OrgDetail is returned by GetOrgByID: the org plus the summary data its
// detail view needs.
type OrgDetail struct {
	Org                 *model.Organization
	MemberCount         int
	ActiveSubscriptions []model.Subscription
}

// OrgMember is a single row in ListMembers' result: a membership joined with
// the identifying fields of the user it belongs to.
type OrgMember struct {
	UserID    uuid.UUID
	Email     string
	Name      string
	Role      string
	Status    string
	InvitedAt *time.Time
	JoinedAt  *time.Time
}

// OrgService implements org creation, membership management, and the org
// detail/listing views used by the org admin API.
type OrgService struct {
	db               *gorm.DB
	orgRepo          *repository.OrganizationRepository
	membershipRepo   *repository.OrgMembershipRepository
	subscriptionRepo *repository.SubscriptionRepository
	userRepo         *repository.UserRepository
	emailService     *EmailService
}

func NewOrgService(
	db *gorm.DB,
	orgRepo *repository.OrganizationRepository,
	membershipRepo *repository.OrgMembershipRepository,
	subscriptionRepo *repository.SubscriptionRepository,
	userRepo *repository.UserRepository,
	emailService *EmailService,
) *OrgService {
	return &OrgService{
		db:               db,
		orgRepo:          orgRepo,
		membershipRepo:   membershipRepo,
		subscriptionRepo: subscriptionRepo,
		userRepo:         userRepo,
		emailService:     emailService,
	}
}

// CreateOrg creates a new organization and makes userID its owner. The two
// writes happen in a transaction so a failure can never leave an org with
// no owning membership.
func (s *OrgService) CreateOrg(ctx context.Context, userID uuid.UUID, name, slug string) (*model.Organization, error) {
	trimmedSlug := strings.TrimSpace(slug)
	if !slugPattern.MatchString(trimmedSlug) {
		return nil, ErrInvalidSlug
	}

	if _, err := s.orgRepo.FindBySlug(ctx, trimmedSlug); err == nil {
		return nil, ErrSlugAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("org: failed to check existing slug: %w", err)
	}

	org := &model.Organization{
		Name: name,
		Slug: trimmedSlug,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txOrgRepo := repository.NewOrganizationRepository(tx)
		txMembershipRepo := repository.NewOrgMembershipRepository(tx)

		if err := txOrgRepo.Create(ctx, org); err != nil {
			return fmt.Errorf("org: failed to create organization: %w", err)
		}

		now := time.Now().UTC()
		membership := &model.OrgMembership{
			UserID:   userID,
			OrgID:    org.ID,
			Role:     model.OrgRoleOwner,
			Status:   model.OrgMembershipStatusActive,
			JoinedAt: &now,
		}
		if err := txMembershipRepo.Create(ctx, membership); err != nil {
			return fmt.Errorf("org: failed to create owner membership: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return org, nil
}

// GetOrgByID returns org details for requesterUserID, who must be an active
// member. MemberCount counts active memberships only.
func (s *OrgService) GetOrgByID(ctx context.Context, orgID, requesterUserID uuid.UUID) (*OrgDetail, error) {
	if _, err := s.getActiveMembership(ctx, requesterUserID, orgID); err != nil {
		return nil, err
	}

	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("org: failed to look up organization: %w", err)
	}

	memberships, err := s.membershipRepo.FindAllByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("org: failed to list memberships: %w", err)
	}
	activeCount := 0
	for _, m := range memberships {
		if m.Status == model.OrgMembershipStatusActive {
			activeCount++
		}
	}

	subs, err := s.subscriptionRepo.FindAllByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("org: failed to list subscriptions: %w", err)
	}
	now := time.Now().UTC()
	activeSubs := make([]model.Subscription, 0, len(subs))
	for _, sub := range subs {
		if sub.Status == model.SubscriptionStatusActive && sub.ExpiresAt.After(now) {
			activeSubs = append(activeSubs, sub)
		}
	}

	return &OrgDetail{
		Org:                 org,
		MemberCount:         activeCount,
		ActiveSubscriptions: activeSubs,
	}, nil
}

// InviteMember invites inviteeEmail (an existing user) to orgID. inviterUserID
// must be an active owner or admin. The new membership starts as "invited";
// AcceptInvite is what activates it.
func (s *OrgService) InviteMember(ctx context.Context, orgID, inviterUserID uuid.UUID, inviteeEmail string) error {
	inviter, err := s.getActiveMembership(ctx, inviterUserID, orgID)
	if err != nil {
		return err
	}
	if inviter.Role != model.OrgRoleOwner && inviter.Role != model.OrgRoleAdmin {
		return ErrInsufficientPermissions
	}

	normalizedEmail := normalizeEmail(inviteeEmail)
	invitee, err := s.userRepo.FindByEmail(ctx, normalizedEmail)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("org: failed to look up invitee: %w", err)
	}

	if _, err := s.membershipRepo.FindByUserAndOrg(ctx, invitee.ID, orgID); err == nil {
		return ErrAlreadyMember
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("org: failed to check existing membership: %w", err)
	}

	org, err := s.orgRepo.FindByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOrgNotFound
		}
		return fmt.Errorf("org: failed to look up organization: %w", err)
	}

	inviterUser, err := s.userRepo.FindByID(ctx, inviterUserID)
	if err != nil {
		return fmt.Errorf("org: failed to look up inviter: %w", err)
	}

	now := time.Now().UTC()
	membership := &model.OrgMembership{
		UserID:    invitee.ID,
		OrgID:     orgID,
		Role:      model.OrgRoleMember,
		Status:    model.OrgMembershipStatusInvited,
		InvitedBy: &inviterUserID,
		InvitedAt: &now,
	}
	if err := s.membershipRepo.Create(ctx, membership); err != nil {
		return fmt.Errorf("org: failed to create invite: %w", err)
	}

	// inviteToken has no separate secret in this design — the "invited"
	// membership row itself (gated by the invitee's authenticated session) is
	// what AcceptInvite checks — so the org ID doubles as the link parameter.
	if err := s.emailService.SendOrgInvite(ctx, invitee.Email, org.Name, inviterUser.Name, orgID.String()); err != nil {
		log.Printf("org: failed to send invite email to %s: %v", invitee.Email, err)
	}

	return nil
}

// AcceptInvite activates a pending invite for userID in orgID.
func (s *OrgService) AcceptInvite(ctx context.Context, userID, orgID uuid.UUID) error {
	membership, err := s.membershipRepo.FindByUserAndOrg(ctx, userID, orgID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInviteNotFound
		}
		return fmt.Errorf("org: failed to look up invite: %w", err)
	}
	if membership.Status != model.OrgMembershipStatusInvited {
		return ErrInviteNotFound
	}
	if membership.InvitedAt != nil && time.Since(*membership.InvitedAt) > inviteExpiry {
		return ErrInviteExpired
	}

	now := time.Now().UTC()
	membership.Status = model.OrgMembershipStatusActive
	membership.JoinedAt = &now

	if err := s.membershipRepo.Update(ctx, membership); err != nil {
		return fmt.Errorf("org: failed to accept invite: %w", err)
	}
	return nil
}

// UpdateMember changes targetUserID's role and/or status within orgID.
// requesterUserID must be an active owner or admin. role/status may be ""
// (left unchanged); when set they must be in the admin-manageable subset
// (role: admin/member; status: active/suspended — "owner" and "invited" are
// not assignable through this path). An admin (not an owner) may never modify
// an owner's membership.
func (s *OrgService) UpdateMember(ctx context.Context, orgID, requesterUserID, targetUserID uuid.UUID, role, status string) error {
	requester, err := s.getActiveMembership(ctx, requesterUserID, orgID)
	if err != nil {
		return err
	}
	if requester.Role != model.OrgRoleOwner && requester.Role != model.OrgRoleAdmin {
		return ErrInsufficientPermissions
	}

	if role != "" && role != model.OrgRoleAdmin && role != model.OrgRoleMember {
		return ErrInvalidRole
	}
	if status != "" && status != model.OrgMembershipStatusActive && status != model.OrgMembershipStatusSuspended {
		return ErrInvalidStatus
	}

	target, err := s.membershipRepo.FindByUserAndOrg(ctx, targetUserID, orgID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrMembershipNotFound
		}
		return fmt.Errorf("org: failed to look up target membership: %w", err)
	}

	if requester.Role == model.OrgRoleAdmin && target.Role == model.OrgRoleOwner {
		return ErrCannotModifyOwner
	}

	if role != "" {
		target.Role = role
	}
	if status != "" {
		target.Status = status
	}

	if err := s.membershipRepo.Update(ctx, target); err != nil {
		return fmt.Errorf("org: failed to update member: %w", err)
	}
	return nil
}

// RemoveMember removes targetUserID from orgID. requesterUserID must be an
// active owner or admin. The org owner can never be removed this way —
// ownership transfer is out of scope for Phase 1.
func (s *OrgService) RemoveMember(ctx context.Context, orgID, requesterUserID, targetUserID uuid.UUID) error {
	requester, err := s.getActiveMembership(ctx, requesterUserID, orgID)
	if err != nil {
		return err
	}
	if requester.Role != model.OrgRoleOwner && requester.Role != model.OrgRoleAdmin {
		return ErrInsufficientPermissions
	}

	target, err := s.membershipRepo.FindByUserAndOrg(ctx, targetUserID, orgID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrMembershipNotFound
		}
		return fmt.Errorf("org: failed to look up target membership: %w", err)
	}

	if target.Role == model.OrgRoleOwner {
		return ErrCannotRemoveOwner
	}

	if err := s.membershipRepo.Delete(ctx, target.ID); err != nil {
		return fmt.Errorf("org: failed to remove member: %w", err)
	}
	return nil
}

// ListMembers returns every member of orgID. requesterUserID must be an
// active member (any role).
//
// This does one user lookup per membership (no join query exists in the
// repository layer) — fine at Phase 1 membership counts, but worth revisiting
// if org rosters grow large.
func (s *OrgService) ListMembers(ctx context.Context, orgID, requesterUserID uuid.UUID) ([]OrgMember, error) {
	if _, err := s.getActiveMembership(ctx, requesterUserID, orgID); err != nil {
		return nil, err
	}

	memberships, err := s.membershipRepo.FindAllByOrgID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("org: failed to list memberships: %w", err)
	}

	members := make([]OrgMember, 0, len(memberships))
	for _, m := range memberships {
		user, err := s.userRepo.FindByID(ctx, m.UserID)
		if err != nil {
			return nil, fmt.Errorf("org: failed to look up user %s: %w", m.UserID, err)
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
	return members, nil
}

// VerifyActiveMembership returns nil if userID is an active member of orgID,
// otherwise ErrForbidden. For handlers that only need an authorization check
// (e.g. listing an org's subscriptions) without the full org/member detail.
func (s *OrgService) VerifyActiveMembership(ctx context.Context, userID, orgID uuid.UUID) error {
	_, err := s.getActiveMembership(ctx, userID, orgID)
	return err
}

// getActiveMembership looks up userID's membership in orgID and returns
// ErrForbidden unless it exists and is active.
func (s *OrgService) getActiveMembership(ctx context.Context, userID, orgID uuid.UUID) (*model.OrgMembership, error) {
	membership, err := s.membershipRepo.FindByUserAndOrg(ctx, userID, orgID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrForbidden
		}
		return nil, fmt.Errorf("org: failed to look up membership: %w", err)
	}
	if membership.Status != model.OrgMembershipStatusActive {
		return nil, ErrForbidden
	}
	return membership, nil
}
