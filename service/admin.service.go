package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/ShifdLabs/shifd-identity-service/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const defaultPageLimit = 20

// activationTokenTTL is how long a platform-admin-issued activation link stays
// valid. Longer than the 1h self-service password reset (passwordResetTokenTTL)
// because these links are handed over out-of-band during client onboarding.
const activationTokenTTL = 72 * time.Hour

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
	userService      *UserService
	cfg              *config.Config
}

func NewAdminService(
	orgRepo *repository.OrganizationRepository,
	membershipRepo *repository.OrgMembershipRepository,
	userRepo *repository.UserRepository,
	refreshTokenRepo *repository.RefreshTokenRepository,
	subscriptionSvc *SubscriptionService,
	orgService *OrgService,
	userService *UserService,
	cfg *config.Config,
) *AdminService {
	return &AdminService{
		orgRepo:          orgRepo,
		membershipRepo:   membershipRepo,
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		subscriptionSvc:  subscriptionSvc,
		orgService:       orgService,
		userService:      userService,
		cfg:              cfg,
	}
}

// ActivationLinkResult is returned by CreateActivationLink: a ready-to-hand-over
// link that lets an existing user set their own password, plus its expiry.
type ActivationLinkResult struct {
	ActivationLink string
	ExpiresAt      time.Time
	UserID         uuid.UUID
	Email          string
}

// CreateActivationLink issues a password-set ("activation") link for an
// EXISTING user identified by email, reusing the password-reset token
// machinery (so the link is consumed by the same POST /api/auth/reset-password
// endpoint and the same set-password page). It does NOT create users: an
// unknown email returns ErrUserNotFound. Intended for platform-admin client
// onboarding — the caller hands the returned link to the client's admin.
func (s *AdminService) CreateActivationLink(ctx context.Context, email string) (*ActivationLinkResult, error) {
	user, err := s.userRepo.FindByEmail(ctx, normalizeEmail(email))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("admin: failed to look up user: %w", err)
	}

	rawToken, err := generateSecureToken(passwordResetTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("admin: failed to generate activation token: %w", err)
	}

	expiresAt := time.Now().UTC().Add(activationTokenTTL)
	token := &model.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: hashToken(rawToken),
		ExpiresAt: expiresAt,
	}
	if err := s.userRepo.CreatePasswordResetToken(ctx, token); err != nil {
		return nil, fmt.Errorf("admin: failed to store activation token: %w", err)
	}

	link := fmt.Sprintf("%s/activate?token=%s", strings.TrimRight(s.cfg.FrontendBaseURL, "/"), rawToken)
	return &ActivationLinkResult{
		ActivationLink: link,
		ExpiresAt:      expiresAt,
		UserID:         user.ID,
		Email:          user.Email,
	}, nil
}

// AdminOrg is an org list row plus the subscription that decides its standing,
// so the list can show plan/status/expiry without a detail fetch per row.
// Subscription is nil for an org that has never had one.
type AdminOrg struct {
	Org          model.Organization
	Subscription *repository.OrgSubscription
}

// ListOrgs returns a page of organizations ordered newest-first. plan, when
// non-empty (e.g. "trial"), filters to orgs with an active subscription on
// that plan — an unrecognized plan value simply yields zero results rather
// than an error, same as the email search filter on ListUsers.
func (s *AdminService) ListOrgs(ctx context.Context, page, limit int, plan string) ([]AdminOrg, int64, error) {
	offset, limit := normalizePagination(page, limit)
	orgs, total, err := s.orgRepo.ListPaginated(ctx, offset, limit, plan)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: failed to list organizations: %w", err)
	}

	ids := make([]uuid.UUID, 0, len(orgs))
	for _, org := range orgs {
		ids = append(ids, org.ID)
	}
	subs, err := s.orgRepo.SubscriptionSummaryByOrgIDs(ctx, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: failed to load subscription summary: %w", err)
	}

	rows := make([]AdminOrg, 0, len(orgs))
	for _, org := range orgs {
		row := AdminOrg{Org: org}
		if sub, ok := subs[org.ID]; ok {
			found := sub
			row.Subscription = &found
		}
		rows = append(rows, row)
	}
	return rows, total, nil
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

// AddMember directly adds an existing user (looked up by email) to orgID as an
// ACTIVE member with the given role — the platform-admin equivalent of
// OrgService.InviteMember. role must be "admin" or "member" ("owner" is
// assigned only via org creation).
func (s *AdminService) AddMember(ctx context.Context, orgID uuid.UUID, email, role string) (*model.OrgMembership, error) {
	if role != model.OrgRoleAdmin && role != model.OrgRoleMember {
		return nil, ErrInvalidRole
	}

	if _, err := s.orgRepo.FindByID(ctx, orgID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrgNotFound
		}
		return nil, fmt.Errorf("admin: failed to look up organization: %w", err)
	}

	user, err := s.userRepo.FindByEmail(ctx, normalizeEmail(email))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("admin: failed to look up user: %w", err)
	}

	if _, err := s.membershipRepo.FindByUserAndOrg(ctx, user.ID, orgID); err == nil {
		return nil, ErrAlreadyMember
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("admin: failed to check existing membership: %w", err)
	}

	if err := s.subscriptionSvc.EnforceUserLimit(ctx, orgID); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	membership := &model.OrgMembership{
		UserID:   user.ID,
		OrgID:    orgID,
		Role:     role,
		Status:   model.OrgMembershipStatusActive,
		JoinedAt: &now,
	}
	if err := s.membershipRepo.Create(ctx, membership); err != nil {
		return nil, fmt.Errorf("admin: failed to create membership: %w", err)
	}
	return membership, nil
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

// AdminUser is a user list row plus the login summary derived from that user's
// refresh tokens. LastLoginAt is nil for a user who has never logged in.
type AdminUser struct {
	User           model.User
	LastLoginAt    *time.Time
	ActiveSessions int
	// Non-nil only while a lock is actually in force — see lockedUntil.
	LockedUntil *time.Time
}

// AdminUserDetail is one user with everything the admin panel shows about them.
type AdminUserDetail struct {
	AdminUser
	Orgs []UserOrg
}

// lockedUntil reports when a locked account unlocks itself, or nil when the
// account is not locked *right now*. SIS locks an account after too many failed
// logins (AuthService.handleFailedLogin) but the lock elapses on its own after
// ACCOUNT_LOCK_DURATION_MINUTES, and the next correct login clears the flag —
// so a stale is_locked=true row must not be reported as locked, or the panel
// would show a wall the user can already walk through.
func (s *AdminService) lockedUntil(user *model.User) *time.Time {
	if !user.IsLocked || user.LockTimestamp == nil {
		return nil
	}
	until := user.LockTimestamp.Add(time.Duration(s.cfg.AccountLockDurationMinutes) * time.Minute)
	if !time.Now().UTC().Before(until) {
		return nil
	}
	return &until
}

// ListUsers returns a page of users ordered newest-first, optionally filtered
// by a case-insensitive partial match on email. Each row carries the user's
// last login and live session count, fetched in one extra grouped query for
// the whole page rather than one per user.
func (s *AdminService) ListUsers(ctx context.Context, page, limit int, emailSearch string) ([]AdminUser, int64, error) {
	offset, limit := normalizePagination(page, limit)
	users, total, err := s.userRepo.ListPaginated(ctx, offset, limit, emailSearch)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: failed to list users: %w", err)
	}

	ids := make([]uuid.UUID, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	stats, err := s.refreshTokenRepo.StatsByUserIDs(ctx, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("admin: failed to load session stats: %w", err)
	}

	rows := make([]AdminUser, 0, len(users))
	for _, u := range users {
		row := AdminUser{User: u, LockedUntil: s.lockedUntil(&u)}
		if stat, ok := stats[u.ID]; ok {
			lastLogin := stat.LastLoginAt
			row.LastLoginAt = &lastLogin
			row.ActiveSessions = stat.ActiveSessions
		}
		rows = append(rows, row)
	}
	return rows, total, nil
}

// normalizeEventType keeps only the two event types the feed knows about;
// anything else becomes "" (no filter) so a stale or hand-typed ?type= shows
// everything instead of erroring or silently returning an empty page.
func normalizeEventType(eventType string) string {
	if eventType == repository.EventLogin || eventType == repository.EventLoginFailed {
		return eventType
	}
	return ""
}

// ListLoginEvents returns a page of the platform-wide login feed (successful
// logins and failed attempts, newest first). eventType narrows to one kind;
// anything other than the two known types is ignored rather than rejected, so
// a stale client filter degrades to "show everything" instead of erroring.
func (s *AdminService) ListLoginEvents(ctx context.Context, page, limit int, emailSearch, eventType string) ([]repository.LoginEvent, int64, error) {
	offset, limit := normalizePagination(page, limit)
	events, total, err := s.refreshTokenRepo.ListLoginEvents(ctx, offset, limit, emailSearch, normalizeEventType(eventType))
	if err != nil {
		return nil, 0, fmt.Errorf("admin: failed to list login events: %w", err)
	}
	return events, total, nil
}

// GetUserDetail returns one user with their session summary, lock state and
// org memberships — everything the panel's user page shows, in one call, so it
// no longer has to carry a user object through router state from the list.
func (s *AdminService) GetUserDetail(ctx context.Context, userID uuid.UUID) (*AdminUserDetail, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("admin: failed to look up user: %w", err)
	}

	stats, err := s.refreshTokenRepo.StatsByUserIDs(ctx, []uuid.UUID{user.ID})
	if err != nil {
		return nil, fmt.Errorf("admin: failed to load session stats: %w", err)
	}

	orgs, err := s.userService.ListUserOrgs(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("admin: failed to list user orgs: %w", err)
	}

	detail := &AdminUserDetail{
		AdminUser: AdminUser{User: *user, LockedUntil: s.lockedUntil(user)},
		Orgs:      orgs,
	}
	if stat, ok := stats[user.ID]; ok {
		lastLogin := stat.LastLoginAt
		detail.LastLoginAt = &lastLogin
		detail.ActiveSessions = stat.ActiveSessions
	}
	return detail, nil
}

// ForceLogout revokes every refresh token for userID, ending all of that
// user's active sessions.
func (s *AdminService) ForceLogout(ctx context.Context, userID uuid.UUID) error {
	if err := s.refreshTokenRepo.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("admin: failed to revoke refresh tokens: %w", err)
	}
	return nil
}

// ForceLogoutOrg revokes every refresh token bound to orgID, ending every
// active session that currently has access to that org — every member at
// once, in one call, rather than force-logging-out members one by one.
// This only kills existing sessions; it does not touch subscription status —
// pair it with PATCH .../subscriptions/:id (status: suspended/cancelled) if
// the org should also lose access on its next fresh login.
func (s *AdminService) ForceLogoutOrg(ctx context.Context, orgID uuid.UUID) error {
	if _, err := s.orgRepo.FindByID(ctx, orgID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOrgNotFound
		}
		return fmt.Errorf("admin: failed to look up organization: %w", err)
	}
	if err := s.refreshTokenRepo.RevokeAllByOrgID(ctx, orgID); err != nil {
		return fmt.Errorf("admin: failed to revoke org refresh tokens: %w", err)
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
