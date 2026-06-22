package repository

import (
	"context"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserRepository handles DB operations for the users table and, since neither
// has a dedicated repository, the failed_login_attempts and password_reset_tokens tables.
type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var user model.User
	if err := r.db.WithContext(ctx).First(&user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Create(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *UserRepository) Update(ctx context.Context, user *model.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// ListPaginated returns a page of users ordered newest-first, plus the total
// count across all pages. emailSearch, when non-empty, filters to emails
// containing it (case-insensitive).
func (r *UserRepository) ListPaginated(ctx context.Context, offset, limit int, emailSearch string) ([]model.User, int64, error) {
	base := r.db.WithContext(ctx).Model(&model.User{})
	if emailSearch != "" {
		base = base.Where("email ILIKE ?", "%"+emailSearch+"%")
	}

	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var users []model.User
	if err := base.Session(&gorm.Session{}).Order("created_at DESC").Offset(offset).Limit(limit).Find(&users).Error; err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// IsPlatformAdmin returns whether the user with the given ID has platform
// admin privileges. Fetches only the is_platform_admin column — the admin
// middleware calls this on every admin request, so it never trusts the JWT
// claim and never pulls the password hash or other fields unnecessarily.
func (r *UserRepository) IsPlatformAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var user model.User
	if err := r.db.WithContext(ctx).Select("is_platform_admin").First(&user, "id = ?", userID).Error; err != nil {
		return false, err
	}
	return user.IsPlatformAdmin, nil
}

// IncrementFailedLogins records a failed login attempt for the given email/IP.
func (r *UserRepository) IncrementFailedLogins(ctx context.Context, email, ipAddress string) error {
	attempt := model.FailedLoginAttempt{
		Email: email,
	}
	if ipAddress != "" {
		attempt.IPAddress = &ipAddress
	}
	return r.db.WithContext(ctx).Create(&attempt).Error
}

// ResetFailedLogins clears all recorded failed login attempts for the given email.
func (r *UserRepository) ResetFailedLogins(ctx context.Context, email string) error {
	return r.db.WithContext(ctx).Where("email = ?", email).Delete(&model.FailedLoginAttempt{}).Error
}

// CountRecentFailedLogins counts failed login attempts for the given email since the provided time.
func (r *UserRepository) CountRecentFailedLogins(ctx context.Context, email string, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&model.FailedLoginAttempt{}).
		Where("email = ? AND attempted_at > ?", email, since).
		Count(&count).Error
	return count, err
}

// CreatePasswordResetToken stores a newly issued password reset token.
func (r *UserRepository) CreatePasswordResetToken(ctx context.Context, token *model.PasswordResetToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

// FindPasswordResetTokenByHash looks up a password reset token by its SHA-256 hash.
func (r *UserRepository) FindPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*model.PasswordResetToken, error) {
	var token model.PasswordResetToken
	if err := r.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

// MarkPasswordResetTokenUsed sets used_at on the given password reset token.
func (r *UserRepository) MarkPasswordResetTokenUsed(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&model.PasswordResetToken{}).
		Where("id = ?", id).
		Update("used_at", time.Now().UTC()).Error
}
