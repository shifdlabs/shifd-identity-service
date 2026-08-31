package repository

import (
	"context"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/model"
	"github.com/google/uuid"
)

// This file only reads the login trail the auth flow already leaves behind:
// refresh_tokens gets one row per successful login (never updated afterwards —
// Refresh reuses the row), failed_login_attempts one row per failure. That is
// enough to answer "who logged in, when, from what, and who is still signed
// in" without introducing an audit-log table. It lives on
// RefreshTokenRepository because that is the table doing the work and the one
// AdminService already holds.

// Login event types returned by ListLoginEvents / accepted as its filter.
const (
	EventLogin       = "login"
	EventLoginFailed = "login_failed"
)

// UserSessionStats summarizes one user's refresh tokens.
type UserSessionStats struct {
	UserID         uuid.UUID `gorm:"column:user_id"`
	LastLoginAt    time.Time `gorm:"column:last_login_at"`
	ActiveSessions int       `gorm:"column:active_sessions"`
}

// StatsByUserIDs returns, per user id, when that user last logged in and how
// many of their sessions are still alive (not revoked, not expired). Users who
// have never logged in are absent from the map — callers treat that as "never".
func (r *RefreshTokenRepository) StatsByUserIDs(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]UserSessionStats, error) {
	stats := make(map[uuid.UUID]UserSessionStats, len(userIDs))
	if len(userIDs) == 0 {
		return stats, nil
	}

	var rows []UserSessionStats
	if err := r.db.WithContext(ctx).
		Model(&model.RefreshToken{}).
		Select(
			"user_id, MAX(created_at) AS last_login_at, COUNT(*) FILTER (WHERE revoked_at IS NULL AND expires_at > ?) AS active_sessions",
			time.Now().UTC(),
		).
		Where("user_id IN ?", userIDs).
		Group("user_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	for _, row := range rows {
		stats[row.UserID] = row
	}
	return stats, nil
}

// LoginEvent is one row of the platform-wide login feed. UserID/OrgID are nil
// for a failed attempt on an email that matches no account; DeviceInfo is only
// set on successes and IPAddress only on failures, because that is all each
// side records.
type LoginEvent struct {
	Type       string     `gorm:"column:type"`
	At         time.Time  `gorm:"column:at"`
	UserID     *uuid.UUID `gorm:"column:user_id"`
	Email      string     `gorm:"column:email"`
	Name       string     `gorm:"column:name"`
	OrgID      *uuid.UUID `gorm:"column:org_id"`
	OrgName    *string    `gorm:"column:org_name"`
	DeviceInfo *string    `gorm:"column:device_info"`
	IPAddress  *string    `gorm:"column:ip_address"`
}

// loginEventsSQL is the union both the count and the page select from. The
// NULL casts are required: Postgres needs a type for every column of a UNION
// branch that has no source column.
// ponytail: the union is built per request and neither created_at nor
// attempted_at is indexed for a global sort, so this scans both tables. Fine
// for an internal panel at a few hundred thousand rows — add
// idx_refresh_tokens_created_at (and the equivalent on attempted_at) before it
// stops being fine.
const loginEventsSQL = `
SELECT 'login' AS type, rt.created_at AS at, u.id AS user_id, u.email, u.name,
       rt.org_id, o.name AS org_name, rt.device_info, NULL::varchar AS ip_address
  FROM refresh_tokens rt
  JOIN users u ON u.id = rt.user_id
  LEFT JOIN organizations o ON o.id = rt.org_id
UNION ALL
SELECT 'login_failed', f.attempted_at, u.id, f.email, COALESCE(u.name, ''),
       NULL::uuid, NULL::varchar, NULL::varchar, f.ip_address
  FROM failed_login_attempts f
  LEFT JOIN users u ON u.email = f.email
`

// ListLoginEvents returns a page of login events newest-first, plus the total
// across all pages. emailSearch filters case-insensitively on the email the
// attempt was made with; eventType, when non-empty, narrows to EventLogin or
// EventLoginFailed.
func (r *RefreshTokenRepository) ListLoginEvents(ctx context.Context, offset, limit int, emailSearch, eventType string) ([]LoginEvent, int64, error) {
	where := ""
	args := []interface{}{}
	if emailSearch != "" {
		where += " AND email ILIKE ?"
		args = append(args, "%"+emailSearch+"%")
	}
	if eventType != "" {
		where += " AND type = ?"
		args = append(args, eventType)
	}
	where = " WHERE TRUE" + where

	var total int64
	if err := r.db.WithContext(ctx).
		Raw("SELECT COUNT(*) FROM ("+loginEventsSQL+") e"+where, args...).
		Scan(&total).Error; err != nil {
		return nil, 0, err
	}

	events := []LoginEvent{}
	if err := r.db.WithContext(ctx).
		Raw("SELECT * FROM ("+loginEventsSQL+") e"+where+" ORDER BY at DESC LIMIT ? OFFSET ?", append(args, limit, offset)...).
		Scan(&events).Error; err != nil {
		return nil, 0, err
	}
	return events, total, nil
}
