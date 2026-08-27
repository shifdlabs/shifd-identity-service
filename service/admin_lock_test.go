package service

import (
	"testing"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/model"
)

func TestLockedUntil(t *testing.T) {
	svc := &AdminService{cfg: &config.Config{AccountLockDurationMinutes: 30}}
	ago := func(d time.Duration) *time.Time {
		ts := time.Now().UTC().Add(-d)
		return &ts
	}

	cases := []struct {
		name       string
		user       model.User
		wantLocked bool
	}{
		{"not locked", model.User{}, false},
		{"locked 5 minutes ago", model.User{IsLocked: true, LockTimestamp: ago(5 * time.Minute)}, true},
		// The lock lifts by itself after AccountLockDurationMinutes, so a row
		// still carrying is_locked=true must report as unlocked.
		{"lock already elapsed", model.User{IsLocked: true, LockTimestamp: ago(31 * time.Minute)}, false},
		{"flag without timestamp never strands the account", model.User{IsLocked: true}, false},
	}

	for _, tc := range cases {
		got := svc.lockedUntil(&tc.user)
		if (got != nil) != tc.wantLocked {
			t.Errorf("%s: lockedUntil() = %v, want locked=%v", tc.name, got, tc.wantLocked)
		}
	}
}
