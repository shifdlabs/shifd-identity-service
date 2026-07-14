package service

import (
	"strings"
	"testing"
	"time"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/ShifdLabs/shifd-identity-service/model"
)

// TestMaskEmail covers S-14: emails must be redacted before they reach logs.
func TestMaskEmail(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"john@company.com", "j***@company.com"},
		{"a@company.com", "*@company.com"},
		{"", "***"},
		{"no-at-sign", "***"},
		{"@company.com", "***"},
	}
	for _, tc := range cases {
		if got := MaskEmail(tc.in); got != tc.want {
			t.Errorf("MaskEmail(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The local part must never appear verbatim in the masked output.
	if got := MaskEmail("sensitive@company.com"); strings.Contains(got, "sensitive") {
		t.Errorf("MaskEmail leaked the local part: %q", got)
	}
}

// TestValidatePasswordLength covers S-10: passwords must be within [8, 72] bytes
// so bcrypt's silent 72-byte truncation cannot hide unused entropy.
func TestValidatePasswordLength(t *testing.T) {
	cases := []struct {
		name    string
		pw      string
		wantErr error
	}{
		{"too short", "short", ErrPasswordTooShort},
		{"minimum ok", "12345678", nil},
		{"exactly 72", strings.Repeat("a", 72), nil},
		{"73 too long", strings.Repeat("a", 73), ErrPasswordTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validatePasswordLength(tc.pw); got != tc.wantErr {
				t.Errorf("validatePasswordLength(len=%d) = %v, want %v", len(tc.pw), got, tc.wantErr)
			}
		})
	}
}

// TestIsLockActive covers S-15: a lock with no timestamp must be treated as
// elapsed (never permanent), and a timestamped lock expires after the duration.
func TestIsLockActive(t *testing.T) {
	svc := &AuthService{cfg: &config.Config{AccountLockDurationMinutes: 30}}

	within := time.Now().UTC().Add(-5 * time.Minute)
	elapsed := time.Now().UTC().Add(-31 * time.Minute)

	cases := []struct {
		name string
		user *model.User
		want bool
	}{
		{"not locked", &model.User{IsLocked: false}, false},
		{"locked, nil timestamp -> not permanent", &model.User{IsLocked: true, LockTimestamp: nil}, false},
		{"locked within window", &model.User{IsLocked: true, LockTimestamp: &within}, true},
		{"locked but window elapsed", &model.User{IsLocked: true, LockTimestamp: &elapsed}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := svc.isLockActive(tc.user); got != tc.want {
				t.Errorf("isLockActive() = %v, want %v", got, tc.want)
			}
		})
	}
}
