-- Adds a permanent admin-controlled deactivation flag, distinct from
-- is_locked (which is temporary brute-force lockout with its own auto-expiry
-- in AuthService.isLockActive — reusing it for admin deactivation would let
-- the account silently reactivate itself after ACCOUNT_LOCK_DURATION_MINUTES).
-- is_active does not expire: it stays false until an admin flips it back.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
