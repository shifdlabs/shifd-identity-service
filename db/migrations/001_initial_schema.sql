CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE users (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email               VARCHAR(255) UNIQUE NOT NULL,
  password_hash       VARCHAR(255) NOT NULL,
  name                VARCHAR(255) NOT NULL,
  phone               VARCHAR(50),
  is_platform_admin   BOOLEAN NOT NULL DEFAULT FALSE,
  email_verified_at   TIMESTAMP,
  is_locked           BOOLEAN NOT NULL DEFAULT FALSE,
  lock_timestamp      TIMESTAMP,
  created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
  deleted_at          TIMESTAMP
);
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;

-- ============================================================
-- ORGANIZATIONS
-- ============================================================
CREATE TABLE organizations (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       VARCHAR(255) NOT NULL,
  slug       VARCHAR(255) UNIQUE NOT NULL,
  metadata   JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMP
);

-- ============================================================
-- ORG MEMBERSHIPS
-- Role values: 'owner' | 'admin' | 'member'
-- Status values: 'invited' | 'active' | 'suspended'
-- ============================================================
CREATE TABLE org_memberships (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id),
  org_id      UUID NOT NULL REFERENCES organizations(id),
  role        VARCHAR(50) NOT NULL DEFAULT 'member',
  status      VARCHAR(50) NOT NULL DEFAULT 'active',
  invited_by  UUID REFERENCES users(id),
  invited_at  TIMESTAMP,
  joined_at   TIMESTAMP,
  created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, org_id)
);
CREATE INDEX idx_org_memberships_org_id  ON org_memberships(org_id);
CREATE INDEX idx_org_memberships_user_id ON org_memberships(user_id);

-- ============================================================
-- SUBSCRIPTIONS
-- Product values: 'shifd-approval' (more products added later)
-- Plan values: 'standard' | 'professional' | 'enterprise'
-- Status values: 'pending' | 'active' | 'expired' | 'cancelled' | 'suspended'
-- ============================================================
CREATE TABLE subscriptions (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     UUID NOT NULL REFERENCES organizations(id),
  product_id VARCHAR(100) NOT NULL,
  plan       VARCHAR(100) NOT NULL DEFAULT 'standard',
  status     VARCHAR(50) NOT NULL DEFAULT 'active',
  started_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  notes      TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_subscriptions_org_product ON subscriptions(org_id, product_id);

-- ============================================================
-- REFRESH TOKENS
-- token_hash = SHA-256 hex of the actual token (never store raw)
-- ============================================================
CREATE TABLE refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id),
  org_id      UUID REFERENCES organizations(id),
  token_hash  VARCHAR(64) NOT NULL UNIQUE,
  expires_at  TIMESTAMP NOT NULL,
  revoked_at  TIMESTAMP,
  device_info VARCHAR(500),
  created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- ============================================================
-- PASSWORD RESET TOKENS
-- token_hash = SHA-256 hex, expires 1 hour, single-use
-- ============================================================
CREATE TABLE password_reset_tokens (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES users(id),
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  used_at    TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ============================================================
-- FAILED LOGIN ATTEMPTS (for brute force protection)
-- ============================================================
CREATE TABLE failed_login_attempts (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email        VARCHAR(255) NOT NULL,
  ip_address   VARCHAR(45),
  attempted_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_failed_login_email_time ON failed_login_attempts(email, attempted_at);
