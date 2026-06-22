# CLAUDE.md — Shifd Labs Identity Service (SIS)

## Purpose

SIS is the centralized authentication and identity microservice for all Shifd Labs products.
It is the single source of truth for user identity, organization management, and subscription state.

Responsibilities:
- User authentication (register, login, password reset, logout)
- JWT issuance using RS256 (asymmetric RSA keys)
- JWKS endpoint so downstream services validate JWTs locally without calling SIS per-request
- Organization (tenant) management
- Subscription state (which org has access to which product)
- Platform admin API for Shifd Labs internal team

Downstream consumers:
- **Shifd Approval** — validates every API request by checking JWT via JWKS, reads org_id and products claims
- **Shifd Labs Admin Panel** — uses the /api/admin/* endpoints to manage orgs and subscriptions
- Future Shifd Labs products follow the same pattern

---

## Tech Stack

| Concern       | Library                              |
|---------------|--------------------------------------|
| HTTP          | github.com/gin-gonic/gin             |
| ORM           | gorm.io/gorm                         |
| DB Driver     | gorm.io/driver/postgres              |
| JWT           | github.com/golang-jwt/jwt/v5         |
| JWK Format    | github.com/lestrrat-go/jwx/v2        |
| UUID          | github.com/google/uuid               |
| Password      | golang.org/x/crypto/bcrypt           |
| Env Config    | github.com/joho/godotenv             |
| Email         | github.com/resend/resend-go/v2       |
| Rate Limiting | golang.org/x/time/rate               |

Go version: 1.21+

---

## Project Structure

```
shifd-identity-service/
├── cmd/
│   └── server/
│       └── main.go                      ← entry point, wires everything together
├── config/
│   └── config.go                        ← load and validate all env vars, panic if required missing
├── db/
│   ├── database.go                      ← GORM connection init
│   └── migrations/
│       └── 001_initial_schema.sql       ← full SQL schema, run once manually
├── model/
│   ├── user.go
│   ├── organization.go
│   ├── org_membership.go
│   ├── subscription.go
│   ├── refresh_token.go
│   ├── password_reset_token.go
│   └── failed_login_attempt.go
├── repository/
│   ├── user.repository.go
│   ├── organization.repository.go
│   ├── org_membership.repository.go
│   ├── subscription.repository.go
│   └── refresh_token.repository.go
├── service/
│   ├── auth.service.go                  ← register, login, logout, refresh, forgot/reset password
│   ├── org.service.go                   ← org create, member invite, member management
│   ├── subscription.service.go          ← subscription CRUD and state transitions
│   ├── jwks.service.go                  ← load RSA keys, build JWKS response
│   └── email.service.go                 ← send emails via Resend
├── handler/
│   ├── auth.handler.go
│   ├── org.handler.go
│   ├── subscription.handler.go
│   ├── admin.handler.go
│   └── jwks.handler.go
├── middleware/
│   ├── auth.middleware.go               ← validate Bearer JWT on protected routes
│   ├── admin.middleware.go              ← check users.is_platform_admin = true in DB
│   └── rate_limit.middleware.go         ← per-IP rate limiting for auth endpoints
├── pkg/
│   └── jwtutil/
│       └── jwtutil.go                   ← sign and parse JWT helpers (RS256 only)
├── router/
│   └── router.go                        ← register all routes and middleware
├── .env.example
├── .env                                 ← gitignored, filled in locally
├── .gitignore
├── Dockerfile
├── go.mod
└── go.sum
```

---

## Database Schema

Database name: `shifd_identity`
All timestamps stored in UTC.

```sql
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
```

---

## JWT Claims Structure (RS256)

Access token expiry: 15 minutes
Refresh token expiry: 7 days (stored in DB as SHA-256 hash)

```json
{
  "iss": "https://auth.shifd.com",
  "sub": "<user_uuid>",
  "jti": "<unique_uuid_per_token>",
  "iat": 1750000000,
  "exp": 1750000900,
  "email": "user@company.com",
  "name": "John Doe",
  "org_id": "<org_uuid>",
  "org_role": "admin",
  "products": ["shifd-approval"]
}
```

Field notes:
- `sub` = users.id
- `org_id` = the organization context for this session
- `org_role` = user's role in that org: `"owner"`, `"admin"`, or `"member"`
- `products` = list of product_id values from ACTIVE subscriptions for this org. Downstream services check this to gate access.
- `jti` = UUID v4, unique per token. Used for potential future revocation list.

The JWKS response (`GET /.well-known/jwks.json`) must contain:
```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "sis-key-v1",
    "n": "<base64url encoded modulus>",
    "e": "<base64url encoded exponent>"
  }]
}
```

---

## API Endpoints

### Public — no authentication
```
POST   /api/auth/register          Register new user account
POST   /api/auth/login             Login → {access_token, refresh_token, user, org}
POST   /api/auth/refresh           Exchange refresh token → {access_token}
POST   /api/auth/forgot-password   Send password reset email
POST   /api/auth/reset-password    Reset password using token from email
GET    /.well-known/jwks.json      JWKS public key (no /api prefix — standard path)
```

### Authenticated user — requires valid Bearer JWT
```
POST   /api/auth/logout            Revoke current refresh token
GET    /api/me                     Get own profile (name, email, phone)
PATCH  /api/me                     Update name or phone
PATCH  /api/me/password            Change password (requires current_password)
GET    /api/me/orgs                List orgs the user belongs to with subscription status
```

### Org admin — requires org_role = owner or admin for :org_id
```
POST   /api/orgs                              Create org (caller becomes owner)
GET    /api/orgs/:org_id                      Get org info
PATCH  /api/orgs/:org_id                      Update org name
POST   /api/orgs/:org_id/members              Invite member by email (sends invite email)
GET    /api/orgs/:org_id/members              List members + their roles
PATCH  /api/orgs/:org_id/members/:user_id     Update role or status (admin/member, active/suspended)
DELETE /api/orgs/:org_id/members/:user_id     Remove member from org
GET    /api/orgs/:org_id/subscriptions        List subscriptions for this org
```

### Platform admin — requires users.is_platform_admin = true (checked in DB, not JWT)
```
GET    /api/admin/users                             List all users (paginated, search by email)
GET    /api/admin/users/:uid                        Get user + their org memberships
POST   /api/admin/users/:uid/force-logout           Revoke all refresh tokens for a user
PATCH  /api/admin/users/:uid/lock                   Lock or unlock user account

GET    /api/admin/orgs                              List all orgs (paginated)
POST   /api/admin/orgs                              Create org directly
GET    /api/admin/orgs/:org_id                      Get org + members + subscriptions
POST   /api/admin/orgs/:org_id/subscriptions        Create subscription for org
PATCH  /api/admin/orgs/:org_id/subscriptions/:id    Update subscription (status, expires_at, plan)
```

---

## Environment Variables (.env.example)

```env
# Application
APP_ENV=development
APP_PORT=8080
APP_BASE_URL=http://localhost:8080

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=shifd_identity
DB_USER=postgres
DB_PASSWORD=your_password_here
DB_SSLMODE=disable

# JWT (RSA keys stored as base64-encoded PEM)
# Generate:
#   openssl genrsa -out private.pem 2048
#   openssl rsa -in private.pem -pubout -out public.pem
#   macOS:  base64 -i private.pem | tr -d '\n'
#   Linux:  base64 -w 0 private.pem
JWT_PRIVATE_KEY_BASE64=PASTE_BASE64_ENCODED_PRIVATE_KEY_HERE
JWT_PUBLIC_KEY_BASE64=PASTE_BASE64_ENCODED_PUBLIC_KEY_HERE
JWT_KEY_ID=sis-key-v1
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=168h
JWT_ISSUER=https://auth.shifd.com

# Email (Resend)
RESEND_API_KEY=re_your_key_here
RESEND_FROM_EMAIL=noreply@shifd.com
RESEND_FROM_NAME=Shifd Labs

# Security
MAX_FAILED_LOGINS=5
ACCOUNT_LOCK_DURATION_MINUTES=30
RATE_LIMIT_AUTH_PER_MIN=5
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Platform admin (comma-separated emails — these users get is_platform_admin=true on register)
PLATFORM_ADMIN_EMAILS=youremail@example.com
```

---

## Coding Conventions

Follow the exact same layered architecture as approval-backend:

- `model/` — GORM structs only. No methods, no business logic.
- `repository/` — DB operations only. All queries live here. Returns raw model structs.
- `service/` — all business logic. Calls repositories. Returns domain results.
- `handler/` — HTTP layer only. Parse request → call service → write response. No business logic.
- `middleware/` — Gin middleware functions only.
- `router/` — route registration only.

**Error handling:**
- Services return `(result, error)`. Handlers convert errors to HTTP status codes.
- Log errors at handler level with context: `log.Printf("handler: login error for %s: %v", email, err)`
- Never expose internal error details in API responses. Use generic messages.

**Consistent response envelope:**
```go
// Success
c.JSON(200, gin.H{"data": result, "message": "success"})

// Error
c.JSON(statusCode, gin.H{"error": "Human readable message", "code": "SNAKE_CASE_CODE"})
```

**Standard error codes to use:**
- `INVALID_CREDENTIALS` — wrong email/password
- `ACCOUNT_LOCKED` — brute force lockout
- `EMAIL_ALREADY_EXISTS` — duplicate registration
- `TOKEN_EXPIRED` — JWT or reset token expired
- `TOKEN_INVALID` — malformed or signature mismatch
- `NOT_FOUND` — resource not found
- `FORBIDDEN` — insufficient role/permission
- `SUBSCRIPTION_INACTIVE` — org does not have active subscription for this product

**GORM usage:**
- Always use transactions for multi-step operations: `db.Transaction(func(tx *gorm.DB) error {...})`
- Use `db.WithContext(ctx)` on every query
- Enable soft delete on users and organizations via `gorm.Model` or custom `DeletedAt *time.Time`
- Never hard delete users or organizations

---

## Security Rules — Non-Negotiable

1. RSA private key must NEVER appear in logs, error messages, or API responses
2. Hash passwords with bcrypt minimum cost 12
3. Store refresh tokens as SHA-256 hex hash in DB — never the raw token value
4. Rate limit `/api/auth/login` and `/api/auth/register` — max RATE_LIMIT_AUTH_PER_MIN per IP
5. Lock account after MAX_FAILED_LOGINS consecutive failures within a time window
6. Password reset tokens expire after 1 hour and are single-use (set used_at on first use)
7. CORS configured strictly via CORS_ALLOWED_ORIGINS — no wildcard `*` ever
8. Platform admin middleware must re-query `users.is_platform_admin` from DB on every request — do not trust JWT claims for this check
9. Invite tokens (for org member invitations) expire after 48 hours

---

## How Shifd Approval Backend Uses SIS

This context helps you understand what the JWKS endpoint and JWT format must satisfy.

```
Approval Backend startup:
  GET /.well-known/jwks.json  →  cache public key in memory

Every Approval API request:
  1. Extract Bearer token from Authorization header
  2. Validate JWT signature using cached public key (local operation, no SIS call)
  3. Check token not expired
  4. Extract org_id → apply as filter on all DB queries
  5. Check products array contains "shifd-approval" → if not, return 403
  6. Extract org_role → use for admin-only routes in Approval

Approval Backend refreshes JWKS cache:
  - Every 24 hours
  - Or immediately on JWT validation failure (fallback mechanism)
```

Because Approval validates tokens locally, the JWKS endpoint must always return a valid, parseable JWK set. Test this endpoint manually before integrating.

---

## Build and Run

```bash
# Run migrations manually first
psql -U postgres -d shifd_identity -f db/migrations/001_initial_schema.sql

# Copy and fill in env
cp .env.example .env
# Edit .env: fill in DB_PASSWORD, JWT_PRIVATE_KEY_BASE64, JWT_PUBLIC_KEY_BASE64, etc.

# Install dependencies
go mod tidy

# Run in development
go run cmd/server/main.go

# Build
go build -o bin/sis cmd/server/main.go

# Check for issues
go vet ./...
```

---

## Out of Scope for Phase 1

Do NOT implement these in Phase 1:
- Payment gateway integration (Midtrans/Stripe)
- Email verification flow (just store the column, implement later)
- OAuth2/SSO login (Google, etc.)
- Multi-factor authentication
- Webhook system for subscription events
- Usage metrics/analytics

Keep the scope tight. The goal for Phase 1 is: working auth, working JWKS endpoint, working org and subscription management, working admin API. Nothing more.
