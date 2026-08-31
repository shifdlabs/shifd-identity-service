# SIS (Shifd Identity Service) — API Documentation

Dokumen ini menjelaskan **shape request/response yang sebenarnya berjalan di kode** (handler/service/middleware/router saat ini), bukan spesifikasi awal di `CLAUDE.md`. Beberapa endpoint di spesifikasi awal **belum diimplementasikan** — lihat bagian [11. Belum Diimplementasikan](#11-belum-diimplementasikan) supaya FE tidak salah wiring.

Base URL (local dev): `http://localhost:8080` (sesuai `APP_PORT` di `app.env`)

---

## 1. Konvensi Umum

### Response sukses
Semua endpoint sukses (kecuali JWKS) membungkus hasil dalam:
```json
{
  "data": { ... } | [ ... ] | null,
  "message": "success"
}
```
`message` kadang berisi teks lain yang lebih spesifik (misal `"logged out"`, `"invite sent"`) — dicatat per-endpoint di bawah.

### Response error
```json
{
  "error": "Pesan yang bisa ditampilkan ke user",
  "code": "SNAKE_CASE_CODE"
}
```

### Tabel kode error (yang benar-benar dipakai di kode)

| Code | HTTP Status | Dipakai di |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Body/param tidak valid (semua endpoint) |
| `UNAUTHORIZED` | 401 | Header `Authorization` kosong/format salah/token invalid atau expired |
| `INVALID_CREDENTIALS` | 401 | Login: email/password salah |
| `TOKEN_EXPIRED` | 401 | Refresh token / reset-password token / invite expired |
| `TOKEN_INVALID` | 401 | Refresh token / reset-password token tidak valid |
| `ACCOUNT_LOCKED` | 403 | Login: akun terkunci karena terlalu banyak gagal login |
| `FORBIDDEN` | 403 | Bukan member aktif org / bukan owner-admin / platform admin check gagal |
| `NOT_FOUND` | 404 | Resource (org/member/subscription/user) tidak ditemukan |
| `EMAIL_ALREADY_EXISTS` | 409 | Register: email sudah dipakai |
| `SLUG_ALREADY_EXISTS` | 409 | Create org: slug sudah dipakai |
| `ALREADY_MEMBER` | 409 | Invite member: user sudah jadi member org tsb |
| `RATE_LIMIT_EXCEEDED` | 429 | Terlalu banyak request ke `/login` atau `/register` |
| `INTERNAL_ERROR` | 500 | Error tak terduga di server |

### Auth header
Semua endpoint **ter-otentikasi** butuh header:
```
Authorization: Bearer <access_token>
```
Tidak ada cookie/session — semua state ada di JWT.

---

## 2. Quick Start Flow untuk FE

1. **Register** → dapat data user (belum dapat token, harus login).
2. **Login** → dapat `access_token` (umur **15 menit**) + `refresh_token` (umur **7 hari**) + `user` + `org` (context org aktif, bisa `null` kalau user belum punya org).
3. Simpan `access_token` di memory/state (bukan localStorage kalau bisa), simpan `refresh_token` lebih aman (httpOnly cookie idealnya, tapi saat ini API mengembalikannya sebagai field JSON biasa — penyimpanannya jadi tanggung jawab FE).
4. Pasang `Authorization: Bearer <access_token>` di semua request ke endpoint ter-otentikasi.
5. Kalau dapat `401 UNAUTHORIZED` (kemungkinan besar access_token expired karena cuma 15 menit) → panggil `POST /api/auth/refresh` dengan `refresh_token` → dapat `access_token` baru → retry request. `refresh_token` **tidak di-rotate**, tetap sama sampai expired/logout/reset-password.
6. **Logout** → kirim `refresh_token` ke `POST /api/auth/logout` (endpoint ini **publik**, tidak butuh header `Authorization` — refresh token itu sendiri yang jadi kredensial).

---

## 3. Endpoint Publik (tanpa header `Authorization`)

### `POST /api/auth/register`
Rate limited (lihat [8. Rate Limiting](#8-rate-limiting)).

**Request**
```json
{
  "email": "budi@contoh.com",
  "password": "password123",
  "name": "Budi Santoso",
  "phone": "081234567890"
}
```
- `email`, `password`, `name` wajib. `phone` opsional.
- `password` minimal 8 karakter (`VALIDATION_ERROR` kalau kurang).

**Response 201**
```json
{
  "data": {
    "id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
    "email": "budi@contoh.com",
    "name": "Budi Santoso",
    "phone": "081234567890",
    "is_platform_admin": false,
    "email_verified_at": null,
    "created_at": "2026-06-23T10:00:00Z",
    "updated_at": "2026-06-23T10:00:00Z"
  },
  "message": "success"
}
```
`email_verified_at` selalu `null` — verifikasi email belum diimplementasikan (Phase 1).

**Errors**: `VALIDATION_ERROR` (400), `EMAIL_ALREADY_EXISTS` (409).

---

### `POST /api/auth/login`
Rate limited.

**Request**
```json
{
  "email": "budi@contoh.com",
  "password": "password123",
  "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
  "device_info": "Chrome on macOS"
}
```
- `email`, `password` wajib.
- `org_id` **opsional**. Kalau diisi, user harus member aktif org itu (kalau bukan → `FORBIDDEN`). Kalau dikosongkan, server otomatis pilih membership aktif pertama milik user (bisa `null` kalau user belum punya org sama sekali).
- `device_info` opsional, bebas teks, cuma disimpan sebagai label di tabel `refresh_tokens`.

**Response 200**
```json
{
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "9e1f9c2a-1b3d-4a5e-8f6a-2c3d4e5f6a7b",
    "user": {
      "id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
      "email": "budi@contoh.com",
      "name": "Budi Santoso",
      "phone": "081234567890",
      "is_platform_admin": false,
      "email_verified_at": null,
      "created_at": "2026-06-23T10:00:00Z",
      "updated_at": "2026-06-23T10:00:00Z"
    },
    "org": {
      "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
      "role": "owner",
      "status": "active"
    }
  },
  "message": "success"
}
```
- `org` bisa `null` → artinya user belum punya/join org manapun. FE harus handle case ini (misal arahkan ke flow "buat organisasi").
- `refresh_token` **bukan JWT** — cuma UUID v4 random string. Jangan coba decode sebagai JWT.
- Klaim lengkap di dalam `access_token` (JWT) dijelaskan di [7. JWT Access Token Claims](#7-jwt-access-token-claims).

**Errors**: `VALIDATION_ERROR` (400, termasuk kalau `org_id` bukan UUID valid), `INVALID_CREDENTIALS` (401), `ACCOUNT_LOCKED` (403, akun terkunci karena gagal login berkali-kali), `FORBIDDEN` (403, kalau `org_id` diisi tapi user bukan member aktif).

---

### `POST /api/auth/refresh`

**Request**
```json
{ "refresh_token": "9e1f9c2a-1b3d-4a5e-8f6a-2c3d4e5f6a7b" }
```

**Response 200**
```json
{
  "data": { "access_token": "eyJhbGciOiJSUzI1NiIs..." },
  "message": "success"
}
```
Catatan: `refresh_token` **tidak ikut dikembalikan lagi** dan tidak di-rotate — token yang sama dipakai terus sampai expired/logout. Org context (`org_id`/`org_role`/`products`) di access_token baru di-derive ulang dari DB saat ini, bukan dari token lama.

**Errors**: `VALIDATION_ERROR` (400), `TOKEN_EXPIRED` (401), `TOKEN_INVALID` (401).

---

### `POST /api/auth/logout`
**Publik** — tidak butuh `Authorization` header. `refresh_token` itu sendiri adalah kredensialnya.

**Request**
```json
{ "refresh_token": "9e1f9c2a-1b3d-4a5e-8f6a-2c3d4e5f6a7b" }
```

**Response 200**
```json
{ "data": null, "message": "logged out" }
```
Idempotent — refresh token yang sudah revoked/tidak dikenal tetap dibalas 200 (bukan error), demi tidak membocorkan info token mana yang valid.

---

### `POST /api/auth/forgot-password`

**Request**
```json
{ "email": "budi@contoh.com" }
```

**Response 200** — **selalu** dibalas sama, baik email terdaftar atau tidak (anti email-enumeration):
```json
{
  "data": null,
  "message": "If an account exists for that email, a password reset link has been sent"
}
```

---

### `POST /api/auth/reset-password`

**Request**
```json
{
  "token": "a1b2c3d4...",
  "new_password": "passwordBaru123"
}
```
`token` didapat dari link di email reset password. Berlaku **1 jam**, sekali pakai.

**Response 200**
```json
{ "data": null, "message": "Password has been reset" }
```
Side effect: semua refresh token milik user di-revoke (semua sesi lama logout otomatis).

**Errors**: `VALIDATION_ERROR` (400, password < 8 karakter), `TOKEN_EXPIRED` (401), `TOKEN_INVALID` (401).

---

### `GET /.well-known/jwks.json`
**Tidak dibungkus** envelope `{data, message}` — response-nya **langsung** dokumen JWKS standar (RFC 7517), karena dikonsumsi sebagai JWKS biasa oleh service lain (Shifd Approval), bukan oleh FE secara langsung.

**Response 200**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "sis-key-v1",
      "n": "<base64url modulus>",
      "e": "<base64url exponent>"
    }
  ]
}
```
Header `Cache-Control: public, max-age=86400`.

---

## 4. Endpoint Ter-otentikasi (`/api/orgs/*`)

Semua butuh `Authorization: Bearer <access_token>`. `org_role` (owner/admin/member) dicek di level service, bukan cuma JWT.

### `POST /api/orgs`
Bikin organisasi baru — pembuat otomatis jadi `owner`.

**Request**
```json
{ "name": "PT Contoh Sejahtera", "slug": "contoh-sejahtera" }
```
- `slug` harus: huruf kecil, angka, dan strip (`-`) saja, minimal 3 karakter. Regex: `^[a-z0-9-]{3,}$`. **Tidak di-lowercase otomatis** — kalau kirim huruf besar akan ditolak `VALIDATION_ERROR`, bukan di-normalize.

**Response 201**
```json
{
  "data": {
    "id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
    "name": "PT Contoh Sejahtera",
    "slug": "contoh-sejahtera",
    "created_at": "2026-06-23T10:05:00Z",
    "updated_at": "2026-06-23T10:05:00Z"
  },
  "message": "success"
}
```

**Errors**: `VALIDATION_ERROR` (400, slug invalid), `SLUG_ALREADY_EXISTS` (409).

---

### `GET /api/orgs/:org_id`
Butuh jadi member aktif (role apapun) di org tersebut.

**Response 200**
```json
{
  "data": {
    "org": {
      "id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
      "name": "PT Contoh Sejahtera",
      "slug": "contoh-sejahtera",
      "created_at": "2026-06-23T10:05:00Z",
      "updated_at": "2026-06-23T10:05:00Z"
    },
    "member_count": 3,
    "active_subscriptions": [
      {
        "id": "cbe53cb8-8dc4-446e-8889-9b7b743e8e23",
        "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
        "product_id": "shifd-approval",
        "plan": "premium_yearly",
        "status": "active",
        "started_at": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
      }
    ]
  },
  "message": "success"
}
```
- `member_count` cuma menghitung member dengan `status = "active"` (tidak termasuk yang masih `invited`/`suspended`).
- `active_subscriptions` cuma yang `status = "active"` **dan** `expires_at` belum lewat (subscription expired/cancelled/pending tidak ikut muncul di sini — kalau perlu semua subscription apapun statusnya, pakai `GET /api/orgs/:org_id/subscriptions`).

**Errors**: `FORBIDDEN` (403, bukan member aktif), `NOT_FOUND` (404).

---

### `POST /api/orgs/:org_id/members`
Invite user (harus sudah punya akun SIS) ke org. Butuh role `owner` atau `admin`.

**Request**
```json
{ "email": "calon-member@contoh.com" }
```

**Response 201**
```json
{ "data": null, "message": "invite sent" }
```
Membership baru dibuat dengan `status = "invited"`, role default `member`. Email invite dikirim via Resend (kalau gagal kirim email, tetap dianggap sukses — cuma di-log di server, tidak mempengaruhi response).

**Errors**: `FORBIDDEN` (403, requester bukan owner/admin atau bukan member aktif), `NOT_FOUND` (404, email tidak terdaftar sebagai user SIS, atau org tidak ada), `ALREADY_MEMBER` (409).

> Catatan penting: yang diundang **harus sudah punya akun** (register dulu) — endpoint ini tidak bisa invite email yang belum pernah register.

---

### `POST /api/orgs/:org_id/members/accept`
Invitee menerima undangan. Dipanggil oleh user yang login sebagai akun yang diundang (`userID` dari JWT, bukan dari body).

**Request**: tidak ada body.

**Response 200**
```json
{ "data": null, "message": "success" }
```
Mengubah membership invitee jadi `status = "active"`, set `joined_at`.

**Errors**: `NOT_FOUND` (404, tidak ada invite pending untuk user+org ini), `TOKEN_EXPIRED` (401, invite sudah lebih dari **48 jam** sejak diundang).

---

### `GET /api/orgs/:org_id/members`
Butuh member aktif (role apapun).

**Response 200**
```json
{
  "data": [
    {
      "user_id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
      "email": "budi@contoh.com",
      "name": "Budi Santoso",
      "role": "owner",
      "status": "active",
      "invited_at": null,
      "joined_at": "2026-06-23T10:05:00Z"
    },
    {
      "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "email": "calon-member@contoh.com",
      "name": "Calon Member",
      "role": "member",
      "status": "invited",
      "invited_at": "2026-06-23T11:00:00Z",
      "joined_at": null
    }
  ],
  "message": "success"
}
```
Tidak paginated — semua member dikembalikan sekaligus dalam array (langsung di `data`, bukan dibungkus `{items, pagination}`).

**Errors**: `FORBIDDEN` (403).

---

### `PATCH /api/orgs/:org_id/members/:user_id`
Ubah role dan/atau status member. Butuh role `owner` atau `admin`.

**Request** (semua field opsional, kirim yang mau diubah saja)
```json
{ "role": "admin", "status": "active" }
```
- `role` valid: `"admin"` atau `"member"` saja (**bukan** `"owner"` — transfer ownership tidak ada di endpoint ini).
- `status` valid: `"active"` atau `"suspended"` saja (**bukan** `"invited"`).
- Admin (bukan owner) **tidak bisa** mengubah membership milik owner.

**Response 200**
```json
{ "data": null, "message": "success" }
```

**Errors**: `FORBIDDEN` (403 — requester bukan owner/admin, atau admin coba ubah owner), `VALIDATION_ERROR` (400 — value role/status di luar yang diizinkan), `NOT_FOUND` (404 — target bukan member org ini).

---

### `DELETE /api/orgs/:org_id/members/:user_id`
Keluarkan member dari org. Butuh role `owner` atau `admin`. **Owner tidak bisa dihapus** (siapapun yang minta, termasuk owner lain).

**Response 200**
```json
{ "data": null, "message": "success" }
```

**Errors**: `FORBIDDEN` (403 — termasuk kalau target adalah owner), `NOT_FOUND` (404).

---

### `GET /api/orgs/:org_id/subscriptions`
Butuh member aktif (role apapun). Mengembalikan **semua** subscription org ini apapun statusnya (beda dengan `active_subscriptions` di `GET /api/orgs/:org_id` yang cuma yang aktif).

**Response 200**
```json
{
  "data": [
    {
      "id": "cbe53cb8-8dc4-446e-8889-9b7b743e8e23",
      "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
      "product_id": "shifd-approval",
      "plan": "premium_yearly",
      "status": "active",
      "started_at": "2026-01-01T00:00:00Z",
      "expires_at": "2027-01-01T00:00:00Z",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    }
  ],
  "message": "success"
}
```

**Errors**: `FORBIDDEN` (403).

---

## 5. Endpoint Profil Sendiri (`/api/me/*`)

Semua butuh `Authorization: Bearer <access_token>`. Selalu beroperasi pada user yang sedang login (diambil dari klaim `sub` di JWT) — tidak ada user ID di path/body, jadi user tidak bisa baca/ubah profil orang lain lewat endpoint ini.

### `GET /api/me`
Ambil profil sendiri.

**Response 200**
```json
{
  "data": {
    "id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
    "email": "budi@contoh.com",
    "name": "Budi Santoso",
    "phone": "081234567890",
    "is_platform_admin": false,
    "email_verified_at": null,
    "created_at": "2026-06-23T10:00:00Z",
    "updated_at": "2026-06-23T10:00:00Z"
  },
  "message": "success"
}
```

---

### `PATCH /api/me`
Update nama dan/atau phone sendiri. Partial update — kirim field yang mau diubah saja.

**Request** (kedua field opsional)
```json
{ "name": "Budi S.", "phone": "081200000000" }
```
- `name`: kalau dikirim, tidak boleh kosong/whitespace (`VALIDATION_ERROR`). Kalau field di-omit, nama lama dipertahankan.
- `phone`: kirim string kosong `""` → phone di-clear jadi `null`; kirim non-kosong → di-set; field di-omit → phone lama dipertahankan.
- Karena membedakan "field ada vs tidak ada", kirim **hanya** field yang mau diubah. Contoh ubah phone saja: `{ "phone": "0899..." }`.

**Response 200** — shape user sama seperti `GET /api/me`.

**Errors**: `VALIDATION_ERROR` (400, body invalid atau name kosong).

---

### `PATCH /api/me/password`
Ganti password saat sedang login (beda dari forgot/reset password yang lewat email).

**Request**
```json
{ "current_password": "passwordLama123", "new_password": "passwordBaru456" }
```
- Kedua field wajib. `new_password` minimal 8 karakter.

**Response 200**
```json
{ "data": null, "message": "Password has been changed" }
```

**Catatan sesi:** ganti password di sini **tidak** me-revoke sesi/refresh token yang ada — kamu tetap login, refresh token tetap jalan. (Beda dengan reset-password lewat email yang me-revoke semua sesi.) Jadi FE tidak perlu memaksa re-login setelah ganti password.

**Errors**: `INVALID_CREDENTIALS` (401, `current_password` salah), `VALIDATION_ERROR` (400, `new_password` < 8 karakter atau body invalid).

---

### `GET /api/me/orgs`
List semua org yang user ikuti (semua status membership: active/invited/suspended), beserta role user dan subscription aktif tiap org.

**Response 200**
```json
{
  "data": [
    {
      "org": {
        "id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
        "name": "PT Contoh Sejahtera",
        "slug": "contoh-sejahtera",
        "created_at": "2026-06-23T10:05:00Z",
        "updated_at": "2026-06-23T10:05:00Z"
      },
      "role": "owner",
      "membership_status": "active",
      "active_subscriptions": [
        {
          "id": "cbe53cb8-8dc4-446e-8889-9b7b743e8e23",
          "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
          "product_id": "shifd-approval",
          "plan": "premium_yearly",
          "status": "active",
          "started_at": "2026-01-01T00:00:00Z",
          "expires_at": "2027-01-01T00:00:00Z",
          "created_at": "2026-01-01T00:00:00Z",
          "updated_at": "2026-01-01T00:00:00Z"
        }
      ]
    }
  ],
  "message": "success"
}
```
- `membership_status` bisa `"active" | "invited" | "suspended"` — FE bisa tampilkan badge "undangan pending" untuk yang `invited`.
- `active_subscriptions` cuma yang `status = "active"` dan belum expired (bisa array kosong `[]`).
- `data` bisa array kosong `[]` kalau user belum ikut org manapun.

---

## 6. Endpoint Platform Admin (`/api/admin/*`)

Semua butuh `Authorization: Bearer <access_token>` **dan** `users.is_platform_admin = true` di DB (di-cek ulang ke DB tiap request, **tidak percaya klaim JWT**). Kalau bukan admin → `403 FORBIDDEN`, pesan `"Platform admin access required"`.

### `GET /api/admin/orgs`
Query params: `page` (default `1`), `limit` (default `20`, di-cap maksimal `100`). Value ≤ 0 atau tidak valid otomatis fallback ke default.

`plan` (opsional) — filter org yang punya subscription **aktif & belum expired** dengan plan tersebut, mis. `?plan=trial` untuk lihat semua org yang lagi trial. Plan yang tidak dikenal (typo dsb.) bukan error, cuma balikin list kosong. Kalau di-omit, semua org ditampilkan (perilaku lama, tidak berubah).

**Response 200**
```json
{
  "data": {
    "items": [
      {
        "id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
        "name": "PT Contoh Sejahtera",
        "slug": "contoh-sejahtera",
        "created_at": "2026-06-23T10:05:00Z",
        "updated_at": "2026-06-23T10:05:00Z",
        "subscription": {
          "product_id": "shifd-approval",
          "plan": "trial",
          "status": "active",
          "expires_at": "2026-09-10T17:00:00Z",
          "user_limit": 5
        }
      }
    ],
    "pagination": { "page": 1, "limit": 20, "total": 1, "total_pages": 1 }
  },
  "message": "success"
}
```
Diurutkan terbaru dulu (`created_at DESC`).

**`subscription` (sejak Agustus 2026)** — satu subscription yang menentukan status org: yang **aktif dan paling cepat habis**, atau kalau tidak ada yang aktif, yang paling akhir berakhir (apa pun statusnya). `null` untuk org yang belum pernah punya subscription. Satu org hari ini hanya punya satu produk (`shifd-approval`), jadi praktisnya ini "subscription org tersebut". Dengan ini badge status + hitung mundur expiry bisa dirender langsung di tabel list tanpa `GET /api/admin/orgs/:org_id` per baris.

---

### `POST /api/admin/orgs`
Bikin org untuk user lain (`owner_email` harus user yang sudah ada).

**Request**
```json
{
  "name": "PT Lain Makmur",
  "slug": "lain-makmur",
  "owner_email": "owner-baru@contoh.com"
}
```

**Response 201** — shape sama seperti `POST /api/orgs`.

**Errors**: `NOT_FOUND` (404, `owner_email` tidak ada user-nya), `VALIDATION_ERROR` (400, slug invalid), `SLUG_ALREADY_EXISTS` (409).

---

### `GET /api/admin/orgs/:org_id`
Beda dengan versi tenant (`GET /api/orgs/:org_id`): admin lihat **semua** member dan **semua** subscription apapun statusnya, tanpa perlu jadi member org tersebut.

**Response 200**
```json
{
  "data": {
    "org": {
      "id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
      "name": "PT Contoh Sejahtera",
      "slug": "contoh-sejahtera",
      "created_at": "2026-06-23T10:05:00Z",
      "updated_at": "2026-06-23T10:05:00Z"
    },
    "members": [
      {
        "user_id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
        "email": "budi@contoh.com",
        "name": "Budi Santoso",
        "role": "owner",
        "status": "active",
        "invited_at": null,
        "joined_at": "2026-06-23T10:05:00Z"
      }
    ],
    "subscriptions": [
      {
        "id": "cbe53cb8-8dc4-446e-8889-9b7b743e8e23",
        "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
        "product_id": "shifd-approval",
        "plan": "premium_yearly",
        "status": "active",
        "started_at": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
      }
    ]
  },
  "message": "success"
}
```

**Errors**: `NOT_FOUND` (404).

---

### `POST /api/admin/orgs/:org_id/members`
Tambah user yang **sudah punya akun SIS** sebagai member org, langsung aktif. Beda dengan `POST /api/orgs/:org_id/members` (jalur tenant) yang bikin undangan `invited` + kirim email: jalur admin ini langsung set `status="active"` + `joined_at`, **tanpa** email undangan dan tanpa cek org-role (cukup platform admin).

**Request**
```json
{ "email": "calon-member@contoh.com", "role": "member" }
```
- `email` wajib, harus user yang sudah terdaftar di SIS.
- `role` wajib, hanya `"admin"` atau `"member"` (**bukan** `"owner"` — owner hanya lewat pembuatan org).

**Response 201**
```json
{
  "data": {
    "id": "7d2e4f10-3a1b-4c2d-9e8f-1a2b3c4d5e6f",
    "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
    "role": "member",
    "status": "active",
    "invited_by": null,
    "invited_at": null,
    "joined_at": "2026-06-23T12:00:00Z",
    "created_at": "2026-06-23T12:00:00Z"
  },
  "message": "success"
}
```

**Errors**: `VALIDATION_ERROR` (400, body invalid atau `role` di luar admin/member), `NOT_FOUND` (404 — email tidak terdaftar di SIS → pesan `"User with this email not found in SIS"`, atau org tidak ada), `ALREADY_MEMBER` (409, user sudah jadi member org ini).

---

### `POST /api/admin/orgs/:org_id/subscriptions`

**Request**
```json
{
  "product_id": "shifd-approval",
  "plan": "premium_yearly",
  "expires_at": "2027-06-23T00:00:00Z"
}
```
- Semua field **wajib** kecuali `user_limit` (opsional). `expires_at` format ISO8601/RFC3339 (`YYYY-MM-DDTHH:mm:ssZ`), harus di masa depan.
- `status` subscription baru **selalu** `"active"` — tidak bisa diset lewat endpoint ini.
- `plan` **divalidasi** di server ke enum `trial | premium_monthly | premium_yearly`. Nilai lain → `400 VALIDATION_ERROR`.
- `user_limit` (integer, opsional) — kalau di-omit, dapat default per plan: `trial` → 5, `premium_monthly`/`premium_yearly` → unlimited (`null`). Untuk kontrak dengan kuota seat tertentu (billing per-employee), isi `user_limit` eksplisit saat create.

**Response 201** — shape subscription sama seperti di atas.

---

### `PATCH /api/admin/orgs/:org_id/subscriptions/:sub_id`

**Request** (semua field opsional)
```json
{
  "status": "suspended",
  "expires_at": "2027-12-31T00:00:00Z",
  "plan": "premium_monthly"
}
```
- `status` valid: `"pending" | "active" | "expired" | "cancelled" | "suspended"`.
- `expires_at` kalau dikirim, **harus** valid timestamp (tidak bisa kirim string kosong untuk "tidak diubah" — cukup omit field-nya saja dari JSON).
- `plan` sama seperti create: divalidasi ke `trial | premium_monthly | premium_yearly`.

**Response 200** — shape subscription terbaru.

**Errors**: `NOT_FOUND` (404, subscription tidak ada), `VALIDATION_ERROR` (400, `status` atau `plan` di luar enum di atas).

---

### `POST /api/admin/orgs/:org_id/force-logout`
Revoke **semua** refresh token yang terikat ke org ini sekaligus — versi org dari `POST /api/admin/users/:uid/force-logout` di bawah, tapi untuk seluruh member org dalam satu panggilan (tidak perlu loop per user_id).

Sesi user lain di org yang **berbeda** (kalau user itu member banyak org) **tidak ikut ter-revoke** — hanya sesi yang context org-nya org ini.

**Request**: tidak ada body.

**Response 200**
```json
{ "data": null, "message": "all sessions revoked for organization" }
```
Tidak error walau org tidak punya sesi aktif sama sekali (operasi idempotent).

⚠️ **Ini hanya mematikan sesi yang sudah ada** (user harus login ulang). Ini **tidak** mengubah status subscription — kalau tujuannya juga supaya org tidak bisa dapat akses lagi walau login ulang (mis. klien pilot bermasalah, atau langganan diputus), pasangkan dengan `PATCH /api/admin/orgs/:org_id/subscriptions/:sub_id` (`status: "suspended"` atau `"cancelled"`) untuk tiap subscription aktif org tersebut.

**Errors**: `NOT_FOUND` (404, org tidak ada).

---

### `GET /api/admin/users`
Query params: `page` (default `1`), `limit` (default `20`), `email` (opsional, partial match case-insensitive).

**Response 200**
```json
{
  "data": {
    "items": [
      {
        "id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
        "email": "budi@contoh.com",
        "name": "Budi Santoso",
        "phone": "081234567890",
        "is_platform_admin": false,
        "email_verified_at": null,
        "created_at": "2026-06-23T10:00:00Z",
        "updated_at": "2026-06-23T10:00:00Z",
        "last_login_at": "2026-08-27T13:11:09.663807Z",
        "active_sessions": 2
      }
    ],
    "pagination": { "page": 1, "limit": 20, "total": 1, "total_pages": 1 }
  },
  "message": "success"
}
```
Contoh cari: `GET /api/admin/users?email=budi&page=1&limit=10`

`is_locked` = akun sedang terkunci **saat ini** karena login gagal berulang; `lock_expires_at` = kapan kuncinya lepas sendiri. Kunci ini kedaluwarsa otomatis setelah `ACCOUNT_LOCK_DURATION_MINUTES` dan flag-nya dibersihkan saat login benar berikutnya, jadi baris yang masih punya `is_locked=true` di DB tapi window-nya sudah lewat dilaporkan sebagai **tidak** terkunci — supaya panel tidak menampilkan tembok yang sebenarnya sudah bisa dilewati user.

`last_login_at` = waktu login terakhir (`null` kalau user belum pernah login sama sekali). `active_sessions` = jumlah sesi yang masih hidup (refresh token belum dicabut & belum expired) — `0` artinya user sedang tidak login di mana pun. Keduanya diturunkan dari tabel `refresh_tokens`, bukan kolom di tabel `users`.

---

### `GET /api/admin/activity`
Feed login se-platform, terbaru dulu: login sukses (1 baris `refresh_tokens` per login) digabung dengan percobaan login gagal (`failed_login_attempts`).

Query params: `page` (default `1`), `limit` (default `20`, cap `100`), `email` (opsional, partial match case-insensitive), `type` (opsional: `login` | `login_failed`; nilai lain diabaikan = tampil semua).

**Response 200**
```json
{
  "data": {
    "items": [
      {
        "type": "login",
        "at": "2026-08-27T13:11:09.663807Z",
        "user_id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
        "email": "budi@contoh.com",
        "name": "Budi Santoso",
        "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
        "org_name": "PT Demo Company",
        "device_info": "Mozilla/5.0 ...",
        "ip_address": null
      },
      {
        "type": "login_failed",
        "at": "2026-08-27T12:59:01.100000Z",
        "user_id": null,
        "email": "salah@contoh.com",
        "name": "",
        "org_id": null,
        "org_name": null,
        "device_info": null,
        "ip_address": "103.12.4.9"
      }
    ],
    "pagination": { "page": 1, "limit": 20, "total": 2, "total_pages": 1 }
  },
  "message": "success"
}
```

Catatan:
- `device_info` hanya terisi di event `login`, `ip_address` hanya di `login_failed` — memang itu saja yang masing-masing direkam. Sejak Agustus 2026 `device_info` otomatis diisi dari header `User-Agent` kalau body login tidak mengirim `device_info`; row lama tetap kosong.
- `user_id`/`name` bisa `null`/`""` di `login_failed` kalau email-nya tidak cocok dengan akun mana pun.
- `org_id`/`org_name` = org context sesi tersebut saat login, bukan seluruh org milik user.
- Feed ini **bukan** audit log aplikasi. Aktivitas di dalam produk (mis. approval) tidak ada di sini — SIS hanya tahu peristiwa autentikasi.

---

### `GET /api/admin/users/:uid`
Detail 1 user: profil + ringkasan sesi + status kunci + semua org yang dia ikuti (status membership apa pun). Endpoint ini yang dipakai halaman user detail admin panel — sebelumnya FE terpaksa mengoper objek user lewat router state dari halaman list, sehingga hard refresh / deep link cuma dapat tampilan terbatas.

**Response 200**
```json
{
  "data": {
    "user": {
      "id": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
      "email": "budi@contoh.com",
      "name": "Budi Santoso",
      "is_platform_admin": false,
      "created_at": "2026-06-23T10:00:00Z",
      "last_login_at": "2026-08-27T13:11:09.663807Z",
      "active_sessions": 2,
      "is_locked": false,
      "lock_expires_at": null
    },
    "orgs": [
      {
        "org": { "id": "19bd5ea0-...", "name": "PT Contoh Sejahtera", "slug": "contoh-sejahtera" },
        "role": "owner",
        "membership_status": "active",
        "active_subscriptions": [ { "product_id": "shifd-approval", "plan": "trial", "status": "active" } ]
      }
    ]
  },
  "message": "success"
}
```
`uid` bukan UUID → `400 VALIDATION_ERROR`. User tidak ada → `404 NOT_FOUND`. Org yang sudah soft-deleted tidak ikut muncul di `orgs`.

---

### `POST /api/admin/users/:uid/force-logout`
Revoke semua refresh token milik user — semua sesi (web/mobile/dll) langsung ter-logout begitu access_token mereka expired (≤15 menit) dan mereka coba refresh.

**Request**: tidak ada body.

**Response 200**
```json
{ "data": null, "message": "all sessions revoked" }
```
Tidak error walau `uid` tidak punya sesi aktif sama sekali (operasi idempotent).

---

## 7. Path & Query Parameter

| Param | Dipakai di | Tipe |
|---|---|---|
| `:org_id`, `:user_id`, `:sub_id`, `:uid` | path | UUID v4 string. Format salah → `400 VALIDATION_ERROR` |
| `page`, `limit` | query (endpoint admin list) | integer > 0. Default `page=1`, `limit=20`, `limit` di-cap `100` |
| `email` | query (`GET /api/admin/users`, `GET /api/admin/activity`) | string, partial match |
| `type` | query (`GET /api/admin/activity`) | `login` atau `login_failed`. Nilai lain = tanpa filter |
| `plan` | query (`GET /api/admin/orgs`) | string exact match, salah satu dari `trial`, `premium_monthly`, `premium_yearly`. Filter ke org dengan subscription plan tsb yang sedang aktif |

---

## 8. JWT Access Token Claims

`access_token` adalah JWT RS256. FE **biasanya tidak perlu** decode ini — cukup kirim sebagai Bearer token. Tapi kalau perlu baca info di dalamnya tanpa hit API lagi (misal cek `org_role` buat hide/show menu), shape-nya:

```json
{
  "iss": "https://auth.shifd.com",
  "sub": "630e19ab-9027-4fd7-8a92-83f6aa788edb",
  "jti": "cc9fcc18-868d-4ca3-b49f-d099001d8202",
  "iat": 1782140339,
  "exp": 1782141239,
  "email": "budi@contoh.com",
  "name": "Budi Santoso",
  "org_id": "19bd5ea0-8da5-4db4-b7e4-6575e8579ab2",
  "org_role": "owner",
  "products": ["shifd-approval"]
}
```
- `exp - iat` = 900 detik (15 menit).
- `org_id`, `org_role`, `products` **hilang sepenuhnya dari claims** (bukan `null`) kalau user tidak punya org context aktif saat token diterbitkan.
- `products` = daftar `product_id` dari subscription **aktif & belum expired** milik org tersebut.
- Header JWT punya `kid: "sis-key-v1"` — cocokkan dengan `kid` di response JWKS kalau FE/service lain mau verifikasi signature sendiri (biasanya tidak perlu, itu tugas Shifd Approval).

---

## 9. Rate Limiting

Hanya berlaku di `POST /api/auth/register` dan `POST /api/auth/login`, per IP address, limit `RATE_LIMIT_AUTH_PER_MIN` (lihat `app.env`, default contoh `5`/menit).

Kena limit → `429`:
```json
{ "error": "Too many requests, please try again later", "code": "RATE_LIMIT_EXCEEDED" }
```

---

## 10. CORS

Origin FE harus terdaftar di `CORS_ALLOWED_ORIGINS` (comma-separated) di `app.env` server — **tidak ada wildcard**. Kalau origin tidak terdaftar, browser akan block request (tidak ada header `Access-Control-Allow-Origin` yang dikirim balik). Tidak perlu `credentials: 'include'` di fetch/axios karena auth pakai Bearer token, bukan cookie.

---

## 11. Belum Diimplementasikan

Endpoint ini ada di spesifikasi awal (`CLAUDE.md`) tapi **belum ada route/handler-nya** — jangan wiring FE ke ini dulu:

| Method & Path | Keterangan |
|---|---|
| `PATCH /api/orgs/:org_id` | Update nama organisasi |
| `PATCH /api/admin/users/:uid/lock` | Lock/unlock akun user secara manual (kunci otomatis dari login gagal tetap jalan, dan lepas sendiri) |

Email verification, OAuth/SSO, MFA, payment gateway, dan webhook subscription juga belum ada (sesuai "Out of Scope for Phase 1" di `CLAUDE.md`).

---

## 12. Catatan Penyesuaian FE — Perubahan Enum `plan` (BREAKING CHANGE)

⚠️ **Enum `plan` diganti total**, bukan ditambah. Lama: `standard | professional | enterprise | large_enterprise` (plus `trial` yang baru ditambahkan sebelumnya). Baru: **hanya 3 nilai** — `trial | premium_monthly | premium_yearly`. `premium_monthly`/`premium_yearly` adalah satu tier yang sama, bedanya cuma siklus billing (bulanan vs tahunan) — bukan tier fitur/kapasitas yang beda seperti dulu (standard/professional/enterprise punya kapasitas berjenjang).

**Yang WAJIB diubah di FE:**
1. **Dropdown/select plan** di form create/update subscription (admin panel) — ganti opsinya ke 3 nilai baru. Kalau ada label tampilan (mis. "Professional Plan"), sesuaikan jadi "Premium (Bulanan)" / "Premium (Tahunan)".
2. **Semua hardcoded string plan lama** di kode FE (switch/if-else untuk styling badge, filter, dsb. yang cek `=== "standard"`, `"professional"`, `"enterprise"`, `"large_enterprise"`) — tidak akan pernah match lagi untuk subscription baru, harus diganti ke 3 nilai baru.
3. **Request body** create/update subscription — kirim `plan` salah satu dari 3 nilai baru. Nilai lama sekarang ditolak server dengan `400 VALIDATION_ERROR` (pesan: `"plan must be one of: trial, premium_monthly, premium_yearly"`).

**Data lama sudah di-backfill** (`db/migrations/004_backfill_premium_yearly_plan.sql`): semua subscription existing dengan `plan = "standard"/"professional"/"enterprise"/"large_enterprise"` sudah diubah jadi `"premium_yearly"`. Kalau ada environment lain (staging/production) yang belum menjalankan migration ini, response GET di environment itu masih bisa memunculkan nilai plan lama sampai migration-nya dijalankan di sana juga — cukup jalankan file migration yang sama.

**Default `user_limit` per plan** (kalau admin tidak isi manual saat create): `trial` → 5, `premium_monthly`/`premium_yearly` → unlimited (`null`). Untuk kontrak dengan kuota seat tertentu (billing per-employee — lihat pembahasan sebelumnya), **isi `user_limit` eksplisit saat create**, jangan andalkan default.

---

## 13. Catatan Penyesuaian FE — Trial/Pilot Organisasi

Fitur trial **bukan** field baru di org/user — trial itu subscription biasa dengan `plan = "trial"`. Tidak ada tabel/kolom baru, jadi tidak ada breaking change tambahan di shape response manapun (di luar perubahan enum di atas).

**Membuat pilot untuk calon client:**
```
POST /api/admin/orgs/:org_id/subscriptions
{ "product_id": "shifd-approval", "plan": "trial", "expires_at": "2026-07-28T00:00:00Z" }
```
Akses org otomatis mati sendiri ≤15 menit setelah `expires_at` lewat (access token umur 15 menit, re-issued dari DB tiap refresh) — **tidak perlu** aksi manual dari FE atau admin untuk "mematikan" trial.

**Di mana FE bisa baca status trial:**
- `GET /api/admin/orgs/:org_id` → `data.subscriptions[].plan` — cek `=== "trial"` untuk tampilkan badge, dan hitung sisa hari dari `expires_at`.
- `GET /api/orgs/:org_id` dan `GET /api/orgs/:org_id/subscriptions` → sama, versi tenant (`active_subscriptions[].plan`).
- `GET /api/me/orgs` → user yang login juga otomatis dapat info ini lewat `active_subscriptions[].plan`, tanpa endpoint terpisah.

**Filter list org:** `GET /api/admin/orgs?plan=trial` untuk halaman admin yang mau nampilin "org mana saja yang lagi trial" tanpa buka detail satu-satu.

**Catatan FE:** batasan lama "item list tidak membawa `plan`" **sudah tidak berlaku** sejak Agustus 2026 — tiap item `GET /api/admin/orgs` sekarang membawa objek `subscription` (plan/status/expires_at/user_limit), jadi badge "Trial" dan hitung mundur expiry bisa dirender langsung di tabel list.

---

## 14. Catatan Penyesuaian FE — Revoke Akses Organisasi

Endpoint baru: `POST /api/admin/orgs/:org_id/force-logout` — cabut semua sesi (refresh token) seluruh member org sekaligus, dalam satu klik. Sebelumnya cuma ada versi per-user (`POST /api/admin/users/:uid/force-logout`); ini versi org-nya.

**Tempat yang wajar untuk tombol ini di admin panel:** halaman detail org (`GET /api/admin/orgs/:org_id`), sejenis tombol "Force Logout Organization" / "Revoke All Sessions" — bukan di halaman list org.

**WAJIB pakai dialog konfirmasi di FE sebelum panggil endpoint ini.** Efeknya me-logout seluruh member org secara paksa (semua device, semua sesi) — tidak ada undo. Idealnya konfirmasi menyebutkan jumlah member yang akan ke-logout (ambil dari `member_count` di response `GET /api/admin/orgs/:org_id`), meski API sendiri tidak mengembalikan angka "berapa sesi yang direvoke" di response-nya (cuma `{ "data": null, "message": "..." }`).

**Ini BUKAN tombol "Suspend Organization" / "Cancel Subscription".** Efeknya cuma logout paksa — kalau member login ulang dan subscription org masih aktif, mereka dapat akses lagi seperti biasa. Kalau maksud FE/admin adalah "hentikan akses org ini sepenuhnya" (bukan cuma logout paksa), harus **kombinasi 2 aksi**:
1. `POST /api/admin/orgs/:org_id/force-logout` — logout paksa semua sesi yang sedang aktif sekarang
2. `PATCH /api/admin/orgs/:org_id/subscriptions/:sub_id` dengan `status: "suspended"` (atau `"cancelled"`) untuk **setiap** subscription aktif org itu — supaya login ulang pun tidak dapat akses lagi

Kalau di admin panel ada use case "offboard client" / "hentikan pilot yang bermasalah", pertimbangkan bikin **satu tombol gabungan** di FE yang trigger kedua call itu berurutan (BE tidak menyediakan endpoint gabungan — dua request terpisah dari FE), supaya admin tidak lupa langkah kedua.

**Sesi user di org lain tidak ikut kena.** Kalau seorang user adalah member di org A dan org B, force-logout org A tidak me-logout sesi dia di org B — presisi per org context, bukan per user.
