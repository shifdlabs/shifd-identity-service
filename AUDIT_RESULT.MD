# AUDIT_RESULT — Shifd Labs Identity Service (SIS)

> Tanggal audit: 2026-06-29
> Cakupan: seluruh source `cmd/`, `config/`, `db/`, `model/`, `repository/`, `service/`, `handler/`, `middleware/`, `pkg/`, `router/`, plus `Dockerfile`, `docker-compose.yml`, `app.env.example`, `.gitignore`.
> Metode: review statik manual (tidak menjalankan aplikasi). Referensi spesifikasi: `CLAUDE.md` dan `API.md`.

Ringkasan: arsitektur berlapis sudah rapi dan banyak praktik keamanan dasar sudah benar (bcrypt cost 12, refresh/reset token disimpan sebagai SHA-256, RS256 + cek signing-method untuk cegah alg-confusion, CORS allowlist tanpa wildcard, admin re-query DB untuk `is_platform_admin`, response envelope konsisten, secret tidak ter-commit). Namun ada beberapa celah yang membuat proteksi anti-brute-force bisa di-bypass, satu bug yang membuat Docker image gagal build, dan sejumlah area peningkatan operasional.

Legenda severity: **CRITICAL** · **HIGH** · **MEDIUM** · **LOW**

---

## 1. Celah Security / Bug yang Ditemukan

### [HIGH] S-01 — Rate limit & account-lock bisa di-bypass via spoofing IP (trusted proxies tidak dikonfigurasi)
- **Lokasi:** `router/router.go:38` (`gin.Default()` tanpa `SetTrustedProxies`), `middleware/rate_limit.middleware.go:33` (`c.ClientIP()`).
- **Masalah:** Secara default Gin mempercayai SEMUA proxy, sehingga `c.ClientIP()` mengambil nilai dari header `X-Forwarded-For` / `X-Real-IP` yang dikirim klien. Penyerang cukup merotasi nilai header tersebut tiap request untuk mendapat limiter baru per "IP".
- **Dampak:** Proteksi rate limit per-IP pada `/api/auth/login` dan `/api/auth/register` (security rule #4) menjadi tidak efektif → memungkinkan brute-force / credential stuffing dalam skala besar.
- **Perbaikan:** Panggil `engine.SetTrustedProxies([...])` dengan IP proxy/LB yang sebenarnya; jika service diekspos langsung (tanpa proxy), set ke `nil`/empty agar `ClientIP()` memakai `RemoteAddr`. Pertimbangkan juga `engine.ForwardedByClientIP` sesuai topologi deploy.

### [HIGH] S-02 — Docker image gagal build: versi Go tidak cocok
- **Lokasi:** `go.mod:3` → `go 1.26.2`, `Dockerfile:4` → `FROM golang:1.21-alpine`.
- **Masalah:** Toolchain Go 1.21 akan menolak mem-build modul yang mensyaratkan `go >= 1.26.2` (tidak ada direktif `toolchain` untuk auto-download). `CLAUDE.md` pun menyebut "Go 1.21+".
- **Dampak:** Build produksi (image Docker) gagal total — bug yang menghambat rilis.
- **Perbaikan:** Samakan versi: naikkan base image (mis. `golang:1.26-alpine`) atau turunkan direktif `go` di `go.mod` ke versi yang benar-benar dipakai. Selaraskan juga dengan `CLAUDE.md`.

### [HIGH] S-03 — `forgot-password` & `reset-password` tidak di-rate-limit (email bombing & resource abuse)
- **Lokasi:** `router/router.go:68-69` (tidak memakai `authRateLimiter`).
- **Masalah:** `/api/auth/forgot-password` bisa di-spam untuk membanjiri inbox korban dengan email reset dan menghabiskan kuota Resend; `/api/auth/reset-password` bisa di-hammer (token 32-byte memang infeasible di-brute, tapi tetap abuse sumber daya).
- **Dampak:** Email bombing terhadap korban, biaya/kuota email membengkak, potensi DoS.
- **Perbaikan:** Terapkan rate limit pada kedua endpoint (per-IP dan idealnya per-email). Tambahkan throttle khusus untuk pengiriman email reset per akun.

### [MEDIUM] S-04 — Window brute-force tidak benar-benar diterapkan (`CountRecentFailedLogins` dipanggil dengan `time.Time{}`)
- **Lokasi:** `service/auth.service.go:206` → `s.userRepo.CountRecentFailedLogins(ctx, user.Email, time.Time{})`; repo di `repository/user.repository.go:96-103`.
- **Masalah:** `time.Time{}` (zero value) menghasilkan query `attempted_at > '0001-01-01'`, sehingga MENGHITUNG SEMUA percobaan gagal (sejak reset terakhir), bukan rolling window seperti yang dijanjikan `CLAUDE.md` ("within a time window"). Parameter `since` dan index `idx_failed_login_email_time` praktis tidak terpakai. Tidak ada pula env var untuk panjang window.
- **Dampak:** Perilaku lockout menjadi "kegagalan beruntun sejak login sukses terakhir" alih-alih windowed. Masih mengunci akun, tapi menyimpang dari spesifikasi dan tidak bisa di-tuning.
- **Perbaikan:** Tambah konfigurasi window (mis. `FAILED_LOGIN_WINDOW_MINUTES`) dan kirim `time.Now().Add(-window)` ke `CountRecentFailedLogins`.

### [MEDIUM] S-05 — User yang terkunci masih bisa memperbarui access token
- **Lokasi:** `service/auth.service.go:338-381` (`Refresh` hanya cek soft-delete via `FindByID`, tidak cek `IsLocked`); `handleFailedLogin` (`:201-223`) menyetel `IsLocked` tanpa mencabut refresh token.
- **Masalah:** Saat akun dikunci (auto-lock brute force, atau kelak admin-lock), refresh token tidak di-revoke dan `Refresh` tidak menolak user terkunci.
- **Dampak:** User/penyerang dengan refresh token aktif tetap bisa mint access token baru tiap 15 menit hingga refresh token kedaluwarsa (7 hari) meski akun "terkunci".
- **Perbaikan:** Di `Refresh`, tolak bila `user.IsLocked`. Saat lock di-set, panggil `refreshTokenRepo.RevokeAllByUserID`.

### [MEDIUM] S-06 — User enumeration via timing & response berbeda
- **Lokasi:** `service/auth.service.go:144-170` (login: jika email tak ada → return cepat tanpa bcrypt; jika ada → jalankan bcrypt yang mahal); `Register` `:110-114` mengembalikan `EMAIL_ALREADY_EXISTS`.
- **Masalah:** Perbedaan waktu respons login (ada vs tidak ada bcrypt) memungkinkan enumerasi email terdaftar; `register` mengonfirmasi keberadaan email secara eksplisit. (Catatan: `ForgotPassword` sudah benar — selalu balas sukses.)
- **Dampak:** Penyerang dapat menyusun daftar email valid sebelum melakukan brute force/phishing.
- **Perbaikan:** Lakukan dummy `bcrypt.CompareHashAndPassword` terhadap hash dummy pada cabang "user not found" agar waktu respons seragam. Untuk register, pertimbangkan alur konfirmasi via email alih-alih membocorkan status.

### [MEDIUM] S-07 — Account-lockout DoS (lock berbasis email saja)
- **Lokasi:** `service/auth.service.go:201-223`; IP tidak pernah dicatat — `handleFailedLogin` memanggil `IncrementFailedLogins(ctx, user.Email, "")` (`:202`).
- **Masalah:** Siapa pun yang tahu email korban dapat sengaja mengirim password salah berulang untuk mengunci akun korban (default 30 menit), berulang kali.
- **Dampak:** Denial-of-service terhadap akun tertentu (mis. akun admin).
- **Perbaikan:** Pertimbangkan lockout berbasis kombinasi IP+email, atau exponential backoff/CAPTCHA alih-alih hard-lock, dan catat `ip_address` pada `failed_login_attempts` (kolomnya sudah ada di skema).

### [MEDIUM] S-08 — Redis dikonfigurasi tapi tidak dipakai → rate limit tidak konsisten di multi-instance
- **Lokasi:** `config/config.go:32-34,95-96`, `docker-compose.yml:29-36`, `app.env.example:36-38`; tidak ada pemakaian Redis di kode. Limiter in-memory `sync.Map` di `middleware/rate_limit.middleware.go:29`.
- **Masalah:** Rate limiter disimpan di memori per-proses. Jika di-deploy >1 replika, batas efektif menjadi N× lipat (tiap instance punya counter sendiri). Counter brute-force memang di DB (konsisten), tapi rate limit tidak.
- **Dampak:** Proteksi rate limit melemah pada deployment horizontal; konfigurasi Redis menyesatkan (dead config).
- **Perbaikan:** Pindahkan rate limiting (dan idealnya counter lockout) ke Redis dengan TTL, atau hapus konfigurasi Redis yang tidak terpakai.

### [MEDIUM] S-09 — Tidak ada batas ukuran request body (DoS memori)
- **Lokasi:** Semua handler `ShouldBindJSON` (mis. `handler/auth.handler.go`), tidak ada `http.MaxBytesReader` di mana pun.
- **Masalah:** Body JSON berukuran sangat besar diterima tanpa batas.
- **Dampak:** Konsumsi memori berlebih → potensi DoS.
- **Perbaikan:** Tambah middleware global yang membungkus `c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, <limit>)` (mis. 1 MB).

### [LOW] S-10 — bcrypt 72-byte truncation tidak ditangani & kebijakan password minim
- **Lokasi:** `service/auth.service.go:106-119` (register), `service/user.service.go:114-118` (change password); hanya cek `minPasswordLength = 8`.
- **Masalah:** Tidak ada batas maksimum. bcrypt diam-diam memotong input di 72 byte, sehingga password sangat panjang hanya memakai 72 byte pertama. Tidak ada cek kompleksitas/daftar password bocor.
- **Dampak:** Kekuatan password efektif berkurang pada kasus tepi; entropi tinggi yang dikira aman bisa terpotong.
- **Perbaikan:** Tolak password > 72 byte (atau pre-hash SHA-256 → base64 sebelum bcrypt), dan pertimbangkan kebijakan/zxcvbn.

### [LOW] S-11 — TOCTOU pada penegakan seat limit
- **Lokasi:** `service/subscription.service.go:164-184` (`EnforceUserLimit`) dipanggil sebelum `Create` di `org.service.go:235-250` dan `admin.service.go:113-125`, tanpa lock/transaksi.
- **Masalah:** Dua invite konkuren bisa sama-sama lolos pengecekan count lalu insert, melampaui `user_limit`.
- **Dampak:** Pelampauan batas seat (bypass kuota berbayar). Kecil di Phase 1.
- **Perbaikan:** Lakukan cek+insert dalam satu transaksi dengan `SELECT ... FOR UPDATE` pada baris subscription/org, atau constraint DB.

### [LOW] S-12 — JWT tidak memvalidasi `iss` (dan tidak ada `aud`)
- **Lokasi:** `pkg/jwtutil/jwtutil.go:115-134` (`ParseToken`), `middleware/auth.middleware.go:40`.
- **Masalah:** Hanya signature + exp yang divalidasi; `iss` yang di-set saat issuance (`:98`) tidak diverifikasi saat parsing, dan tidak ada claim `aud`.
- **Dampak:** Rendah (signature sudah terikat ke key SIS), tapi praktik baiknya tetap memvalidasi `iss`/`aud`, terutama jika key dipakai lintas konteks.
- **Perbaikan:** Tambahkan `jwt.WithIssuer(cfg.JWTIssuer)` (dan `WithAudience` bila ditambahkan) saat parsing.

### [LOW] S-13 — Validasi data subscription kurang
- **Lokasi:** `service/subscription.service.go:65-83` (`CreateSubscription` tidak validasi `product_id`/`plan`), `:100-127` (`UpdateSubscription` validasi `status` saja, bukan `plan`).
- **Dampak:** Admin dapat membuat subscription dengan `product_id`/`plan` arbitrer → produk tak dikenal tak akan match `ProductShifdApproval` pada penegakan limit. Admin-only, jadi risiko rendah.
- **Perbaikan:** Validasi `product_id` dan `plan` terhadap whitelist; validasi `expires_at` tidak di masa lalu.

### [LOW] S-14 — PII (alamat email) tercatat di log
- **Lokasi:** mis. `handler/auth.handler.go:80,118`, `service/auth.service.go:402,409,419,424`.
- **Dampak:** Email pengguna tercecer di log aplikasi (isu privasi/kepatuhan).
- **Perbaikan:** Redaksi/hindari log email mentah; gunakan user ID atau email ter-mask.

### [LOW] S-15 — Akun yang dikunci dengan `LockTimestamp` NULL = terkunci permanen
- **Lokasi:** `service/auth.service.go:152-156`.
- **Masalah:** Jika `IsLocked = true` tapi `LockTimestamp = nil` (mis. lock manual via DB), cabang auto-unlock tak pernah jalan → akun terkunci selamanya.
- **Perbaikan:** Tangani kasus `LockTimestamp == nil` (mis. perlakukan sebagai sudah lewat, atau wajibkan timestamp saat mengunci).

### [LOW] S-16 — `DB_SSLMODE=disable` & higiene konfigurasi
- **Lokasi:** `app.env.example:34` (`DB_SSLMODE=disable`), `db/database.go:20-23`.
- **Dampak:** Wajar untuk dev, tapi pastikan produksi memakai `require`/`verify-full` agar koneksi DB terenkripsi.
- **Perbaikan:** Dokumentasikan/paksa SSL di produksi.

---

## 2. Apa Saja yang Bisa Di-improve

### Kualitas & keandalan
- **Tidak ada test sama sekali** (0 file `*_test.go`). Logika kritikal (auth, jwtutil, middleware, lockout, seat-limit) tanpa pengaman regresi. → Tambah unit + integration test, prioritaskan `service/auth.service.go`, `pkg/jwtutil`, dan middleware.
- **Tidak ada graceful shutdown.** `cmd/server/main.go:88` memakai `engine.Run` langsung; tidak ada penanganan sinyal/`http.Server.Shutdown`, sehingga request in-flight bisa terputus saat deploy. → Bungkus dengan `http.Server` + `signal.NotifyContext`.
- **N+1 query** di `service/org.service.go:364-391` (`ListMembers`), `service/admin.service.go:142-161` (`GetOrgDetail`), `service/user.service.go:134-163` (`ListUserOrgs`) — satu lookup user/subscription per baris. → Tambah query join di repository.
- **Limiter in-memory tidak pernah di-evict** (diakui di komentar `rate_limit.middleware.go:18-21`) → pertumbuhan memori seiring jumlah IP unik. → Sweeper + TTL, atau Redis.

### Keamanan tingkat lanjut (peningkatan, bukan celah langsung)
- **Refresh token tidak di-rotate & tanpa reuse-detection** (didokumentasikan di `API.md`). Token curian valid 7 hari tanpa deteksi. → Pertimbangkan rotasi + deteksi reuse (revoke family).
- **Tidak ada rotasi key JWT** — hanya satu `kid` (`sis-key-v1`), JWKS hanya memuat 1 key. → Dukung multi-key di JWKS agar rotasi mulus untuk downstream.
- **Tidak ada security headers** (X-Content-Type-Options, X-Frame-Options, HSTS saat TLS, Referrer-Policy). → Tambah middleware header.
- **`ResetPassword` tidak meng-unlock akun** yang sedang terkunci (`service/auth.service.go:433-479`). User yang reset password karena lupa tetap harus menunggu lock berakhir. → Unlock + reset failed attempts saat reset password sukses.
- **`ChangePassword` tidak menawarkan revoke sesi lain** (`service/user.service.go:96-127`, sudah didokumentasikan sebagai sengaja) → bisa jadi opsi "logout perangkat lain".

### Konsistensi & kelengkapan
- **Endpoint terdokumentasi belum diimplementasi** (lihat `API.md:817-819`): `PATCH /api/orgs/:org_id` (update nama org), `GET /api/admin/users/:uid` (detail user), `PATCH /api/admin/users/:uid/lock` (lock/unlock akun oleh admin). Catatan penting: **admin belum punya cara mengunci/membuka akun secara manual** — hanya auto-lock brute force yang ada.
- **Penomoran migrasi melompat** (`001` → `003`, tanpa `002`) dan tidak ada tooling migrasi (mis. golang-migrate); migrasi dijalankan manual. Model `Subscription.UserLimit` bergantung pada `003`. → Konsolidasikan & gunakan migration tool.
- **`*.md` di-gitignore** (`.gitignore:6`) → semua dokumentasi (`CLAUDE.md`, `API.md`, file audit ini) tidak ter-version-control. → Whitelist file docs penting (`!CLAUDE.md`, `!API.md`).
- **Pesan error campur bahasa** (Inggris & Indonesia, mis. `handler/helpers.go:73` vs `handler/auth.handler.go`). → Seragamkan (atau i18n).
- **Tidak ada observability** (structured logging, request ID, metrics, tracing). Hanya logger bawaan `gin.Default()`.
- **Register: cek-email-lalu-create tidak atomik** (`service/auth.service.go:110-133`) → pada race, unique-violation DB terbungkus jadi 500, bukan 409. → Tangani error unique violation secara eksplisit menjadi `EMAIL_ALREADY_EXISTS`.

---

## 3. Saran / Rekomendasi (Prioritas)

**Harus diperbaiki sebelum produksi (P0):**
1. **S-02** — Selaraskan versi Go (`go.mod` vs `Dockerfile`) agar image bisa di-build.
2. **S-01** — Konfigurasikan `SetTrustedProxies` sesuai topologi agar rate limit/lock tidak bisa di-bypass.
3. **S-03** — Tambahkan rate limit pada `forgot-password`/`reset-password` (+ throttle email per akun).
4. **S-05** — Tolak `Refresh` untuk user terkunci & revoke refresh token saat lock.

**Berikutnya (P1):**
5. **S-04** — Terapkan window brute-force yang sebenarnya (+ env config) alih-alih `time.Time{}`.
6. **S-08** — Pindahkan rate limit/lockout ke Redis (Redis sudah disediakan tapi tidak dipakai) untuk konsistensi multi-instance.
7. **S-06 / S-07** — Mitigasi enumerasi (dummy bcrypt) & DoS lockout (IP+email / backoff, catat `ip_address`).
8. **S-09** — Tambah `MaxBytesReader` global.
9. Tambahkan **test** untuk auth, jwtutil, dan middleware; tambahkan **graceful shutdown**.

**Pengerasan & kebersihan (P2):**
10. S-10 (batas password 72-byte), S-12 (validasi `iss`), S-13 (validasi subscription), S-14 (redaksi PII di log), S-15 (lock timestamp NULL), S-16 (SSL DB produksi).
11. Implementasi endpoint admin lock/unlock & detail user; rotasi key JWT (multi-key JWKS); security headers; rotasi/refresh-token reuse-detection.
12. Perbaiki N+1 query, eviction limiter, konsolidasi migrasi + tooling, whitelist docs di `.gitignore`, seragamkan bahasa pesan error, observability.

---

### Catatan positif (sudah benar — pertahankan)
- bcrypt cost 12; refresh & reset token disimpan sebagai SHA-256 hex (raw tidak pernah disimpan).
- RS256 dengan verifikasi signing-method (mencegah alg-confusion `none`/HS256) di `jwtutil.ParseToken`.
- Admin middleware me-re-query `is_platform_admin` dari DB tiap request (tidak percaya JWT) — sesuai rule #8.
- CORS allowlist ketat tanpa wildcard `*`.
- `ForgotPassword` anti-enumerasi (selalu balas sukses, error ditelan & dicatat internal).
- Reset password single-use + revoke semua refresh token setelahnya.
- Otorisasi org-role diverifikasi di service (tidak percaya claim JWT) lewat `getActiveMembership`.
- Secret tidak ter-commit (`app.env` di-gitignore; hanya `app.env.example` yang dilacak).
- Soft-delete pada users & organizations; penggunaan transaksi pada create-org + owner-membership.
