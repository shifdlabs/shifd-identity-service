# ============================================================
# Stage 1: Build
# ============================================================
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies dulu (layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source dan build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /bin/sis \
    ./cmd/server

# ============================================================
# Stage 2: Run (minimal image)
# ============================================================
FROM alpine:3.19

# Needed for HTTPS outbound (Resend API) and proper timezone
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /bin/sis /app/sis

EXPOSE 8080

CMD ["/app/sis"]
