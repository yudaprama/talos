# Build stage
FROM golang:1.26-alpine AS builder

# Install build dependencies (gcc/musl-dev required for CGO/sqlite3)
RUN apk add --no-cache git make ca-certificates tzdata gcc musl-dev

# Create non-root user for runtime
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy the replaced sibling modules referenced by talos/talos/go.mod.
COPY cloudlib ./cloudlib
COPY x ./x

# Copy talos sources (context is the repository root).
COPY talos/talos ./talos/talos

WORKDIR /build/talos/talos

# Download dependencies
RUN go mod download

# Build the binary (CGO required for sqlite3)
RUN CGO_ENABLED=1 go build \
    -ldflags="-w -s" \
    -o talos main.go

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    wget

# Create non-root user
RUN addgroup -g 1000 talos && \
    adduser -D -u 1000 -G talos talos

# Create directories
RUN mkdir -p /var/lib/talos /etc/talos && \
    chown -R talos:talos /var/lib/talos /etc/talos

# Copy the binary from builder
COPY --from=builder /build/talos/talos/talos /talos

# Copy migrations (OSS only)
COPY --from=builder /build/talos/talos/internal/persistence/migrations /migrations

# Use non-root user
USER talos:talos

# Expose ports
# 8080: HTTP API (alternative)
# 4420: HTTP API (default)
# 4422: Metrics endpoint
EXPOSE 8080 4420 4422

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:4422/metrics || exit 1

# Default entrypoint
ENTRYPOINT ["/talos"]

# Default command
CMD ["serve"]
