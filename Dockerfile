# BlackHole Blockchain Node - Production Dockerfile
FROM golang:1.24.3-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    gcc \
    musl-dev \
    sqlite-dev \
    ca-certificates

# Set working directory
WORKDIR /app

# Copy Go workspace files for dependency resolution
COPY go.work go.work.sum ./
COPY core/go.mod core/relay-chain/go.sum ./
COPY libs/go.mod ./libs/
COPY services/go.mod ./services/
COPY parachains/go.mod ./parachains/

# Copy source code
COPY . .

# Build the blockchain binary
WORKDIR /app/core/relay-chain
RUN CGO_ENABLED=1 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s" \
    -o /app/blockchain \
    ./cmd/relay/main.go

# Final runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    sqlite \
    curl \
    && addgroup -g 1001 appgroup \
    && adduser -u 1001 -S appuser -G appgroup

# Create application directories with proper permissions
WORKDIR /app
RUN mkdir -p /data/blockchain /app/logs /app/config \
    && mkdir -p /app/data \
    && chown -R appuser:appgroup /app /data \
    && chmod -R 775 /data /app \
    && chmod g+s /data/blockchain

# Copy binary from builder
COPY --from=builder /app/blockchain ./

# Copy environment file if exists
COPY docker/.env* ./ 2>/dev/null || :

# Set ownership and permissions for data directory
RUN chown -R appuser:appgroup /data/blockchain \
    && chmod -R 775 /data/blockchain

# Create a symlink to maintain compatibility with code expecting /app/data
RUN ln -s /data/blockchain /app/data/blockchain

# Switch to non-root user
USER appuser

# Set working directory to app
WORKDIR /app

# Expose ports
EXPOSE 8080 8545 30303

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default environment variables
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV DOCKER_MODE=true

# Default command runs blockchain
CMD ["./blockchain"]