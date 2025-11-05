# BlackHole Blockchain - Multi-Stage Production Dockerfile
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
COPY go.work go.work.sum* ./
COPY core/go.mod core/go.sum* ./core/
COPY bridge-sdk/go.mod bridge-sdk/go.sum* ./bridge-sdk/
COPY libs/go.mod* ./libs/
COPY services/go.mod* ./services/
COPY parachains/go.mod* ./parachains/

# Copy source code
COPY . .

# Build the blockchain binary
WORKDIR /app/core/relay-chain
RUN CGO_ENABLED=1 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s" \
    -o blockchain \
    ./cmd/relay/main.go

# Build the bridge binary
WORKDIR /app/bridge-sdk/main_bridge
RUN CGO_ENABLED=1 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s" \
    -o bridge-sdk \
    .

# Final runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    sqlite \
    curl \
    && addgroup -g 1001 appgroup \
    && adduser -u 1001 -S appuser -G appgroup

# Create application directories
WORKDIR /app
RUN mkdir -p data logs config media \
    && chown -R appuser:appgroup /app

# Copy binaries from builder
COPY --from=builder /app/core/relay-chain/blockchain ./
COPY --from=builder /app/bridge-sdk/main_bridge/bridge-sdk ./
COPY --from=builder /app/bridge-sdk/media ./media

# Copy environment file
COPY docker/.env* ./

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8080 8084 8545 9090 30303

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default environment variables
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV DOCKER_MODE=true

# Default command runs blockchain
CMD ["./blockchain"]