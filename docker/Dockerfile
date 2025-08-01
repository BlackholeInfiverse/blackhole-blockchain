# BlackHole Bridge SDK Docker Image
FROM golang:1.24.3-alpine AS builder

# Set GOTOOLCHAIN to use local Go version (avoid network downloads)
ENV GOTOOLCHAIN=local

# Install required packages
RUN apk add --no-cache git gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go workspace files first for better caching
COPY go.work go.work.sum ./
COPY bridge-sdk/go.mod bridge-sdk/go.sum ./bridge-sdk/
COPY core/go.mod ./core/
COPY libs/go.mod ./libs/
COPY services/go.mod ./services/
COPY parachains/go.mod ./parachains/

# Copy the core directory (required by bridge-sdk workspace)
COPY core/ ./core/
COPY libs/ ./libs/
COPY services/ ./services/
COPY parachains/ ./parachains/

# Copy the entire bridge-sdk source code (needed for go.work)
COPY bridge-sdk/ ./bridge-sdk/

# # Download dependencies
# WORKDIR /app/bridge-sdk
# RUN go mod download

# Build the bridge-sdk application
WORKDIR /app/bridge-sdk/example
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o bridge-sdk main.go

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite

# Create app directory and user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/bridge-sdk/example/bridge-sdk .

# Create necessary directories
RUN mkdir -p data logs media && \
    chown -R appuser:appgroup /app

# Copy media files from the new location
COPY --from=builder /app/bridge-sdk/media ./media

# Switch to non-root user
USER appuser

# Expose the bridge-sdk port
EXPOSE 8084

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8084/health || exit 1

# Set environment variables
ENV BRIDGE_PORT=8084
ENV DATABASE_PATH=./data/bridge_fixed.db
ENV LOG_LEVEL=info
ENV LOG_FILE=./logs/bridge.log
ENV REPLAY_PROTECTION_ENABLED=true
ENV CIRCUIT_BREAKER_ENABLED=true
ENV MAX_RETRIES=3
ENV ENABLE_COLORED_LOGS=true
ENV ENABLE_DOCUMENTATION=true

# Run the bridge-sdk
CMD ["./bridge-sdk"]
