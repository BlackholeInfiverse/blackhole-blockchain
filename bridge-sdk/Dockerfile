# Multi-stage build for BlackHole Bridge
FROM golang:1.24.3-alpine AS builder
# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy everything (assuming build context is project root)
COPY . .

WORKDIR /app/bridge-sdk/example

# Download dependencies
RUN go mod tidy && go build -o main .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create app user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bridge-sdk/example/main .

# Copy static assets
COPY --from=builder /app/bridge-sdk/example/blackhole-logo.jpg .

# Create necessary directories
RUN mkdir -p data logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8084

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8084/health || exit 1

# Run the application
CMD ["./main"]
