# Build stage
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

# Copy only the necessary files for dependency resolution
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o bridge-sdk ./main_bridge/main.go

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite

# Set working directory and create necessary directories
WORKDIR /app
RUN mkdir -p /app/data /app/logs && \
    chown -R 1000:1000 /app

# Copy binary from builder
COPY --from=builder /app/bridge-sdk ./

# Create a default .env file
RUN echo "NODE_ENV=production" > /app/.env && \
    echo "LOG_LEVEL=info" >> /app/.env && \
    echo "PORT=8084" >> /app/.env && \
    echo "USE_REAL_BLOCKCHAIN_LISTENERS=true" >> /app/.env && \
    echo "RELAY_PORT=9090" >> /app/.env && \
    echo "DATABASE_PATH=/app/data/bridge.db" >> /app/.env && \
    echo "LOG_FILE=/app/logs/bridge.log" >> /app/.env && \
    echo "BLOCKCHAIN_RPC_URL=http://node1:8545" >> /app/.env

# Set ownership and permissions for data directory
RUN chown -R 1000:1000 /app

# Use non-root user
USER 1000:1000

# Expose ports
EXPOSE 8084 9090

# Command to run the application
CMD ["./bridge-sdk"]
