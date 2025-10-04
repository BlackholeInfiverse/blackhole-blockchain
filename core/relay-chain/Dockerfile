# Use official Go image - using latest to match go.mod requirements
FROM golang:alpine AS builder

# Install git and other dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the blockchain node
RUN go build -o node cmd/relay/main.go

# Build the enhanced wallet
RUN go build -o enhanced-wallet cmd/enhanced-wallet/main.go

# Runtime stage
FROM alpine:latest

# Install ca-certificates
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/node .
COPY --from=builder /app/enhanced-wallet .

# Create data directory
RUN mkdir -p /app/data

# Set up volume for persistent data
VOLUME ["/app/data"]

# Expose ports
EXPOSE 3000 3001 3002 8080 8888

# Default command
CMD ["./node", "3000"]