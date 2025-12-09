# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN go build -o wallet .

# Production stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/wallet .

# Expose port 9000
EXPOSE 9000

# Run the wallet service
CMD ["./wallet", "-web", "-port", "9000", "-peerAddr", "/dns4/blackhole-node-1/tcp/3000/p2p/12D3KooWMRRmpZVtmSC8ShFxR5kVLdycGHuLtuvxMtvgAhLN22ku"]
