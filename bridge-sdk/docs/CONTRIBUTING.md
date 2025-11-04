# Contributing to BlackHole Bridge SDK

🎉 Thank you for your interest in contributing to the BlackHole Bridge SDK! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## 📜 Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful** and inclusive
- **Be collaborative** and constructive
- **Be patient** with newcomers
- **Focus on what's best** for the community
- **Show empathy** towards other community members

## 🚀 Getting Started

### Prerequisites

- **Go 1.21+** - [Install Go](https://golang.org/dl/)
- **Git** - [Install Git](https://git-scm.com/downloads)
- **Docker** (optional) - [Install Docker](https://docs.docker.com/get-docker/)

### Fork and Clone

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/bridge-sdk.git
   cd bridge-sdk
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/blackhole-network/bridge-sdk.git
   ```

## 🛠️ Development Setup

### Local Development

```bash
# Install dependencies
go mod download

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env

# Run development server
cd example && go run main.go
```

### Docker Development

```bash
# Start development environment
make dev

# Or using Docker Compose
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

### Verify Setup

```bash
# Check health
curl http://localhost:8084/health

# Run tests
go test ./...

# Run linting
golangci-lint run
```

## 📝 Contributing Guidelines

### Types of Contributions

We welcome various types of contributions:

- 🐛 **Bug fixes**
- ✨ **New features**
- 📚 **Documentation improvements**
- 🧪 **Test coverage improvements**
- 🔧 **Performance optimizations**
- 🎨 **UI/UX improvements**

### Before You Start

1. **Check existing issues** to avoid duplicates
2. **Create an issue** for new features or major changes
3. **Discuss your approach** with maintainers
4. **Keep changes focused** and atomic

### Issue Guidelines

When creating issues:

- **Use clear, descriptive titles**
- **Provide detailed descriptions**
- **Include steps to reproduce** (for bugs)
- **Add relevant labels**
- **Reference related issues**

**Bug Report Template**:
```markdown
## Bug Description
Brief description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 20.04]
- Go version: [e.g., 1.21.0]
- Bridge SDK version: [e.g., v1.0.0]

## Additional Context
Any other relevant information
```

**Feature Request Template**:
```markdown
## Feature Description
Brief description of the feature

## Use Case
Why is this feature needed?

## Proposed Solution
How should this feature work?

## Alternatives Considered
Other approaches you've considered

## Additional Context
Any other relevant information
```

## 🔄 Pull Request Process

### 1. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- **Follow coding standards** (see below)
- **Write tests** for new functionality
- **Update documentation** as needed
- **Keep commits atomic** and well-described

### 3. Test Your Changes

```bash
# Run all tests
go test ./...

# Run with race detection
go test -race ./...

# Run integration tests
go test -tags=integration ./...

# Check test coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 4. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add support for custom relay handlers

- Add SetRelayHandler method to BridgeSDK
- Implement custom validation logic
- Add tests for custom relay functionality
- Update documentation

Closes #123"
```

### 5. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

### Pull Request Guidelines

- **Use clear, descriptive titles**
- **Reference related issues** (e.g., "Closes #123")
- **Provide detailed description** of changes
- **Include testing information**
- **Update documentation** if needed
- **Ensure CI passes**

**PR Template**:
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 🎨 Coding Standards

### Go Style Guide

Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) and these additional guidelines:

#### Naming Conventions

```go
// Use camelCase for variables and functions
var bridgeConfig *Config
func startEthereumListener() error

// Use PascalCase for exported types and functions
type BridgeSDK struct {}
func NewBridgeSDK() *BridgeSDK

// Use ALL_CAPS for constants
const MAX_RETRY_ATTEMPTS = 3
```

#### Error Handling

```go
// Always handle errors explicitly
result, err := someFunction()
if err != nil {
    return fmt.Errorf("failed to execute function: %w", err)
}

// Use custom error types for specific errors
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation error in field %s: %s", e.Field, e.Message)
}
```

#### Documentation

```go
// Package documentation
// Package bridgesdk provides cross-chain bridge functionality
// for Ethereum, Solana, and BlackHole networks.
package bridgesdk

// Function documentation
// StartEthereumListener starts the Ethereum blockchain event listener.
// It returns an error if the connection cannot be established.
func StartEthereumListener(ctx context.Context) error {
    // Implementation
}

// Type documentation
// BridgeSDK provides the main interface for cross-chain bridge operations.
type BridgeSDK struct {
    // blockchain is the underlying blockchain instance
    blockchain Blockchain
    // config holds the bridge configuration
    config *Config
}
```

#### Code Organization

```go
// Group imports logically
import (
    // Standard library
    "context"
    "fmt"
    "time"
    
    // Third-party packages
    "github.com/gorilla/websocket"
    "github.com/sirupsen/logrus"
    
    // Local packages
    "github.com/blackhole-network/bridge-sdk/internal/types"
)

// Group struct fields logically
type Config struct {
    // Network configuration
    EthereumRPC string
    SolanaRPC   string
    
    // Database configuration
    DatabasePath string
    DatabaseType string
    
    // Security configuration
    ReplayProtectionEnabled bool
    CircuitBreakerEnabled   bool
}
```

### Code Quality

#### Use Linting Tools

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linting
golangci-lint run

# Fix auto-fixable issues
golangci-lint run --fix
```

#### Performance Considerations

```go
// Use context for cancellation
func processEvents(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case event := <-eventChan:
            // Process event
        }
    }
}

// Use sync.Pool for frequent allocations
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 1024)
    },
}

// Prefer channels for goroutine communication
func startWorkers(eventChan <-chan Event, resultChan chan<- Result) {
    for i := 0; i < numWorkers; i++ {
        go worker(eventChan, resultChan)
    }
}
```

## 🧪 Testing

### Test Structure

```go
package bridgesdk

import (
    "testing"
    "context"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/mock"
)

func TestBridgeSDK_StartEthereumListener(t *testing.T) {
    tests := []struct {
        name    string
        setup   func() *BridgeSDK
        wantErr bool
    }{
        {
            name: "successful start",
            setup: func() *BridgeSDK {
                return NewBridgeSDK(mockBlockchain, validConfig)
            },
            wantErr: false,
        },
        {
            name: "invalid config",
            setup: func() *BridgeSDK {
                return NewBridgeSDK(mockBlockchain, invalidConfig)
            },
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            sdk := tt.setup()
            err := sdk.StartEthereumListener(context.Background())
            
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Test Categories

#### Unit Tests
```bash
# Run unit tests only
go test -short ./...
```

#### Integration Tests
```bash
# Run integration tests
go test -tags=integration ./...
```

#### Benchmark Tests
```bash
# Run benchmarks
go test -bench=. ./...
```

### Test Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out

# Check coverage percentage
go tool cover -func=coverage.out
```

**Coverage Requirements:**
- **Minimum 80%** overall coverage
- **90%+ coverage** for critical components
- **100% coverage** for security-related code

## 📚 Documentation

### Documentation Types

1. **Code Documentation** - GoDoc comments
2. **API Documentation** - REST API reference
3. **User Documentation** - Usage guides and tutorials
4. **Architecture Documentation** - System design and architecture

### Writing Guidelines

- **Use clear, concise language**
- **Provide examples** where helpful
- **Keep documentation up-to-date** with code changes
- **Include troubleshooting information**

### Documentation Tools

```bash
# Generate documentation
go doc -all ./...

# Serve documentation locally
godoc -http=:6060
```

## 🏷️ Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped
- [ ] Git tag created
- [ ] Release notes written

## 🤝 Community

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and discussions
- **Discord** - Real-time chat and community support
- **Email** - Direct contact with maintainers

### Recognition

Contributors will be recognized in:
- **CONTRIBUTORS.md** file
- **Release notes**
- **Project documentation**

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

Thank you for contributing to the BlackHole Bridge SDK! Your contributions help make cross-chain bridging more accessible and reliable for everyone.
