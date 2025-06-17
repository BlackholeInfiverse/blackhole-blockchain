#!/bin/bash

# BlackHole Bridge Testnet Setup Script
# This script sets up the complete end-to-end testnet demonstration

set -e  # Exit on any error

echo "🚀 BlackHole Bridge Testnet Setup"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check prerequisites
echo "🔍 Checking prerequisites..."

# Check Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    print_status "Node.js is installed: $NODE_VERSION"
else
    print_error "Node.js is not installed. Please install Node.js 18+ from https://nodejs.org/"
    exit 1
fi

# Check npm
if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    print_status "npm is installed: $NPM_VERSION"
else
    print_error "npm is not installed. Please install npm."
    exit 1
fi

# Check Go
if command -v go &> /dev/null; then
    GO_VERSION=$(go version)
    print_status "Go is installed: $GO_VERSION"
else
    print_error "Go is not installed. Please install Go 1.21+ from https://golang.org/"
    exit 1
fi

# Check Git
if command -v git &> /dev/null; then
    GIT_VERSION=$(git --version)
    print_status "Git is installed: $GIT_VERSION"
else
    print_error "Git is not installed. Please install Git."
    exit 1
fi

# Create necessary directories
echo ""
echo "📁 Creating project directories..."
mkdir -p logs config screenshots
print_status "Created directories: logs, config, screenshots"

# Setup Ethereum contracts
echo ""
echo "🔧 Setting up Ethereum contracts..."
cd ethereum-contracts

if [ ! -f "package.json" ]; then
    print_error "Ethereum contracts package.json not found!"
    exit 1
fi

print_info "Installing Ethereum dependencies..."
npm install

if [ ! -f ".env" ]; then
    print_warning "Creating .env file from template..."
    cp .env.example .env
    print_warning "Please edit .env file with your private key and RPC URLs"
fi

cd ..

# Setup Solana contracts
echo ""
echo "🔧 Setting up Solana contracts..."
cd solana-contracts

if [ ! -f "package.json" ]; then
    print_error "Solana contracts package.json not found!"
    exit 1
fi

print_info "Installing Solana dependencies..."
npm install

cd ..

# Setup monitoring scripts
echo ""
echo "🔧 Setting up monitoring scripts..."
cd scripts

print_info "Installing monitoring dependencies..."
npm init -y 2>/dev/null || true
npm install ethers @solana/web3.js @solana/spl-token dotenv bs58

cd ..

# Check bridge SDK
echo ""
echo "🔧 Checking bridge SDK..."
cd ../bridge-sdk

if [ ! -f "go.mod" ]; then
    print_error "Bridge SDK go.mod not found!"
    exit 1
fi

print_info "Installing Go dependencies..."
go mod tidy

cd example
if [ ! -f "main.go" ]; then
    print_error "Bridge example main.go not found!"
    exit 1
fi

print_status "Bridge SDK is ready"

cd ../../testnet-setup

# Create demo configuration
echo ""
echo "📋 Creating demo configuration..."

cat > config/demo-config.json << EOF
{
  "demo": {
    "name": "BlackHole Bridge End-to-End Testnet Demo",
    "version": "1.0.0",
    "networks": {
      "ethereum": {
        "name": "Sepolia Testnet",
        "chainId": 11155111,
        "rpcUrl": "https://ethereum-sepolia-rpc.publicnode.com",
        "explorerUrl": "https://sepolia.etherscan.io",
        "faucetUrl": "https://sepoliafaucet.com/"
      },
      "solana": {
        "name": "Devnet",
        "cluster": "devnet",
        "rpcUrl": "https://api.devnet.solana.com",
        "explorerUrl": "https://explorer.solana.com",
        "faucetCommand": "solana airdrop 2"
      }
    },
    "bridge": {
      "dashboardUrl": "http://localhost:8084",
      "apiUrl": "http://localhost:8084/api"
    }
  }
}
EOF

print_status "Demo configuration created"

# Create quick start script
echo ""
echo "📝 Creating quick start script..."

cat > quick-start.sh << 'EOF'
#!/bin/bash

echo "🚀 BlackHole Bridge Quick Start"
echo "==============================="

echo "1. 📋 Prerequisites Check:"
echo "   - Ethereum Sepolia ETH in wallet (get from https://sepoliafaucet.com/)"
echo "   - Private key in ethereum-contracts/.env file"
echo "   - Solana CLI installed (optional)"

echo ""
echo "2. 🚀 Deploy Contracts (if not already deployed):"
echo "   cd ethereum-contracts && npm run deploy:sepolia"
echo "   cd ../solana-contracts && npm run deploy:devnet"

echo ""
echo "3. 🌉 Start Bridge System:"
echo "   cd ../bridge-sdk/example && go run main.go"

echo ""
echo "4. 👁️  Start Monitoring (in new terminal):"
echo "   cd testnet-setup/scripts && node monitor-bridge.js"

echo ""
echo "5. 💸 Send Test Transactions (in new terminal):"
echo "   cd testnet-setup/scripts"
echo "   node send-eth-transaction.js"
echo "   node send-sol-transaction.js"

echo ""
echo "6. 📊 View Results:"
echo "   - Bridge Dashboard: http://localhost:8084"
echo "   - Logs: ./logs/"
echo "   - Config: ./config/"

echo ""
echo "🎥 For screen recording, capture:"
echo "   - Contract deployment output"
echo "   - Bridge startup logs"
echo "   - Transaction sending"
echo "   - Dashboard showing real-time processing"
echo "   - Cross-chain relay completion"
EOF

chmod +x quick-start.sh
print_status "Quick start script created"

# Create package.json for scripts
echo ""
echo "📦 Creating package.json for scripts..."

cd scripts
cat > package.json << EOF
{
  "name": "blackhole-bridge-scripts",
  "version": "1.0.0",
  "description": "Scripts for BlackHole Bridge testnet demonstration",
  "main": "monitor-bridge.js",
  "scripts": {
    "monitor": "node monitor-bridge.js",
    "send-eth": "node send-eth-transaction.js",
    "send-sol": "node send-sol-transaction.js",
    "demo": "node ../demo.js"
  },
  "dependencies": {
    "ethers": "^6.8.0",
    "@solana/web3.js": "^1.87.0",
    "@solana/spl-token": "^0.3.9",
    "dotenv": "^16.3.1",
    "bs58": "^5.0.0"
  }
}
EOF

npm install
cd ..

print_status "Scripts package.json created and dependencies installed"

# Final setup summary
echo ""
echo "🎉 Setup Complete!"
echo "=================="
print_status "All components are ready for the end-to-end demo"

echo ""
echo "📋 Next Steps:"
echo "1. Edit ethereum-contracts/.env with your private key"
echo "2. Get Sepolia ETH from https://sepoliafaucet.com/"
echo "3. Run: ./quick-start.sh to see the demo steps"
echo "4. Or run: node demo.js for automated demo"

echo ""
echo "📁 Project Structure:"
echo "├── ethereum-contracts/     # ERC-20 token deployment"
echo "├── solana-contracts/       # SPL token deployment"
echo "├── scripts/               # Transaction and monitoring scripts"
echo "├── config/                # Network and deployment configs"
echo "├── logs/                  # Demo logs and events"
echo "└── screenshots/           # For demo recording"

echo ""
echo "🔗 Important URLs:"
echo "- Sepolia Faucet: https://sepoliafaucet.com/"
echo "- Sepolia Explorer: https://sepolia.etherscan.io/"
echo "- Solana Explorer: https://explorer.solana.com/?cluster=devnet"
echo "- Bridge Dashboard: http://localhost:8084 (when running)"

echo ""
print_info "Ready for end-to-end testnet demonstration! 🚀"
