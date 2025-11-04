#!/bin/bash

# 🚀 BHX Token Quick Deployment Script
# This script automates the entire deployment and listing process

set -e  # Exit on any error

echo "🌌 BlackHole (BHX) Token - Quick Deployment to Exchanges"
echo "========================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "contracts/BHX_ERC20.sol" ]; then
    print_error "BHX_ERC20.sol not found. Make sure you're in the project root directory."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    print_error "npm is not installed. Please install npm first."
    exit 1
fi

print_status "Setting up deployment environment..."

# Navigate to contracts directory
cd contracts

# Check if .env file exists
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Creating from template..."
    cp .env.example .env
    print_warning "Please edit contracts/.env with your private key and RPC URLs before continuing."
    read -p "Press Enter after updating .env file..."
fi

# Install dependencies
print_status "Installing dependencies..."
npm install

# Compile contracts
print_status "Compiling contracts..."
npm run compile

# Ask user which network to deploy to
echo ""
print_status "Select deployment network:"
echo "1) Sepolia Testnet (Recommended for testing)"
echo "2) Ethereum Mainnet (Production)"
echo "3) BSC Mainnet (Multi-chain)"
echo "4) Polygon Mainnet (Multi-chain)"

read -p "Enter your choice (1-4): " network_choice

case $network_choice in
    1)
        NETWORK="sepolia"
        print_status "Deploying to Sepolia testnet..."
        ;;
    2)
        NETWORK="mainnet"
        print_warning "Deploying to Ethereum mainnet. This will cost real ETH!"
        read -p "Are you sure? (y/N): " confirm
        if [[ $confirm != [yY] ]]; then
            print_error "Deployment cancelled."
            exit 1
        fi
        ;;
    3)
        NETWORK="bsc"
        print_status "Deploying to BSC mainnet..."
        ;;
    4)
        NETWORK="polygon"
        print_status "Deploying to Polygon mainnet..."
        ;;
    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
esac

# Deploy contract
print_status "Deploying BHX token contract to $NETWORK..."
DEPLOY_OUTPUT=$(npm run deploy:$NETWORK 2>&1)
DEPLOY_STATUS=$?

if [ $DEPLOY_STATUS -eq 0 ]; then
    print_success "Contract deployed successfully!"
    
    # Extract contract address from output
    CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep -o "0x[a-fA-F0-9]\{40\}" | head -1)
    
    if [ -n "$CONTRACT_ADDRESS" ]; then
        print_success "Contract Address: $CONTRACT_ADDRESS"
        
        # Ask if user wants to verify contract
        read -p "Do you want to verify the contract on block explorer? (y/N): " verify_choice
        if [[ $verify_choice == [yY] ]]; then
            print_status "Verifying contract..."
            npm run verify:$NETWORK $CONTRACT_ADDRESS "10000000000000000000000000"
        fi
        
        # Generate exchange submission data
        print_status "Generating exchange submission data..."
        
        # Create quick submission template
        cat > ../exchange_submission.txt << EOF
🚀 BHX Token Exchange Listing Application

BASIC INFORMATION:
- Token Name: BlackHole
- Symbol: BHX
- Contract Address: $CONTRACT_ADDRESS
- Network: $NETWORK
- Decimals: 18
- Total Supply: 1,000,000,000 BHX
- Initial Circulating: 10,000,000 BHX

LINKS:
- Website: https://blackhole-blockchain.com
- Whitepaper: https://blackhole-blockchain.com/whitepaper.pdf
- Twitter: https://twitter.com/BlackHoleChain
- Telegram: https://t.me/BlackHoleChain
- GitHub: https://github.com/BlackHoleChain/blackhole-blockchain

CONTRACT VERIFICATION:
- Etherscan: https://etherscan.io/address/$CONTRACT_ADDRESS
- Source Code: Verified
- Security: OpenZeppelin standard

NEXT STEPS:
1. Add liquidity to Uniswap
2. Submit to CoinGecko
3. Submit to CoinMarketCap
4. Apply to exchanges

EOF
        
        print_success "Exchange submission data saved to exchange_submission.txt"
        
        # Next steps
        echo ""
        print_status "🎉 Deployment Complete! Next Steps:"
        echo ""
        echo "1. 💧 Add Liquidity to Uniswap:"
        echo "   - Go to https://app.uniswap.org/#/add/v2"
        echo "   - Add BHX/ETH and BHX/USDC pairs"
        echo "   - Recommended: $5,000+ initial liquidity"
        echo ""
        echo "2. 📊 Submit to Data Aggregators:"
        echo "   - CoinGecko: https://www.coingecko.com/en/coins/new"
        echo "   - CoinMarketCap: https://support.coinmarketcap.com/hc/en-us/requests/new"
        echo ""
        echo "3. 🏛️ Apply to Exchanges:"
        echo "   - MEXC: https://www.mexc.com/support/articles/17002695435673"
        echo "   - Gate.io: https://www.gate.io/listing_application"
        echo "   - BitMart: https://support.bitmart.com/hc/en-us/articles/360040624234"
        echo ""
        echo "4. 📋 Use the data in exchange_submission.txt for applications"
        echo ""
        print_success "Contract Address: $CONTRACT_ADDRESS"
        
    else
        print_error "Could not extract contract address from deployment output."
        exit 1
    fi
else
    print_error "Contract deployment failed!"
    echo "$DEPLOY_OUTPUT"
    exit 1
fi

echo ""
print_success "🚀 BHX Token is ready for exchange listings!"
echo "📋 Follow the steps in EXCHANGE_LISTING_GUIDE.md for detailed instructions."