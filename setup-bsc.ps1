Write-Host "🌌 BHX Token Deployment - BSC Setup" -ForegroundColor Green
Write-Host "======================================="

# Navigate to contracts directory
Set-Location "C:\Users\pc2\Desktop\Qoder\blackhole-blockchain\contracts"

# Check if we're in the right directory
if (!(Test-Path "package.json")) {
    Write-Host "❌ Error: package.json not found!" -ForegroundColor Red
    Write-Host "Make sure you're in the contracts directory" -ForegroundColor Yellow
    exit 1
}

Write-Host "📍 Current directory: $(Get-Location)" -ForegroundColor Cyan

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
npm install

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to install dependencies!" -ForegroundColor Red
    exit 1
}

# Compile contracts
Write-Host "🔨 Compiling contracts..." -ForegroundColor Yellow
npx hardhat compile

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to compile contracts!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 Next steps:" -ForegroundColor Cyan
Write-Host "1. Edit .env file with your private key" -ForegroundColor White
Write-Host "2. Add some BNB to your wallet for gas" -ForegroundColor White  
Write-Host "3. Run: npx hardhat run deploy-bhx.js --network bsc" -ForegroundColor White
Write-Host ""
Write-Host "💰 Your wallet: 0xe5C146a2FCD084481860..." -ForegroundColor Yellow