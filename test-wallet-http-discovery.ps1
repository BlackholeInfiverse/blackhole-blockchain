# Test script for enhanced wallet with HTTP discovery
param(
    [switch]$BuildOnly = $false,
    [switch]$RunOnly = $false,
    [string]$NodePort = "8080"
)

Write-Host "Enhanced Wallet HTTP Discovery Test" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Set paths
$ProjectRoot = "C:\Users\pc2\Desktop\Qoder\blackhole-blockchain"
$WalletPath = "$ProjectRoot\core\relay-chain\cmd\enhanced-wallet"

# Check if we're in the right directory
if (!(Test-Path $ProjectRoot)) {
    Write-Host "ERROR: Project directory not found at $ProjectRoot" -ForegroundColor Red
    exit 1
}

Set-Location $ProjectRoot

if (!$RunOnly) {
    Write-Host "`nStep 1: Building enhanced wallet..." -ForegroundColor Yellow
    
    # Clean any existing binary
    $BinaryPath = "$WalletPath\enhanced-wallet.exe"
    if (Test-Path $BinaryPath) {
        Remove-Item $BinaryPath -Force
        Write-Host "Removed existing binary" -ForegroundColor Gray
    }
    
    # Build the wallet
    Write-Host "Building: go build -o $BinaryPath $WalletPath\main.go" -ForegroundColor Gray
    $BuildResult = & go build -o $BinaryPath "$WalletPath\main.go" 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BUILD FAILED:" -ForegroundColor Red
        Write-Host $BuildResult -ForegroundColor Red
        exit 1
    } else {
        Write-Host "Build successful!" -ForegroundColor Green
    }
    
    if ($BuildOnly) {
        Write-Host "`nBuild complete. Use -RunOnly to test the wallet." -ForegroundColor Cyan
        exit 0
    }
}

if (!$BuildOnly) {
    Write-Host "`nStep 2: Testing HTTP Discovery..." -ForegroundColor Yellow
    
    # Test if blockchain node API is reachable
    Write-Host "Testing blockchain node API at localhost:$NodePort..." -ForegroundColor Gray
    
    try {
        $Response = Invoke-WebRequest -Uri "http://localhost:$NodePort/api/node/info" -TimeoutSec 5 -ErrorAction Stop
        Write-Host "API Response Status: $($Response.StatusCode)" -ForegroundColor Green
        Write-Host "Content Type: $($Response.Headers.'Content-Type')" -ForegroundColor Gray
        
        # Try to parse JSON
        try {
            $NodeInfo = $Response.Content | ConvertFrom-Json
            Write-Host "Node Name: $($NodeInfo.name)" -ForegroundColor Green
            Write-Host "Network ID: $($NodeInfo.network_id)" -ForegroundColor Green
            Write-Host "Secure P2P Peer ID: $($NodeInfo.secure_p2p_peer_id)" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not parse API response as JSON" -ForegroundColor Yellow
            Write-Host "Raw response: $($Response.Content)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Warning: Could not reach blockchain node API at localhost:$NodePort" -ForegroundColor Yellow
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Make sure the blockchain node is running with HTTP API enabled" -ForegroundColor Yellow
    }
    
    Write-Host "`nStep 3: Running Enhanced Wallet..." -ForegroundColor Yellow
    Write-Host "The wallet will now start and attempt HTTP discovery first" -ForegroundColor Gray
    Write-Host "If HTTP discovery fails, it will fallback to UDP discovery" -ForegroundColor Gray
    Write-Host ""
    Write-Host "TIP: Use option '1' to discover networks, then option '2' to connect" -ForegroundColor Cyan
    Write-Host "     Use option '4' to refresh network list if discovery is slow" -ForegroundColor Cyan
    Write-Host ""
    
    # Run the wallet
    & "$WalletPath\enhanced-wallet.exe"
}

Write-Host "`nTest completed." -ForegroundColor Cyan