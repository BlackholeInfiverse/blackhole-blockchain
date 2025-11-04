# Wallet Service Integration Test Script
# Tests all major functionalities of the Blackhole Wallet Service

Write-Host "🧪 Blackhole Wallet Service Integration Tests" -ForegroundColor Cyan
Write-Host "=" * 60

$baseUrl = "http://localhost:9000"
$testUsername = "testuser_$(Get-Date -Format 'yyyyMMddHHmmss')"
$testPassword = "TestPassword123!"
$sessionCookie = $null

# Function to make HTTP requests
function Invoke-WalletAPI {
    param(
        [string]$Method = "GET",
        [string]$Endpoint,
        [object]$Body = $null,
        [string]$Cookie = $null
    )
    
    $uri = "$baseUrl$Endpoint"
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    if ($Cookie) {
        $headers["Cookie"] = $Cookie
    }
    
    try {
        if ($Body) {
            $jsonBody = $Body | ConvertTo-Json
            $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $jsonBody -ErrorAction Stop
        } else {
            $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -ErrorAction Stop
        }
        return $response
    } catch {
        Write-Host "❌ Request failed: $_" -ForegroundColor Red
        return $null
    }
}

# Test 1: Service Status
Write-Host "`n📊 Test 1: Service Status Check" -ForegroundColor Yellow
$status = Invoke-WalletAPI -Method GET -Endpoint "/api/status"
if ($status -and $status.success) {
    Write-Host "✅ Service is running" -ForegroundColor Green
    Write-Host "   Version: $($status.data.version)"
    Write-Host "   Storage System:"
    Write-Host "     - PostgreSQL: $($status.data.storage_system.postgresql_available)"
    Write-Host "     - Redis: $($status.data.storage_system.redis_available)"
    Write-Host "     - BadgerDB: $($status.data.storage_system.badgerdb_available)"
} else {
    Write-Host "❌ Service status check failed" -ForegroundColor Red
    exit 1
}

# Test 2: User Registration
Write-Host "`n👤 Test 2: User Registration" -ForegroundColor Yellow
$registerBody = @{
    username = $testUsername
    password = $testPassword
}
$registerResponse = Invoke-WalletAPI -Method POST -Endpoint "/api/register" -Body $registerBody
if ($registerResponse -and $registerResponse.success) {
    Write-Host "✅ User registered successfully: $testUsername" -ForegroundColor Green
} else {
    Write-Host "❌ User registration failed" -ForegroundColor Red
}

# Test 3: User Login
Write-Host "`n🔐 Test 3: User Login" -ForegroundColor Yellow
$loginBody = @{
    username = $testUsername
    password = $testPassword
}
try {
    $loginUri = "$baseUrl/api/login"
    $jsonBody = $loginBody | ConvertTo-Json
    $response = Invoke-WebRequest -Uri $loginUri -Method POST -Body $jsonBody -ContentType "application/json" -SessionVariable session
    $loginResponse = $response.Content | ConvertFrom-Json
    
    if ($loginResponse.success) {
        Write-Host "✅ User logged in successfully" -ForegroundColor Green
        # Extract session cookie
        $sessionCookie = $session.Cookies.GetCookies($baseUrl) | Where-Object { $_.Name -eq "session_id" } | Select-Object -First 1
        if ($sessionCookie) {
            $sessionCookie = "session_id=$($sessionCookie.Value)"
            Write-Host "   Session: $sessionCookie" -ForegroundColor Gray
        }
    } else {
        Write-Host "❌ User login failed" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Login request failed: $_" -ForegroundColor Red
}

# Test 4: Get User Info
if ($sessionCookie) {
    Write-Host "`n👤 Test 4: Get User Information" -ForegroundColor Yellow
    $userInfo = Invoke-WalletAPI -Method GET -Endpoint "/api/user" -Cookie $sessionCookie
    if ($userInfo -and $userInfo.success) {
        Write-Host "✅ User information retrieved" -ForegroundColor Green
        Write-Host "   Username: $($userInfo.data.username)"
        Write-Host "   User ID: $($userInfo.data.id)"
    } else {
        Write-Host "❌ Failed to get user information" -ForegroundColor Red
    }
}

# Test 5: Create Wallet
if ($sessionCookie) {
    Write-Host "`n💼 Test 5: Create Wallet" -ForegroundColor Yellow
    $walletBody = @{
        wallet_name = "TestWallet_$(Get-Date -Format 'HHmmss')"
        password = $testPassword
    }
    $walletResponse = Invoke-WalletAPI -Method POST -Endpoint "/api/wallets/create" -Body $walletBody -Cookie $sessionCookie
    if ($walletResponse -and $walletResponse.success) {
        Write-Host "✅ Wallet created successfully" -ForegroundColor Green
        Write-Host "   Wallet: $($walletResponse.data.name)"
        Write-Host "   Address: $($walletResponse.data.address)"
    } else {
        Write-Host "❌ Wallet creation failed" -ForegroundColor Red
    }
}

# Test 6: List Wallets
if ($sessionCookie) {
    Write-Host "`n📋 Test 6: List User Wallets" -ForegroundColor Yellow
    $wallets = Invoke-WalletAPI -Method GET -Endpoint "/api/wallets" -Cookie $sessionCookie
    if ($wallets -and $wallets.success) {
        $walletCount = $wallets.data.Count
        Write-Host "✅ Retrieved $walletCount wallet(s)" -ForegroundColor Green
        foreach ($wallet in $wallets.data) {
            Write-Host "   - $($wallet.name): $($wallet.address)"
        }
    } else {
        Write-Host "❌ Failed to list wallets" -ForegroundColor Red
    }
}

# Test 7: Logout
if ($sessionCookie) {
    Write-Host "`n🚪 Test 7: User Logout" -ForegroundColor Yellow
    $logoutResponse = Invoke-WalletAPI -Method POST -Endpoint "/api/logout" -Cookie $sessionCookie
    if ($logoutResponse -and $logoutResponse.success) {
        Write-Host "✅ User logged out successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Logout failed" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n" + ("=" * 60)
Write-Host "🎉 Test Suite Complete!" -ForegroundColor Cyan
Write-Host "`n📝 Note: For full testing including balance checks and transactions," -ForegroundColor Yellow
Write-Host "   ensure blockchain nodes are running and properly configured." -ForegroundColor Yellow
Write-Host "`nTest user created: $testUsername" -ForegroundColor Gray
