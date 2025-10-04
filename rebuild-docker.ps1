# Script to rebuild Docker images with updated Go version
param(
    [switch]$CleanBuild = $false,
    [switch]$NoCache = $false
)

Write-Host "Docker Rebuild Script - BlackHole Blockchain" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# Set project root
$ProjectRoot = "C:\Users\pc2\Desktop\Qoder\blackhole-blockchain"

if (!(Test-Path $ProjectRoot)) {
    Write-Host "ERROR: Project directory not found at $ProjectRoot" -ForegroundColor Red
    exit 1
}

Set-Location $ProjectRoot

# Check if docker-compose.yml exists
if (!(Test-Path "docker-compose.yml")) {
    Write-Host "ERROR: docker-compose.yml not found in project root" -ForegroundColor Red
    exit 1
}

if ($CleanBuild) {
    Write-Host "`nStep 1: Cleaning up existing containers and images..." -ForegroundColor Yellow
    
    # Stop and remove containers
    Write-Host "Stopping containers..." -ForegroundColor Gray
    & docker-compose down --remove-orphans
    
    # Remove existing images
    Write-Host "Removing existing blackhole-blockchain images..." -ForegroundColor Gray
    $Images = & docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -like "*blackhole-blockchain*" }
    if ($Images) {
        foreach ($Image in $Images) {
            Write-Host "Removing image: $Image" -ForegroundColor Gray
            & docker rmi $Image --force
        }
    }
    
    # Clean up build cache
    Write-Host "Cleaning Docker build cache..." -ForegroundColor Gray
    & docker builder prune -f
}

Write-Host "`nStep 2: Building Docker images..." -ForegroundColor Yellow

# Build arguments
$BuildArgs = @()
if ($NoCache) {
    $BuildArgs += "--no-cache"
}

# Build the images
Write-Host "Running: docker-compose build $($BuildArgs -join ' ')" -ForegroundColor Gray
$BuildResult = & docker-compose build @BuildArgs 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "BUILD FAILED:" -ForegroundColor Red
    Write-Host $BuildResult -ForegroundColor Red
    
    # Show more details
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Check if Dockerfile uses the correct Go version (>=1.24.2)" -ForegroundColor Gray
    Write-Host "2. Verify go.mod and go.sum are correct" -ForegroundColor Gray
    Write-Host "3. Try running with -CleanBuild to remove cached layers" -ForegroundColor Gray
    Write-Host "4. Check internet connection for downloading dependencies" -ForegroundColor Gray
    
    exit 1
} else {
    Write-Host "Build successful!" -ForegroundColor Green
}

Write-Host "`nStep 3: Verifying built images..." -ForegroundColor Yellow
$Images = & docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}" | Where-Object { $_ -like "*blackhole-blockchain*" -or $_ -like "*REPOSITORY*" }
Write-Host $Images -ForegroundColor Green

Write-Host "`nStep 4: Testing image startup..." -ForegroundColor Yellow
Write-Host "Starting containers in detached mode for quick test..." -ForegroundColor Gray

& docker-compose up -d

Start-Sleep -Seconds 5

# Check container status
$Containers = & docker-compose ps
Write-Host "`nContainer Status:" -ForegroundColor Green
Write-Host $Containers

# Check if any containers failed
$FailedContainers = & docker-compose ps --filter "status=exited"
if ($FailedContainers -and $FailedContainers.Count -gt 1) {
    Write-Host "`nWARNING: Some containers exited. Check logs:" -ForegroundColor Yellow
    & docker-compose logs --tail=20
} else {
    Write-Host "`nAll containers appear to be running successfully!" -ForegroundColor Green
    
    # Test API endpoint
    Write-Host "`nTesting blockchain node API..." -ForegroundColor Gray
    Start-Sleep -Seconds 3
    
    try {
        $Response = Invoke-WebRequest -Uri "http://localhost:8080/api/node/info" -TimeoutSec 10 -ErrorAction Stop
        Write-Host "API Test: SUCCESS - Status $($Response.StatusCode)" -ForegroundColor Green
        
        # Parse response
        try {
            $NodeInfo = $Response.Content | ConvertFrom-Json
            Write-Host "Node: $($NodeInfo.name) (Network: $($NodeInfo.network_id))" -ForegroundColor Green
        } catch {
            Write-Host "API responded but JSON parsing failed" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "API Test: FAILED - $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Node may still be initializing. Check logs with: docker-compose logs" -ForegroundColor Gray
    }
}

Write-Host "`nDocker rebuild completed!" -ForegroundColor Cyan
Write-Host "Use 'docker-compose logs' to view container logs" -ForegroundColor Gray
Write-Host "Use 'docker-compose down' to stop containers" -ForegroundColor Gray