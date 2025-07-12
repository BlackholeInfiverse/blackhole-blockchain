# Test script for manual transfer API
$headers = @{
    "Content-Type" = "application/json"
}

$body = @{
    route = "ETH_TO_BH"
    amount = 1.5
    sourceAddress = "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b1"
    destAddress = "0x8ba1f109551bD432803012645Hac136c22C177e9"
    gasFee = 0.001
    confirmations = 12
    timeout = 300
    priority = "medium"
} | ConvertTo-Json

Write-Host "Testing manual transfer API..."
Write-Host "Request body: $body"

try {
    $response = Invoke-WebRequest -Uri "http://localhost:8084/api/manual-transfer" -Method POST -Body $body -Headers $headers
    Write-Host "Response Status: $($response.StatusCode)"
    Write-Host "Response Content: $($response.Content)"
    
    # Parse the response to get transaction ID
    $responseData = $response.Content | ConvertFrom-Json
    if ($responseData.success -and $responseData.data.transaction_id) {
        $txId = $responseData.data.transaction_id
        Write-Host "Transaction ID: $txId"
        
        # Test status endpoint
        Write-Host "`nTesting transfer status API..."
        Start-Sleep -Seconds 2
        
        $statusResponse = Invoke-WebRequest -Uri "http://localhost:8084/api/transfer-status/$txId" -Method GET
        Write-Host "Status Response: $($statusResponse.Content)"
    }
} catch {
    Write-Host "Error: $($_.Exception.Message)"
    Write-Host "Response: $($_.Exception.Response)"
}
