$content = Get-Content 'main.go'
$newContent = @()
$skipLines = $false

for ($i = 0; $i -lt $content.Length; $i++) {
    # Start skipping at line 1817 (0-based index 1816)
    if ($i -eq 1816) {
        $skipLines = $true
    }
    # Stop skipping at line 1846 (0-based index 1845)
    elseif ($i -eq 1845) {
        $skipLines = $false
        continue
    }
    
    if (-not $skipLines) {
        $newContent += $content[$i]
    }
}

$newContent | Set-Content 'main_fixed.go'
Write-Host "Fixed file created as main_fixed.go"