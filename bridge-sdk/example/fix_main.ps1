# PowerShell script to fix orphaned code in main.go
$filePath = "c:\Users\pc121\Desktop\MyProjects\GoProjects\blackhole-blockchain\bridge-sdk\example\main.go"
$content = Get-Content $filePath
$newContent = @()
$skipStartLine = 1815  # Line where orphaned code starts (1-based indexing)
$skipEndLine = 1847    # Line where orphaned code ends (1-based indexing)

for ($i = 0; $i -lt $content.Length; $i++) {
    $lineNumber = $i + 1  # Convert to 1-based indexing
    
    # Skip the orphaned code section
    if ($lineNumber -ge $skipStartLine -and $lineNumber -le $skipEndLine) {
        continue
    }
    
    $newContent += $content[$i]
}

# Create backup
Copy-Item $filePath ($filePath + ".backup")

# Write the fixed content
$newContent | Set-Content $filePath

Write-Host "Fixed main.go by removing orphaned code from lines $skipStartLine to $skipEndLine"
Write-Host "Backup created as main.go.backup"