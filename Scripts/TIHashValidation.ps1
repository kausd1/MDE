# ===================================================================
# Microsoft Defender for Endpoint - Bulk File Hash Validation
# This script reads file hashes from an Excel file and validates them
# against the MDE Files API, exporting determination results
# 
# IMPORTANT - Input File Requirements:
# 1. File must be in .xlsx format (Excel file)
# 2. Column containing hashes MUST be named "Indicator Value"
# 3. If your input file is sourced from another system/tool, 
#    rename the hash column to "Indicator Value" before running this script
# Retrieves a File by identifier Sha1, or Sha256
#
# Prerequisites:
# * Microsoft Entra ID App Registration with API permissions
#   Follow Step 1 for tenantId, appId, appSecret:
#   https://learn.microsoft.com/en-us/defender-endpoint/api/api-hello-world
# * File.Read.All (Application) permission for this validation script
# * PowerShell with ImportExcel module (will auto-install if missing)
# * Network access to Microsoft Defender for Endpoint API
#
# Usage:
# .\Script.ps1 -InputPath "C:\Temp\Hashes.xlsx" -OutputPath "C:\Temp\Results.xlsx"
# ===================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$InputPath = "C:\Temp\FileHashes.xlsx",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Temp\HashValidationResults.xlsx"
)

# Check if ImportExcel module is installed, install if not
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "Installing ImportExcel module..." -ForegroundColor Yellow
    Install-Module -Name ImportExcel -Scope CurrentUser -Force
}

Import-Module ImportExcel

# ===== CONFIGURATION =====
$tenantId = ""  # Replace with your tenant ID
$appId = ""       # Replace with your app ID
$appSecret = ""   # Replace with your app secret

# Use parameters for file paths
$inputExcelPath = $InputPath
$outputExcelPath = $OutputPath

# ===== STEP 1: Acquire OAuth Token =====
Write-Host "Acquiring OAuth token..." -ForegroundColor Cyan

$tokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    client_id     = $appId
    scope         = "https://api.securitycenter.microsoft.com/.default"
    client_secret = $appSecret
    grant_type    = "client_credentials"
}

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    $token = $tokenResponse.access_token
    Write-Host "Token acquired successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to acquire token: $($_.Exception.Message)"
    exit
}

# ===== STEP 2: Read Hashes from Excel =====
# IMPORTANT: Your Excel file MUST have a column named "Indicator Value" containing the file hashes
# Example Excel structure:
# | Indicator Value                                                   |
# |-------------------------------------------------------------------|
# | 97bf5e1a903a978b2281496e0a897688e9d8e6f981238cf91e39bae20390defe |
# | abc123def456...                                                   |

Write-Host "Reading hashes from Excel file: $inputExcelPath" -ForegroundColor Cyan

if (-not (Test-Path $inputExcelPath)) {
    Write-Error "Input file not found: $inputExcelPath"
    exit
}

try {
    $hashData = Import-Excel -Path $inputExcelPath
    Write-Host "Found $($hashData.Count) hash(es) to process." -ForegroundColor Green
} catch {
    Write-Error "Failed to read Excel file: $($_.Exception.Message)"
    exit
}

# ===== STEP 3: Process Each Hash =====
$results = @()
$counter = 0

foreach ($row in $hashData) {
    $counter++
    # Read hash from "Indicator Value" column
    # NOTE: The Excel column name MUST be exactly "Indicator Value" (case-sensitive with space)
    $hash = $row.'Indicator Value'
    
    if ([string]::IsNullOrWhiteSpace($hash)) {
        Write-Host "[$counter/$($hashData.Count)] Skipping empty hash" -ForegroundColor Gray
        continue
    }
    
    # Trim whitespace from hash
    $hash = $hash.Trim()
    
    Write-Host "[$counter/$($hashData.Count)] Processing hash: $hash" -ForegroundColor Cyan
    
    $uri = "https://api.securitycenter.microsoft.com/api/v1.0/files/$hash"
    
    # Initialize result object
    $result = [PSCustomObject]@{
        IndicatorValue          = $hash
        sha1                    = "Unknown"
        sha256                  = "Unknown"
        md5                     = "Unknown"
        globalPrevalence        = "Unknown"
        globalFirstObserved     = "Unknown"
        globalLastObserved      = "Unknown"
        size                    = "Unknown"
        fileType                = "Unknown"
        isPeFile                = "Unknown"
        filePublisher           = "Unknown"
        fileProductName         = "Unknown"
        signer                  = "Unknown"
        issuer                  = "Unknown"
        signerHash              = "Unknown"
        isValidCertificate      = "Unknown"
        determinationType       = "Unknown"
        determinationValue      = "Unknown"
        ResponseStatus          = ""
    }
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers @{
            Authorization = "Bearer $token"
            Accept        = "application/json"
        } -Method Get
        
        # Extract all fields from response
        if ($response.sha1) { $result.sha1 = $response.sha1 }
        if ($response.sha256) { $result.sha256 = $response.sha256 }
        if ($response.md5) { $result.md5 = $response.md5 }
        if ($response.globalPrevalence) { $result.globalPrevalence = $response.globalPrevalence }
        if ($response.globalFirstObserved) { $result.globalFirstObserved = $response.globalFirstObserved }
        if ($response.globalLastObserved) { $result.globalLastObserved = $response.globalLastObserved }
        if ($response.size) { $result.size = $response.size }
        if ($response.fileType) { $result.fileType = $response.fileType }
        if ($null -ne $response.isPeFile) { $result.isPeFile = $response.isPeFile }
        if ($response.filePublisher) { $result.filePublisher = $response.filePublisher }
        if ($response.fileProductName) { $result.fileProductName = $response.fileProductName }
        if ($response.signer) { $result.signer = $response.signer }
        if ($response.issuer) { $result.issuer = $response.issuer }
        if ($response.signerHash) { $result.signerHash = $response.signerHash }
        if ($null -ne $response.isValidCertificate) { $result.isValidCertificate = $response.isValidCertificate }
        if ($response.determinationType) { $result.determinationType = $response.determinationType }
        if ($response.determinationValue) { $result.determinationValue = $response.determinationValue }
        
        $result.ResponseStatus = "Success"
        
        # Color-coded console output
        switch ($result.determinationType) {
            "Malware"  { Write-Host "  Result: MALICIOUS - $($result.determinationType)" -ForegroundColor Red }
            "Suspicious" { Write-Host "  Result: SUSPICIOUS - $($result.determinationType)" -ForegroundColor Yellow }
            "Clean"      { Write-Host "  Result: CLEAN" -ForegroundColor Green }
            default      { Write-Host "  Result: UNKNOWN (No determination)" -ForegroundColor Gray }
        }
        
    } catch {
        $result.ResponseStatus = "Error: $($_.Exception.Message)"
        Write-Host "  Error processing hash: $($_.Exception.Message)" -ForegroundColor Red
        
        # Check for 404 (hash not found)
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Host "  Result: UNKNOWN (Hash not in MDE database)" -ForegroundColor Gray
        }
    }
    
    $results += $result
    
    # Rate limiting - small delay between requests
    Start-Sleep -Milliseconds 500
}

# ===== STEP 4: Export Results to Excel =====
Write-Host "`nExporting results to: $outputExcelPath" -ForegroundColor Cyan

try {
    $results | Export-Excel -Path $outputExcelPath -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -WorksheetName "Hash Validation Results"
    Write-Host "Export completed successfully!" -ForegroundColor Green
    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total processed: $($results.Count)" -ForegroundColor White
    Write-Host "  Malicious: $(($results | Where-Object {$_.determinationType -eq 'Malicious'}).Count)" -ForegroundColor Red
    Write-Host "  Suspicious: $(($results | Where-Object {$_.determinationType -eq 'Suspicious'}).Count)" -ForegroundColor Yellow
    Write-Host "  Clean: $(($results | Where-Object {$_.determinationType -eq 'Clean'}).Count)" -ForegroundColor Green
    Write-Host "  Unknown: $(($results | Where-Object {$_.determinationType -eq 'Unknown'}).Count)" -ForegroundColor Gray
} catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

Write-Host "`nScript completed." -ForegroundColor Cyan

