# ===================================================================
# Microsoft Defender for Endpoint - Bulk Indicator Deletion
# This script reads hashes from HashValidationResults.xlsx and deletes
# the corresponding indicators from the MDE portal
#
# IMPORTANT - Input File Requirements:
# 1. File must be in .xlsx format (Excel file)
# 2. File must contain columns named "sha256" and/or "sha1" with hash values
# 3. If your input file is sourced from another system/tool,
#    rename the hash columns to "sha256" or "sha1" before running this script
# 4. You will be prompted to select which column to use (sha256 or sha1)
#
# Usage:
# .\Script.ps1 -InputPath "C:\Temp\HashValidationResults.xlsx" -OutputPath "C:\Temp\DeletionResults.xlsx"
# ===================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$InputPath = "C:\Temp\HashValidationResults.xlsx",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\Temp\IndicatorDeletionResults.xlsx"
)

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "Installing ImportExcel module..."
    Install-Module -Name ImportExcel -Scope CurrentUser -Force
}
Import-Module ImportExcel

# ===== CONFIGURATION =====
$tenantId = ""  # Replace with your tenant ID
$appId = ""       # Replace with your app ID
$appSecret = ""   # Replace with your app secret

# File paths
# Use parameters for file paths
$inputExcelPath = $InputPath
$outputExcelPath = $OutputPath

# ===== STEP 1: Acquire OAuth Token =====
Write-Host "Acquiring OAuth token..."

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
    Write-Host "Token acquired successfully."
} catch {
    Write-Error "Failed to acquire token: $($_.Exception.Message)"
    exit
}

# ===== STEP 2: Read Hashes from Excel =====
Write-Host "Reading hashes from Excel file: $inputExcelPath"

if (-not (Test-Path $inputExcelPath)) {
    Write-Error "Input file not found: $inputExcelPath"
    exit
}

try {
    $hashData = Import-Excel -Path $inputExcelPath
    Write-Host "Found $($hashData.Count) record(s) in the file."
} catch {
    Write-Error "Failed to read Excel file: $($_.Exception.Message)"
    exit
}

# ===== STEP 3: Prompt User to Select Column =====
Write-Host "Select hash type to use for deletion:"
Write-Host "Column name should either be sha256 or sha1"
Write-Host "  1. sha256"
Write-Host "  2. sha1"
Write-Host "Enter your choice (1 or 2): " -NoNewline
$choice = Read-Host

switch ($choice) {
    "1" { $selectedColumn = "sha256" }
    "2" { $selectedColumn = "sha1" }
    default {
        Write-Error "Invalid choice. Please enter 1 or 2."
        exit
    }
}

Write-Host "Using column: $selectedColumn"

# ===== STEP 4: Process Each Hash and Delete Indicators =====
$results = @()
$counter = 0

Write-Host "Starting indicator deletion process..."

foreach ($row in $hashData) {
    $counter++
    $hash = $row.$selectedColumn
    
    if ([string]::IsNullOrWhiteSpace($hash) -or $hash -eq "Unknown") {
        Write-Host "[$counter/$($hashData.Count)] Skipping empty or unknown hash"
        continue
    }
    
    $hash = $hash.Trim()
    
    Write-Host "[$counter/$($hashData.Count)] Processing hash: $hash"
    
    $result = [PSCustomObject]@{
        Hash               = $hash
        IndicatorID        = ""
        IndicatorType      = ""
        Action             = ""
        ResponseMessage    = ""
    }
    
    try {
        # Get Indicator ID by searching for the hash
        $listUri = "https://api.securitycenter.microsoft.com/api/indicators?`$filter=indicatorValue eq '$hash'"
        
        $listResponse = Invoke-RestMethod -Uri $listUri -Headers @{
            Authorization = "Bearer $token"
            Accept        = "application/json"
        } -Method Get
        
        if ($listResponse.value -and $listResponse.value.Count -gt 0) {
            $indicator = $listResponse.value[0]
            $indicatorId = $indicator.id
            $result.IndicatorID = $indicatorId
            $result.IndicatorType = $indicator.indicatorType
            $result.Action = $indicator.action
            
            Write-Host "  Found Indicator ID: $indicatorId (Type: $($indicator.indicatorType), Action: $($indicator.action))"
            
            # Delete the Indicator by ID
            $deleteUri = "https://api.securitycenter.microsoft.com/api/indicators/$indicatorId"
            
            try {
                Invoke-RestMethod -Uri $deleteUri -Headers @{
                    Authorization = "Bearer $token"
                    Accept        = "application/json"
                } -Method Delete -ErrorAction Stop
                
                $result.ResponseMessage = "204 OK without content"
                Write-Host "  Result: 204 OK without content"
                
            } catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 204) {
                    $result.ResponseMessage = "204 OK without content"
                    Write-Host "  Result: 204 OK without content"
                } else {
                    $result.ResponseMessage = "Error: $($_.Exception.Message)"
                    Write-Host "  Result: Error - $($_.Exception.Message)"
                }
            }
            
        } else {
            $result.ResponseMessage = "404 Not Found"
            Write-Host "  Result: 404 Not Found"
        }
        
    } catch {
        $result.ResponseMessage = "Error: $($_.Exception.Message)"
        Write-Host "  Error: $($_.Exception.Message)"
    }
    
    $results += $result
    
    Start-Sleep -Milliseconds 700
}

# ===== STEP 5: Export Results to Excel =====
Write-Host "Exporting results to: $outputExcelPath"

try {
    $results | Export-Excel -Path $outputExcelPath -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter -WorksheetName "Deletion Results"
    Write-Host "Export completed successfully!"
    
    Write-Host "Summary:"
    Write-Host "  Total processed: $($results.Count)"
    Write-Host "  204 OK (Deleted): $(@($results | Where-Object {$_.ResponseMessage -eq '204 OK without content'}).Count)"
    Write-Host "  404 Not Found: $(@($results | Where-Object {$_.ResponseMessage -eq '404 Not Found'}).Count)"
    Write-Host "  Errors: $(@($results | Where-Object {$_.ResponseMessage -like 'Error:*'}).Count)"
    
} catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

Write-Host "Script completed."

