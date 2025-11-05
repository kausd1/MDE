# Requires the ImportExcel module
# Install it if needed: Install-Module ImportExcel -Force

# Path to your Excel file
$excelPath = "path.xlsx"

# Entra (Azure AD) App Registration details
$tenantId = ""
$clientId = ""
$clientSecret = ""

# Tag you want to assign
$tagName = "Whatsup"
$action="Add"

# Defender for Endpoint API base URL
$baseUrl = "https://api.securitycenter.microsoft.com/api/machines"

# --- AUTHENTICATION SECTION ---

Write-Host "Fetching access token from Microsoft Entra ID..." -ForegroundColor Yellow

$body = @{
    grant_type    = "client_credentials"
    scope         = "https://api.securitycenter.microsoft.com/.default"
    client_id     = $clientId
    client_secret = $clientSecret
}

try {
    $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
    $token = $tokenResponse.access_token
    Write-Host "Access token retrieved successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to retrieve access token: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# --- READ MACHINE IDs ---

try {
    if (Get-Module -ListAvailable -Name ImportExcel) {
        $machineIDs = Import-Excel -Path $excelPath | Select-Object -ExpandProperty MachineID
    } else {
        Write-Host "ImportExcel module not found, attempting CSV import..." -ForegroundColor Yellow
        $machineIDs = Import-Csv -Path $excelPath | Select-Object -ExpandProperty MachineID
    }

    Write-Host "Found $($machineIDs.Count) machine IDs in file." -ForegroundColor Cyan
} catch {
    Write-Host "Failed to read machine list: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

# --- PROCESS EACH MACHINE ---

foreach ($machineId in $machineIDs) {
    Write-Host "Processing MachineID: $machineId..." -ForegroundColor Yellow

    $url = "https://api.securitycenter.microsoft.com/api/machines/$machineId/tags"
    $jsonBody = @{
        "Value"  = $tagName
        "Action" = $action
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers @{
            "Authorization" = "Bearer $token"
            "Content-Type"  = "application/json"
        } -Body $jsonBody

        Write-Host ("{0} tag '{1}' succeeded for machine {2}" -f $action, $tagName, $machineId) -ForegroundColor Green
    } catch {
        Write-Host ("{0} tag failed for machine {1}: {2}" -f $action, $machineId, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host "Tagging process completed." -ForegroundColor Cyan
