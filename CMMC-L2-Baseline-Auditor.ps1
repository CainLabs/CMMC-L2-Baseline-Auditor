<#
.SYNOPSIS
    Audits a local Windows system against key CMMC 2.0 Level 2 controls.

.DESCRIPTION
    This script performs a read-only audit of a system's configuration against a subset of
    technical controls derived from NIST SP 800-171. It generates a compliance report
    in either HTML or CSV format.

.PARAMETER ReportPath
    The full file path where the compliance report will be saved.

.PARAMETER Format
    The desired report format. Valid options are HTML or CSV. Defaults to HTML.

.EXAMPLE
    .\CMMC-L2-Baseline-Auditor.ps1 -ReportPath "C:\CMMC-Audits\report.html" -Verbose

.EXAMPLE
    .\CMMC-L2-Baseline-Auditor.ps1 -ReportPath "C:\CMMC-Audits\report.csv" -Format CSV
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReportPath,

    [Parameter(Mandatory=$false)]
    [ValidateSet('HTML', 'CSV')]
    [string]$Format = 'HTML'
)

# Initialize an array to store the results of each check
$AuditResults = @()

# --- Access Control (AC) ---

# Check 1: Guest Account Status (Control 3.1.3)
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction Stop
    $currentSetting = if ($guestAccount.Enabled) { "Enabled" } else { "Disabled" }
    $status = if ($guestAccount.Enabled) { "FAIL" } else { "PASS" }
}
catch {
    # This block runs if the Guest account doesn't exist, which is also compliant
    $currentSetting = "Not Found"
    $status = "PASS"
}

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Access Control"
    ControlID        = "3.1.3"
    Description      = "Guest account is disabled"
    CurrentSetting   = $currentSetting
    CompliantSetting = "Disabled"
    Status           = $status
}

# Check 2: Session Inactivity Lock (Control 3.1.11)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regKey = "InactivityTimeoutSecs"
$currentTimeout = Get-ItemProperty -Path $regPath -Name $regKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $regKey

if ($null -eq $currentTimeout) {
    $currentSetting = "Not Configured"
    $status = "FAIL"
} else {
    $currentSetting = "$($currentTimeout / 60) minutes"
    $status = if ($currentTimeout -le 900) { "PASS" } else { "FAIL" }
}

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Access Control"
    ControlID        = "3.1.11"
    Description      = "Session lock inactivity timeout is 15 minutes or less"
    CurrentSetting   = $currentSetting
    CompliantSetting = "15 minutes (900 seconds) or less"
    Status           = $status
}

# --- Identification & Authentication (IA) ---

# Get the local password and lockout policies
$secPolicy = (net accounts)

# Check 3: Password Complexity (Control 3.5.7)
$complexityEnabled = ($secPolicy | Select-String -Pattern "Password complexity requirements" -Context 0,1).Context.PostContext -match "Enabled"
$currentSetting = if ($complexityEnabled) { "Enabled" } else { "Disabled" }
$status = if ($complexityEnabled) { "PASS" } else { "FAIL" }

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Identification & Authentication"
    ControlID        = "3.5.7"
    Description      = "Password complexity is enabled"
    CurrentSetting   = $currentSetting
    CompliantSetting = "Enabled"
    Status           = $status
}

# Check 4: Password History (Control 3.5.7)
$historyLength = (($secPolicy | Select-String -Pattern "Password history length").ToString() -split ":")[-1].Trim()
$currentSetting = if ($historyLength -eq "None") { 0 } else { [int]$historyLength }
$status = if ($currentSetting -ge 24) { "PASS" } else { "FAIL" }

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Identification & Authentication"
    ControlID        = "3.5.7"
    Description      = "Password history is 24 or more"
    CurrentSetting   = $currentSetting
    CompliantSetting = "24 or more"
    Status           = $status
}

# Check 5: Minimum Password Length (Control 3.5.7)
$minLength = (($secPolicy | Select-String -Pattern "Minimum password length").ToString() -split ":")[-1].Trim()
$currentSetting = [int]$minLength
$status = if ($currentSetting -ge 14) { "PASS" } else { "FAIL" }

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Identification & Authentication"
    ControlID        = "3.5.7"
    Description      = "Minimum password length is 14 or more"
    CurrentSetting   = $currentSetting
    CompliantSetting = "14 or more"
    Status           = $status
}

# Check 6: Account Lockout Threshold (Control 3.5.8)
$lockoutThreshold = (($secPolicy | Select-String -Pattern "Lockout threshold").ToString() -split ":")[-1].Trim()
$currentSetting = if ($lockoutThreshold -eq "Never") { "Disabled" } else { [int]$lockoutThreshold }
$status = if ($lockoutThreshold -ne "Never" -and [int]$lockoutThreshold -le 10) { "PASS" } else { "FAIL" }

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Identification & Authentication"
    ControlID        = "3.5.8"
    Description      = "Account lockout threshold is 10 or less"
    CurrentSetting   = $currentSetting
    CompliantSetting = "10 or less (but not disabled)"
    Status           = $status
}

# Check 7: Account Lockout Duration (Control 3.5.8)
$lockoutDuration = (($secPolicy | Select-String -Pattern "Lockout duration").ToString() -split ":")[-1].Trim()
$currentSetting = [int]$lockoutDuration
$status = if ($currentSetting -ge 15) { "PASS" } else { "FAIL" }

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Identification & Authentication"
    ControlID        = "3.5.8"
    Description      = "Account lockout duration is 15 minutes or more"
    CurrentSetting   = "$($currentSetting) minutes"
    CompliantSetting = "15 minutes or more"
    Status           = $status
}

# --- Audit & Accountability (AU) ---

# Get the Security Event Log configuration
$secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue

# Check 8: Audit Log Capacity & Retention (Control 3.3.4)
if ($null -ne $secLog) {
    $currentRetention = if ($secLog.IsLogFullAction -eq "OverwriteAsNeeded") { "Overwrite as needed" } else { "Do not overwrite" }
    $statusRetention = if ($currentRetention -eq "Overwrite as needed") { "PASS" } else { "FAIL" }

    $currentMaxSize = "$($secLog.MaximumSizeInBytes / 1MB) MB"
    $statusMaxSize = if ($secLog.MaximumSizeInBytes -ge 4294967296) { "PASS" } else { "FAIL" }
} else {
    $currentRetention = "Log Not Found"
    $statusRetention = "FAIL"
    $currentMaxSize = "Log Not Found"
    $statusMaxSize = "FAIL"
}

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Audit & Accountability"
    ControlID        = "3.3.4"
    Description      = "Security log retention is set to overwrite as needed"
    CurrentSetting   = $currentRetention
    CompliantSetting = "Overwrite as needed"
    Status           = $statusRetention
}

$AuditResults += [pscustomobject]@{
    ControlFamily    = "Audit & Accountability"
    ControlID        = "3.3.4"
    Description      = "Security log maximum size is 4 GB or greater"
    CurrentSetting   = $currentMaxSize
    CompliantSetting = "4096 MB (4 GB) or greater"
    Status           = $statusMaxSize
}

# --- Report Generation ---

if ($Format -eq 'CSV') {
    try {
        $AuditResults | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "CSV report successfully generated at: $ReportPath"
    }
    catch {
        Write-Error "Failed to write CSV report. Error: $($_.Exception.Message)"
    }
} else { # Default to HTML
    $head = @"
<style>
    body { font-family: Calibri, sans-serif; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }
    th { background-color: #f2f2f2; }
    .pass { background-color: #d4edda; }
    .fail { background-color: #f8d7da; }
</style>
"@

    $htmlBody = $AuditResults | ForEach-Object {
        $statusClass = if ($_.Status -eq 'PASS') { 'pass' } else { 'fail' }
        @"
    <tr class="$statusClass">
        <td>$($_.ControlFamily)</td>
        <td>$($_.ControlID)</td>
        <td>$($_.Description)</td>
        <td>$($_.CurrentSetting)</td>
        <td>$($_.CompliantSetting)</td>
        <td>$($_.Status)</td>
    </tr>
"@
    }

    try {
        $AuditResults | ConvertTo-Html -Head $head -Body $htmlBody | Out-File $ReportPath -ErrorAction Stop
        Write-Verbose "HTML report successfully generated at: $ReportPath"
    }
    catch {
        Write-Error "Failed to write HTML report. Error: $($_.Exception.Message)"
    }
}
