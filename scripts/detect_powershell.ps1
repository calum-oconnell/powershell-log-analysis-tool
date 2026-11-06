# detect_powershell.ps1 - Detects suspicious PowerShell activity
#Invoke-WebRequest" and "indicators of potential data exfiltration"

function Detect-PowershellThreats {
    param([string]$LogFile)

    $findings = @()

    if (-not (Test-Path $LogFile)) {
        Write-Host "WARNING: powershell_log.txt not found at $LogFile"
        return $findings
    }

    $lines = Get-Content $LogFile

    # Track if we've seen Compress-Archive (data collection) to pair with upload later
    $archiveSeen = $false

    foreach ($line in $lines) {

        # Check for encoded command
        if ($line -match "-EncodedCommand") {
            $findings += "ENCODED COMMAND: $line"
        }

        # Check for execution policy bypass
        if ($line -match "-ExecutionPolicy Bypass") {
            $findings += "EXECUTION BYPASS: $line"
        }

        # Check for -NoProfile
        if ($line -match "-NoProfile") {
            $findings += "NOPROFILE FLAG: $line"
        }

        # Check for Invoke-WebRequest downloading from http (not https = less safe)
        if ($line -match "Invoke-WebRequest" -and $line -match "http://") {
            $findings += "SUSPICIOUS DOWNLOAD (HTTP): $line"
        }

        # Check for archive creation
        if ($line -match "Compress-Archive") {
            $archiveSeen = $true
            $findings += "DATA COLLECTION: $line"
        }

        # Check for upload after an archive was made 
        if ($line -match "-Upload" -and $archiveSeen) {
            $findings += "POSSIBLE EXFILTRATION: Upload seen after archive creation - $line"
        }

        # Check for basic recon commands - whoami/ipconfig/net user 
        if ($line -match "\bwhoami\b" -or $line -match "\bipconfig\b" -or $line -match "\bnet user\b") {
            $findings += "RECONNAISSANCE: $line"
        }
    }

    return $findings
}
