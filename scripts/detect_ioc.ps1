# detect_ioc.ps1 - Cross-checks access.log against known bad IPs and paths in ioc.txt

function Detect-IOCMatches {
    param(
        [string]$AccessLog,
        [string]$IocFile
    )

    $findings = @()

    if (-not (Test-Path $AccessLog)) {
        Write-Host "WARNING: access.log not found at $AccessLog"
        return $findings
    }

    if (-not (Test-Path $IocFile)) {
        Write-Host "WARNING: ioc.txt not found at $IocFile"
        return $findings
    }

    # Read IOC file and separate IPs from paths, skip comments and blank lines
    $iocLines = Get-Content $IocFile | Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }

    $maliciousIPs    = @()
    $maliciousPaths  = @()

    foreach ($ioc in $iocLines) {
        # IP addresses match the pattern x.x.x.x
        if ($ioc -match "^\d+\.\d+\.\d+\.\d+$") {
            $maliciousIPs += $ioc
        } else {
            # Anything else in ioc.txt is treated as a suspicious web path
            $maliciousPaths += $ioc
        }
    }

    $accessLines = Get-Content $AccessLog

    foreach ($line in $accessLines) {
        # Check if any known bad IP appears at the start of the access log line
        foreach ($ip in $maliciousIPs) {
            if ($line -match [regex]::Escape($ip)) {
                $findings += "MALICIOUS IP HIT: $ip found in access log - $line"
            }
        }

        # Check if any known bad path appears in the request
        foreach ($path in $maliciousPaths) {
            if ($line -match [regex]::Escape($path)) {
                $findings += "MALICIOUS PATH HIT: $path found in access log - $line"
                break
            }
        }
    }

    return $findings
}
