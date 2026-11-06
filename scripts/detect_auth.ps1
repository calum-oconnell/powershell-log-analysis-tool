# detect_auth.ps1 - Detects repeated failed SSH logins from auth.log
# Threshold: 3+ failed attempts from the same IP = suspicious

function Detect-AuthThreats {
    param([string]$LogFile)

    $findings = @()

    # Check the file exists before reading
    if (-not (Test-Path $LogFile)) {
        Write-Host "WARNING: auth.log not found at $LogFile"
        return $findings
    }

    $lines = Get-Content $LogFile

    # Count failed password attempts per IP address
    $failCounts = @{}
    $invalidUsers = @{}

    foreach ($line in $lines) {

        # Expands sshd's merged duplicate messages back into a count
        $repeats = 1
        if ($line -match "message repeated (\d+) times: \[ (.+)\]") {
            $repeats = [int]$Matches[1]
            $line = $Matches[2]
        }

        # Look for lines that say "Failed password" - standard sshd wording
        if ($line -match "Failed password") {
            # Extract the IP address - it appears after "from" in the log line
            if ($line -match "from (\d+\.\d+\.\d+\.\d+)") {
                $ip = $Matches[1]
                # Increment the counter for this IP
                if ($failCounts.ContainsKey($ip)) {
                    $failCounts[$ip] += $repeats
                } else {
                    $failCounts[$ip] = $repeats
                }
            }
        }

        # If there is a login attempt to an account that does not exist, note user's IP address & attempted name
        if ($line -match "invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)") {
            $user = $Matches[1]
            $ip = $Matches[2]
            # Starts a list the first time an IP shows up, then adds a name only if it's new
            if (-not $invalidUsers.ContainsKey($ip)) {
                $invalidUsers[$ip] = @()
            }
            if ($invalidUsers[$ip] -notcontains $user) {
                $invalidUsers[$ip] += $user
            }
        }
    }

    # Flag any IP that hit the threshold (3 or more failures)
    foreach ($ip in $failCounts.Keys) {
        if ($failCounts[$ip] -ge 3) {
            $findings += "BRUTE FORCE: IP $ip had $($failCounts[$ip]) failed login attempts"
        }
    }

    # Reports any IP that tried 3 or more accounts that don't exist, names listed A-Z
    foreach ($ip in $invalidUsers.Keys) {
        if ($invalidUsers[$ip].Count -ge 3) {
            $accounts = $invalidUsers[$ip] | Sort-Object
            $findings += "USER ENUMERATION: $ip tried $($accounts.Count) accounts that do not exist - $($accounts -join ', ')"
        }
    }

    # Flag IPs that had failures and then a successful login - track which IPs already reported
    $reportedLogins = @{}
    foreach ($line in $lines) {
        if ($line -match "Accepted password" -or $line -match "Accepted publickey") {
            if ($line -match "from (\d+\.\d+\.\d+\.\d+)") {
                $ip = $Matches[1]
                # Only report each IP once, not once per successful login line
                if ($failCounts.ContainsKey($ip) -and -not $reportedLogins.ContainsKey($ip)) {
                    $findings += "SUSPICIOUS LOGIN: $ip logged in successfully after previous failures"
                    $reportedLogins[$ip] = $true
                }
            }
        }
    }

    return $findings
}