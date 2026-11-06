BeforeAll {
    . "$PSScriptRoot/../scripts/detect_auth.ps1"

    $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) "log-analysis-tool-tests"
    New-Item -ItemType Directory -Path $script:tmp -Force | Out-Null
}

AfterAll {
    Remove-Item -Path $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe "Detect-AuthThreats" {

    It "counts a repeated message as every attempt it stands for" {
        $log = Join-Path $script:tmp "repeat.log"
        @(
            "Nov 02 03:12:04 host sshd[1]: Failed password for root from 203.0.113.44 port 41020 ssh2"
            "Nov 02 03:12:20 host sshd[2]: message repeated 4 times: [ Failed password for root from 203.0.113.44 port 41020 ssh2]"
        ) | Set-Content -Path $log

        $findings = Detect-AuthThreats -LogFile $log
        $findings | Where-Object { $_ -match "BRUTE FORCE" } | Should -Match "5 failed login attempts"
    }
}

Describe "Generate-Report" {

    It "sets an explicit encoding when writing the report" {
        $source = Get-Content "$PSScriptRoot/../scripts/generate_report.ps1" -Raw
        $source | Should -Match "Out-File[^\r\n]*-Encoding"
    }
}
