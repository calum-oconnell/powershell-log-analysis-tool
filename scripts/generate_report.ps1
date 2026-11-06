# generate_report.ps1 - Writes all findings to investigation_report.txt

function Generate-Report {
    param(
        [array]$AuthFindings,
        [array]$PsFindings,
        [array]$IocFindings,
        [string]$OutputFile
    )

    # Wipe any old report before writing a fresh one
    if (Test-Path $OutputFile) { Remove-Item $OutputFile }

    # Helper to write a line to both the file and the console
    function Write-Line { param($text)
        # Uses UTF-8 to ensure compatibility across multiple editors
        $text | Out-File -FilePath $OutputFile -Append -Encoding utf8
        Write-Host $text
    }

    $total = $AuthFindings.Count + $PsFindings.Count + $IocFindings.Count

    Write-Line "---"
    Write-Line "   SECURITY INVESTIGATION REPORT"
    Write-Line ---
    Write-Line "Generated: $(Get-Date)"
    Write-Line ""
    Write-Line "SUMMARY"
    Write-Line ---
    Write-Line "Total suspicious events found: $total"
    Write-Line "  - Auth threats:       $($AuthFindings.Count)"
    Write-Line "  - PowerShell threats: $($PsFindings.Count)"
    Write-Line "  - IOC matches:        $($IocFindings.Count)"
    Write-Line ""

    # Section 1: Auth findings
    Write-Line "---"
    Write-Line "SECTION 1: AUTHENTICATION THREATS"
    Write-Line "---"
    if ($AuthFindings.Count -eq 0) {
        Write-Line "No suspicious auth activity detected."
    } else {
        foreach ($f in $AuthFindings) { Write-Line "  [!] $f" }
    }
    Write-Line ""

    # Section 2: PowerShell findings
    Write-Line "---"
    Write-Line "SECTION 2: POWERSHELL THREATS"
    Write-Line "---"
    if ($PsFindings.Count -eq 0) {
        Write-Line "No suspicious PowerShell activity detected."
    } else {
        foreach ($f in $PsFindings) { Write-Line "  [!] $f" }
    }
    Write-Line ""

    # Section 3: IOC findings
    Write-Line "---"
    Write-Line "SECTION 3: IOC MATCHES"
    Write-Line "---"
    if ($IocFindings.Count -eq 0) {
        Write-Line "No IOC matches detected."
    } else {
        foreach ($f in $IocFindings) { Write-Line "  [!] $f" }
    }
    Write-Line ""

    Write-Line "---"
    Write-Line "END OF REPORT"
    Write-Line "---"
}
