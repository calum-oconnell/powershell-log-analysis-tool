# run.ps1 - Main entry point. Run this with: .\run.ps1

# Set paths to log files
$accessLog     = "samples\access.log"
$authLog       = "samples\auth.log"
$powershellLog = "samples\powershell_log.txt"
$iocFile       = "samples\ioc.txt"
$reportFile    = "investigation_report.txt"

# Load each detection script from the scripts folder
. .\scripts\detect_auth.ps1
. .\scripts\detect_powershell.ps1
. .\scripts\detect_ioc.ps1
. .\scripts\generate_report.ps1

# Run each detection function and store results
$authFindings        = Detect-AuthThreats       -LogFile $authLog
$powershellFindings  = Detect-PowershellThreats -LogFile $powershellLog
$iocFindings         = Detect-IOCMatches        -AccessLog $accessLog -IocFile $iocFile

# Pass all findings to the report generator
Generate-Report -AuthFindings $authFindings `
                -PsFindings $powershellFindings `
                -IocFindings $iocFindings `
                -OutputFile $reportFile

Write-Host "Done. Report saved to: $reportFile"
