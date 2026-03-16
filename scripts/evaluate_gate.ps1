param(
    [string]$ReportPath         = "reports\scan_report_latest.json",
    [int]$ThresholdCritical     = [int]($env:THRESHOLD_CRITICAL ?? "0"),
    [int]$ThresholdHigh         = [int]($env:THRESHOLD_HIGH ?? "2"),
    [int]$ThresholdMedium       = [int]($env:THRESHOLD_MEDIUM ?? "10")
)

Set-StrictMode -Version Latest

if (-not (Test-Path $ReportPath)) {
    Write-Error "Security report not found at: $ReportPath"
    exit 1
}

$Data       = Get-Content $ReportPath | ConvertFrom-Json
$Evaluation = $Data.evaluation
$Summary    = $Data.summary

$Critical = $Summary.severity_counts.CRITICAL
$High     = $Summary.severity_counts.HIGH
$Medium   = $Summary.severity_counts.MEDIUM
$Passed   = $Evaluation.passed

Write-Host "Security Gate Evaluation" -ForegroundColor Cyan
Write-Host "  Critical : $Critical (threshold: $ThresholdCritical)" -ForegroundColor $(if ($Critical -gt $ThresholdCritical) { "Red" } else { "Green" })
Write-Host "  High     : $High (threshold: $ThresholdHigh)" -ForegroundColor $(if ($High -gt $ThresholdHigh) { "Red" } else { "Green" })
Write-Host "  Medium   : $Medium (threshold: $ThresholdMedium)" -ForegroundColor $(if ($Medium -gt $ThresholdMedium) { "Yellow" } else { "Green" })

$GatePassed = $true

if ($Critical -gt $ThresholdCritical) {
    Write-Host "  !! GATE FAIL: $Critical CRITICAL findings exceed threshold of $ThresholdCritical" -ForegroundColor Red
    $GatePassed = $false
}

if ($High -gt $ThresholdHigh) {
    Write-Host "  !! GATE FAIL: $High HIGH findings exceed threshold of $ThresholdHigh" -ForegroundColor Red
    $GatePassed = $false
}

if (-not $GatePassed) {
    Write-Host ""
    Write-Host "SECURITY GATE FAILED - Deployment blocked." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "SECURITY GATE PASSED - Deployment can proceed." -ForegroundColor Green
exit 0