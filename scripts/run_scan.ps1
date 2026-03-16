param(
    [string]$Target             = $env:SCAN_TARGET,
    [string]$EnableZap          = $env:ENABLE_ZAP,
    [string]$OutDir             = $env:REPORT_DIR,
    [int]$ThresholdCritical     = [int]($env:THRESHOLD_CRITICAL ?? "0"),
    [int]$ThresholdHigh         = [int]($env:THRESHOLD_HIGH ?? "2"),
    [int]$ThresholdMedium       = [int]($env:THRESHOLD_MEDIUM ?? "10"),
    [switch]$Verbose,
    [switch]$OutputJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Target)    { $Target    = "https://example.com" }
if (-not $EnableZap) { $EnableZap = "false" }
if (-not $OutDir)    { $OutDir    = "reports" }

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DevSecOps Automated Security Scanner" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Target   : $Target" -ForegroundColor White
Write-Host "  Out Dir  : $OutDir" -ForegroundColor White
Write-Host "  ZAP      : $EnableZap" -ForegroundColor White
Write-Host "  Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Installing Python dependencies..." -ForegroundColor Yellow
Push-Location $ProjectRoot
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install dependencies"
    exit 1
}

Write-Host "[2/3] Running security scanner..." -ForegroundColor Yellow

$args_list = @(
    "scanner\main.py",
    "--target", $Target,
    "--out-dir", $OutDir,
    "--threshold-critical", $ThresholdCritical,
    "--threshold-high",     $ThresholdHigh,
    "--threshold-medium",   $ThresholdMedium
)

if ($EnableZap -eq "true")  { $args_list += "--zap" }
if ($Verbose)               { $args_list += "--verbose" }
if ($OutputJson)            { $args_list += "--output-json" }

python @args_list
$ScanExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "[3/3] Evaluating results..." -ForegroundColor Yellow

$ReportFile = Join-Path $OutDir "scan_report_latest.json"

if (-not (Test-Path $ReportFile)) {
    Write-Error "Report file not found at: $ReportFile"
    Pop-Location
    exit 1
}

$ReportData = Get-Content $ReportFile | ConvertFrom-Json
$Evaluation = $ReportData.evaluation
$Summary    = $ReportData.summary

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SCAN RESULTS" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("  Status       : " + $(if ($Evaluation.passed) { "PASS" } else { "FAIL" })) -ForegroundColor $(if ($Evaluation.passed) { "Green" } else { "Red" })
Write-Host "  Risk Score   : $($Summary.risk_score)/100 ($($Summary.risk_rating))" -ForegroundColor White
Write-Host "  Total        : $($Summary.total)" -ForegroundColor White
Write-Host "  Critical     : $($Summary.severity_counts.CRITICAL)" -ForegroundColor Red
Write-Host "  High         : $($Summary.severity_counts.HIGH)" -ForegroundColor DarkYellow
Write-Host "  Medium       : $($Summary.severity_counts.MEDIUM)" -ForegroundColor Yellow
Write-Host "  Low          : $($Summary.severity_counts.LOW)" -ForegroundColor Green

if ($Evaluation.failure_reasons.Count -gt 0) {
    Write-Host ""
    Write-Host "  FAILURE REASONS:" -ForegroundColor Red
    foreach ($reason in $Evaluation.failure_reasons) {
        Write-Host "    !! $reason" -ForegroundColor Red
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Pop-Location

if (-not $Evaluation.passed) {
    Write-Host "Pipeline BLOCKED by security gate." -ForegroundColor Red
    exit 1
}

Write-Host "Security gate PASSED. Proceeding to deployment." -ForegroundColor Green
exit 0