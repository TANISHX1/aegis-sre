# setup_aegis.ps1: Sandboxed Environment Initializer for Aegis SRE (Windows/PowerShell)

# 1. Enforce Local Configuration Isolation
# This keeps all Coral configurations, credentials, and source links 
# isolated within the project directory to prevent system-wide contamination.
$AbsSandboxPath = Join-Path (Get-Location) ".aegis_sandbox"
$env:CORAL_CONFIG_DIR = $AbsSandboxPath

if (-not (Test-Path ".aegis_sandbox")) {
    New-Item -ItemType Directory -Path ".aegis_sandbox" -Force
}

Write-Host "🛡️ Aegis Sandbox Initialized at: $env:CORAL_CONFIG_DIR"

# Check if Coral CLI is installed
$CoralPath = Get-Command coral -ErrorAction SilentlyContinue
if (-not $CoralPath) {
    # Check Windows local bin
    $WinLocalBin = Join-Path $env:USERPROFILE ".local\bin\coral.exe"
    if (Test-Path $WinLocalBin) {
        $CoralPath = $WinLocalBin
    }
}

if (-not $CoralPath) {
    Write-Host "⚠️ Warning: 'coral' CLI not found. The project will run in MOCK MODE." -ForegroundColor Yellow
    Write-Host "👉 To run in REAL MODE, install Coral from: https://github.com/withcoral/coral"
    exit 0
}

Write-Host "✅ Found Coral CLI: $CoralPath"

# Using absolute path for all coral calls in this script
function run-coral {
    & $CoralPath @args
}

# 2. Register Custom Bounty Sources
$OsvPath = Join-Path (Get-Location) "backend/specs/osv.yaml"
$LogsPath = Join-Path (Get-Location) "backend/specs/logs.yaml"

if (Test-Path $OsvPath) {
    Write-Host "Registering Google OSV Source..."
    run-coral source add --file $OsvPath
}

# Update paths for all file sources
$FileSpecs = @("logs.yaml", "github.yaml")
foreach ($Spec in $FileSpecs) {
    if (Test-Path "backend/specs/$Spec") {
        Write-Host "Configuring Path for $Spec..."
        $LogsDir = (Resolve-Path "logs").Path -replace '\\', '/'
        $LogsUri = "file:///$LogsDir/"
        
        $Yaml = Get-Content "backend/specs/$Spec" -Raw
        $Yaml = $Yaml -replace "location: file:///.*", "location: $LogsUri"
        $Yaml | Set-Content "backend/specs/$Spec"
        
        Write-Host "Registering $Spec Source..."
        run-coral source add --file "backend/specs/$Spec"
    }
}

Write-Host "✅ Sources Registered." -ForegroundColor Green

# 3. Register Aegis Diagnostic Skill (best-effort)
try {
    Write-Host "Registering Aegis diagnostic skill..."
    run-coral skill add --name "aegis_diagnostic_playbook" --description "Aegis SRE diagnostic heuristics for root-cause isolation, cross-silo join patterns, and remediation playbooks." | Out-Null
}
catch {
    Write-Host "⚠️ Warning: coral skill registration is not supported in this CLI version." -ForegroundColor Yellow
}


Write-Host "🚀 Aegis SRE Backend Ready." -ForegroundColor Cyan
