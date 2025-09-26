<#
Automated PQC-SSH Setup for Windows
- Detects supported KEX via `ssh -Q kex`
- Installs best matching server/client config:
    1) mlkem768x25519-sha256 (if supported)
    2) sntrup761x25519-sha512@openssh.com (if supported)
    3) curve25519-sha256 fallback
- Validates sshd_config
- Starts/Restarts sshd
- Runs local smoke test
Author: Anurag Dongare (Sept 2025)
#>

param(
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Info($m){ Write-Host $m -ForegroundColor Cyan }
function Ok($m){ Write-Host $m -ForegroundColor Green }
function Warn($m){ Write-Host $m -ForegroundColor Yellow }
function Fail($m){ Write-Error $m; exit 1 }

Info "=== PQC SSH Setup (Auto) ==="
if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
  Fail "ssh not found in PATH."
}

# Detect capabilities
$kexList = (& ssh -Q kex) 2>$null
$hasMLKEM = $kexList -match '^mlkem768x25519-sha256$'
$hasSNTRUP = $kexList -match '^sntrup761x25519-sha512(@openssh\.com)?$'

if ($hasMLKEM) {
  $serverConfig = 'sshd_config.pqc.mlkem.example'
  $clientConfig = 'ssh_config.pqc.mlkem.example'
  Info "Detected support for mlkem768x25519-sha256. Selecting ML-KEM hybrid configs."
} elseif ($hasSNTRUP) {
  $serverConfig = 'sshd_config.pqc.sntrup.example'
  $clientConfig = 'ssh_config.pqc.sntrup.example'
  Info "Detected support for sntrup761x25519-sha512. Selecting SNTRUP hybrid configs."
} else {
  $serverConfig = 'sshd_config.fallback.example'
  $clientConfig = 'ssh_config.fallback.example'
  Info "No PQ KEX detected. Selecting curve25519 fallback configs."
}

# Verify files exist
$serverSrc = Join-Path $scriptDir $serverConfig
$clientSrc = Join-Path $scriptDir $clientConfig
if (!(Test-Path $serverSrc) -or !(Test-Path $clientSrc)) {
  Fail "Missing config templates in $scriptDir. Expected $serverConfig and $clientConfig."
}

$sshdCfg = "$env:ProgramData\ssh\sshd_config"
$sshDir = "$env:USERPROFILE\.ssh"
$sshdExe = "C:\Windows\System32\OpenSSH\sshd.exe"

# Backup current config
if (Test-Path $sshdCfg) {
  $backup = "$sshdCfg.bak_$(Get-Date -Format yyyyMMddHHmmss)"
  if (-not $DryRun) { Copy-Item $sshdCfg $backup }
  Warn "Backed up existing sshd_config to $backup"
}

# Apply server config
if (-not $DryRun) { Copy-Item $serverSrc $sshdCfg -Force }
Ok "Applied server config: $serverConfig"

# Validate syntax
& $sshdExe -t -f $sshdCfg
if ($LASTEXITCODE -ne 0) { Fail "sshd_config validation failed" }
Ok "sshd_config validated"

# Start or restart sshd
$svc = Get-Service sshd -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
  if (-not $DryRun) { Restart-Service sshd }
  Ok "sshd service restarted"
} else {
  if (-not $DryRun) { Start-Service sshd }
  Ok "sshd service started"
}

# Apply client config
New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
if (-not $DryRun) { Copy-Item $clientSrc (Join-Path $sshDir 'config') -Force }
Ok "Applied client config: $clientConfig"

# Smoke test
Info "Running smoke test against localhost..."
& (Join-Path $scriptDir 'smoke-test.ps1') -Target localhost
