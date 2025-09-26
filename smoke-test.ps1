param(
  [Parameter(Mandatory=$true)][string]$Target,
  [int]$Port = 22
)

$ErrorActionPreference = 'Stop'
$ssh = "ssh"
$common = "-p $Port -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -vvv"

Write-Host "==> Probing $Target on port $Port ..." -ForegroundColor Cyan
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ssh
$psi.Arguments = "$common $Target exit"
$psi.RedirectStandardError = $true
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()
$p.WaitForExit()
$err = $p.StandardError.ReadToEnd()

$kex = ($err -split "`r?`n") | Where-Object { $_ -match "kex: algorithm:" } | ForEach-Object { ($_ -split ":")[-1].Trim() } | Select-Object -First 1

if (-not $kex) {
  Write-Host "!! Could not determine negotiated KEX. Connection may have failed." -ForegroundColor Yellow
  exit 2
}

Write-Host "Negotiated KEX: $kex" -ForegroundColor Green

if ($kex -like "mlkem768x25519*") {
  Write-Host "PASS: PQ hybrid KEX (mlkem768) in use." -ForegroundColor Green
  exit 0
} elseif ($kex -like "sntrup761x25519*") {
  Write-Host "PASS: PQ hybrid KEX (sntrup) in use." -ForegroundColor Green
  exit 0
} elseif ($kex -like "curve25519-sha256*") {
  Write-Host "OK: Fallback curve25519 in use (peer likely lacks PQ support)." -ForegroundColor Yellow
  exit 0
} else {
  Write-Host "WARN: Using legacy/non-preferred KEX: $kex" -ForegroundColor Yellow
  exit 0
}
