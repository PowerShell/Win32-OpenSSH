<#
auto-pqc-proof.ps1 (v6)
- Zero-touch proof of PQC SSH setup on Windows
- Generates both text and Markdown logs with system info
- Validates config, (re)starts sshd, runs smoke tests (localhost + github.com)
#>

param(
  [string]$MarkdownOut = ".\proof-log.md",
  [string]$TextOut = ".\proof-log.txt"
)

# --- Self-Healing Here-String Terminator Checker ---
try {
  $scriptPath = $MyInvocation.MyCommand.Definition
  $raw = Get-Content $scriptPath -ErrorAction Stop
  $fixed = @()
  $changed = $false
  foreach ($line in $raw) {
    if ($line -match '^\s*"@') {
      $fixed += '"@'
      $changed = $true
    } else {
      $fixed += $line
    }
  }
  if ($changed) {
    Write-Host "[AutoFix] Corrected mis-indented here-string terminators in $scriptPath" -ForegroundColor Yellow
    $fixed | Set-Content $scriptPath -Encoding UTF8
  }
} catch {
  Write-Host "[AutoFix] Skipped (unable to read/patch script): $($_.Exception.Message)" -ForegroundColor DarkYellow
}
# --- End AutoFix ---


$ErrorActionPreference = "Stop"
function NowUtc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") }

# Gather system facts
$os = (Get-CimInstance Win32_OperatingSystem)
$osVer = "$($os.Caption) $($os.Version) Build $($os.BuildNumber)"
$sshVer = (ssh -V) 2>&1
$kexList = (ssh -Q kex) 2>$null
$cipherList = (ssh -Q cipher) 2>$null
$macList = (ssh -Q mac) 2>$null

# Prepare dynamic config (like v4)
$sshdCfg = "$env:ProgramData\ssh\sshd_config"
$sshdExe = "C:\Windows\System32\OpenSSH\sshd.exe"
$backup = "$sshdCfg.bak_$(Get-Date -Format yyyyMMddHHmmss)"

# Choose KEX
if ($kexList -contains "mlkem768x25519-sha256") { $chosenKex = "mlkem768x25519-sha256" }
elseif ($kexList -contains "sntrup761x25519-sha512@openssh.com") { $chosenKex = "sntrup761x25519-sha512@openssh.com" }
elseif ($kexList -contains "curve25519-sha256") { $chosenKex = "curve25519-sha256" }
else { $chosenKex = ($kexList | Select-Object -First 1) }

# Choose ciphers/mac (safe set present on host)
$preferredCiphers = @(
  "chacha20-poly1305@openssh.com","aes256-gcm@openssh.com","aes128-gcm@openssh.com",
  "aes256-ctr","aes192-ctr","aes128-ctr"
) | Where-Object { $cipherList -contains $_ }
if (-not $preferredCiphers) { $preferredCiphers = $cipherList | Select-Object -First 3 }

$preferredMACs = @(
  "hmac-sha2-512-etm@openssh.com","hmac-sha2-256-etm@openssh.com",
  "hmac-sha2-512","hmac-sha2-256"
) | Where-Object { $macList -contains $_ }
if (-not $preferredMACs) { $preferredMACs = $macList | Select-Object -First 2 }

# Backup current config
if (Test-Path $sshdCfg) { Copy-Item $sshdCfg $backup -Force }

# Build config
$config = @"
Port 22
Protocol 2
HostKey C:/ProgramData/ssh/ssh_host_ed25519_key
HostKey C:/ProgramData/ssh/ssh_host_rsa_key
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
UseDNS no
AllowTcpForwarding yes
X11Forwarding no
AllowAgentForwarding yes
Subsystem sftp sftp-server.exe

KexAlgorithms $chosenKex
"@
foreach ($c in $preferredCiphers) { $config += "`r`nCiphers $c" }
foreach ($m in $preferredMACs) { $config += "`r`nMACs $m" }

$config | Out-File -FilePath $sshdCfg -Encoding ascii -Force

# Validate & start
& $sshdExe -t -f $sshdCfg
if ($LASTEXITCODE -ne 0) { throw "sshd_config validation failed" }
$svc = Get-Service sshd -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") { Restart-Service sshd } else { Start-Service sshd }

# Run smoke tests
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$smoke = Join-Path $scriptDir "smoke-test.ps1"

$localOut = & $smoke -Target localhost 2>&1 | Out-String
$ghOut = & $smoke -Target github.com 2>&1 | Out-String

# Parse negotiated lines
function Parse-Kex($s){ ($s -split "\r?\n") | Where-Object { $_ -match '^Negotiated KEX:' } | Select-Object -First 1 }
$kexLocal = Parse-Kex $localOut
$kexGitHub = Parse-Kex $ghOut

# Write text log
$text = @"
=== Auto-Proof PQC SSH (V6) ===
Date: $(NowUtc)
OS: $osVer
SSH: $sshVer

Detected KEX: $($kexList -join ', ')
Detected Ciphers: $($cipherList -join ', ')
Detected MACs: $($macList -join ', ')

Selected KEX: $chosenKex

-- Localhost --
$localOut

-- GitHub.com --
$ghOut
"@
$text | Out-File -FilePath $TextOut -Encoding utf8 -Force

# Write markdown log
$md = @"
## PQC Proof Log (V6)
- **Date:** $(NowUtc)
- **OS:** $osVer
- **SSH:** $sshVer

**Detected KEX:** $($kexList -join ', ')  
**Detected Ciphers:** $($cipherList -join ', ')  
**Detected MACs:** $($macList -join ', ')

**Selected KEX:** `$chosenKex`

### Localhost
```text
$($localOut.Trim())
```

### GitHub.com
```text
$($ghOut.Trim())
```
"@
$md | Out-File -FilePath $MarkdownOut -Encoding utf8 -Force

Write-Host "Proof logs written to $TextOut and $MarkdownOut" -ForegroundColor Green