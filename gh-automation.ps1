<#
gh-automation.ps1 (v6)
- Automates: local proof -> fork/branch -> push -> issue -> PR (with retries, dry-run, stop)
Requires: GitHub CLI (gh), Git
#>

param(
  [switch]$Start,
  [switch]$DryRun,
  [switch]$Stop,
  [string]$Upstream = "PowerShell/Win32-OpenSSH",
  [string]$BaseBranch = "L1-Prod",
  [string]$FeatureBranch = "docs/pqc-ssh",
  [string]$ProofText = ".\proof-log.txt",
  [string]$ProofMarkdown = ".\proof-log.md",
  [string]$IssueTemplate = ".\ISSUE_BODY.md",
  [string]$PrTemplate = ".\PR_BODY.md",
  [string]$WorkDir = ".\tmp-win32openssh"
)

$ErrorActionPreference = "Stop"
function Info($m){ Write-Host $m -ForegroundColor Cyan }
function Ok($m){ Write-Host $m -ForegroundColor Green }
function Warn($m){ Write-Host $m -ForegroundColor Yellow }
function Fail($m){ Write-Error $m; exit 1 }
function Retry($scriptBlock, [int]$times=3){
  for($i=1;$i -le $times;$i++){
    try { & $scriptBlock; return } catch { if($i -eq $times){ throw } ; Start-Sleep -Seconds ([int][Math]::Pow(2, $i)) }
  }
}

if ($Stop){
  if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
  Write-Host "Stopped and cleaned work dir." -ForegroundColor Yellow
  exit 0
}

# 0) Produce fresh proof logs first
if ($Start -or -not $DryRun){
  if (Test-Path ".\docs\pqc-ssh\auto-pqc-proof.ps1"){
    Info "Running local proof to refresh logs..."
    & ".\docs\pqc-ssh\auto-pqc-proof.ps1" -MarkdownOut $ProofMarkdown -TextOut $ProofText
  } else {
    Warn "auto-pqc-proof.ps1 not found; skipping local proof."
  }
}

# 1) Sanity checks
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Fail "GitHub CLI 'gh' not found. Install https://cli.github.com" }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Fail "Git not found. Install https://git-scm.com" }
gh auth status | Out-Null

$me = (gh api user --jq .login).Trim()
if (-not $me) { Fail "Could not resolve your GitHub username." }
Ok "Authenticated as $me"

# 2) dedupe: find similar issues upstream
Info "Searching for existing upstream issues about PQ SSH..."
$existing = gh issue list --repo $Upstream --search "is:issue PQ SSH configs smoke tests" --limit 5
if ($existing){
  Write-Host "Existing issues that may match:" -ForegroundColor Yellow
  Write-Host $existing
}

if ($DryRun){
  Warn "DryRun enabled: skipping fork/clone/push/PR creation."
  exit 0
}

# 3) Ensure fork exists
Retry { gh repo fork $Upstream --remote=false --clone=false --org $me | Out-Null }

# 4) Clone fork
$ForkFull = "$me/" + ($Upstream.Split("/")[1])
if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
Retry { gh repo clone $ForkFull $WorkDir }
Set-Location $WorkDir

# 5) Create branch & copy files
Retry { git checkout -b "$FeatureBranch" }
$src = Resolve-Path "..\docs\pqc-ssh"
$dst = Join-Path $PWD "docs\pqc-ssh"
New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
Copy-Item -Recurse -Force "$src\*" $dst

# 6) Commit/push
Retry { git add docs/pqc-ssh }
Retry { git commit -m "Docs: Add PQ SSH configs + smoke tests (fallback + PQ auto-switch, auto-proof, CI)" }
Retry { git push origin "$FeatureBranch" }
Ok "Pushed feature branch: $FeatureBranch"

# 7) Prepare Issue body (embed proof markdown if exists)
$issueBody = if (Test-Path "..\ISSUE_BODY.md") { Get-Content "..\ISSUE_BODY.md" -Raw } else { "# Feature: PQ SSH" }
if (Test-Path "..\proof-log.md") {
  $md = Get-Content "..\proof-log.md" -Raw
  $issueBody += "`n`n## Automated Proof Log`n" + $md
}

# 8) Create Issue
$issueUrl = (gh issue create --repo $Upstream --title "Feature Request: Post-Quantum SSH configs + smoke tests (safe fallback, PQ auto-detect)" --body "$issueBody").Trim()
Ok "Issue created: $issueUrl"

# 9) Prepare PR body
$prBody = if (Test-Path "..\PR_BODY.md") { Get-Content "..\PR_BODY.md" -Raw } else { "Docs: PQ SSH configs + smoke tests" }
$prBody += "`n`nLinked Issue: $issueUrl"

# 10) Create PR
$prUrl = (gh pr create --repo $Upstream --base $BaseBranch --head "${me}:${FeatureBranch}" --title "Docs: Add PQ SSH configs + smoke tests (fallback + PQ auto-switch, auto-proof, CI)" --body "$prBody").Trim()
Ok "PR created: $prUrl"

# 11) Save automation run log
Set-Location ..
(Get-Date).ToString("s") + " Automation completed. PR: $prUrl Issue: $issueUrl" | Out-File -FilePath ".\automation-run-$(Get-Date -Format yyyyMMddHHmmss).log"
