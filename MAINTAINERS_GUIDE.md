# Maintainer's Guide — PQC SSH Docs & Automation

## Quick Verify
```powershell
cd .\docs\pqc-ssh
Set-ExecutionPolicy -Scope Process Bypass -Force
.\auto-pqc-proof.ps1
```
- Windows 9.5p2: expect `curve25519-sha256` (**OK fallback**).
- Future PQ builds: expect `sntrup...` or `mlkem...` (**PASS PQ hybrid**).

## Rollback
```powershell
Copy-Item "$env:ProgramData\ssh\sshd_config.bak_*" "$env:ProgramData\ssh\sshd_config" -Force
Restart-Service sshd
```

## CI
- Nightly workflow uploads `proof-latest.txt` / `proof-latest.md` artifacts.
- Ubuntu job exercises smoke test on Linux for forward-compatibility.

## Files
- `auto-pqc-proof.ps1`: Zero-touch local proof; writes markdown and text logs.
- `gh-automation.ps1`: One-click fork/branch/issue/PR with retries and dry-run.
