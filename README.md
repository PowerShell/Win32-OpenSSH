# Post-Quantum / Hybrid SSH on Windows (Win32-OpenSSH) — Auto Switch
**Author (contributor): Anurag Dongare — Sept 2025**

This contribution provides **drop-in SSH configs**, **smoke tests**, and a **one‑shot setup script**
that **auto‑switches** between:
- **Fallback (today on Windows 9.5p2)** → curve25519-only KEX
- **PQC hybrid (future-ready)** → `sntrup761x25519-sha512@openssh.com`
- **PQC hybrid (OpenSSH ≥10.0 default)** → `mlkem768x25519-sha256`

The script detects supported algorithms via `ssh -Q kex` and installs the best available config.

> As of Windows OpenSSH **9.5p2**, `ssh -Q kex` typically does **not** include PQ KEX.
> You will see **fallback** today and **auto-upgrade** to PQ once Win32-OpenSSH adds support.

## Included
- **Configs**
  - `sshd_config.fallback.example` / `ssh_config.fallback.example`
  - `sshd_config.pqc.sntrup.example` / `ssh_config.pqc.sntrup.example`
  - `sshd_config.pqc.mlkem.example` / `ssh_config.pqc.mlkem.example`
- **Automation**
  - `setup-pqc-ssh.ps1` — auto-detect & apply best config; runs smoke test
- **Smoke tests**
  - `smoke-test.ps1` (PowerShell) and `smoke-test.sh` (bash/WSL)
- **Docs & meta**
  - `WINDOWS_BUILD_NOTES.md`, `LEGAL_NOTICE.md`, `OWNER.txt`, `PR_BODY.md`, `ISSUE_BODY.md`

## Quick run
Open **PowerShell (Administrator)** in this folder and run:
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\setup-pqc-ssh.ps1
```
It will:
1) backup `C:\ProgramData\ssh\sshd_config`,
2) detect PQ support with `ssh -Q kex`,
3) install the best server & client config,
4) (re)start the `sshd` service,
5) run `smoke-test.ps1 -Target localhost` and print the negotiated KEX.

**Interpretation**
- **PASS** → `mlkem768x25519-sha256` or `sntrup761x25519-sha512…`
- **OK (fallback)** → `curve25519-sha256`
- **WARN** → legacy/non-preferred algorithm

See `WINDOWS_BUILD_NOTES.md` for current Windows behavior.
