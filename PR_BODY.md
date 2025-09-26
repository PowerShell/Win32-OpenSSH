## Docs/Automation: Post-Quantum SSH on Windows (auto-detect + smoke tests)
**What**
- Adds `docs/pqc-ssh/` with server/client configs (fallback, sntrup hybrid, mlkem hybrid), automation (`setup-pqc-ssh.ps1`), and smoke tests.
- Auto-detects support via `ssh -Q kex` and installs the best config.
- Zero code changes; docs/examples only.

**Why**
- OpenSSH has offered post-quantum KEX since 9.0 (sntrup), and 10.0 made mlkem768 hybrid default.
- Windows builds (as of 9.5p2) typically lack these KEX; users need a safe fallback today and a path to auto-upgrade when support lands.

**Testing**
- Local validation: `sshd -t -f` and localhost smoke test (`ssh -vvv` parsed).
- Behavior:
  - Today: curve25519 fallback (`OK`).
  - Future: sntrup/mlkem hybrid (`PASS`) once Win32-OpenSSH supports it.

**Scope**
- Documentation, examples, and scripts under `docs/pqc-ssh/`.

**Notes**
- Includes `WINDOWS_BUILD_NOTES.md` describing current Windows support status.
