### Feature: Official PQ SSH configuration, automation & tests for Windows OpenSSH
**Problem**
Endpoints (e.g., major Git hosting) now advertise PQ hybrid SSH KEX. Windows users need guidance and
tested configs. Current Windows builds typically do not list sntrup/mlkem in `ssh -Q kex`.

**Proposal**
- Provide `docs/pqc-ssh/` with:
  - fallback (curve25519) configs for immediate use,
  - sntrup & mlkem hybrid configs for future readiness,
  - automation to auto-detect and apply the best option,
  - smoke tests to reveal negotiated KEX from `ssh -vvv`.
**Benefit**
- Zero risk docs; immediate value for operators; accelerates PQ readiness.
**Related**
- Link to Win32-OpenSSH issues about missing sntrup/mlkem support.
