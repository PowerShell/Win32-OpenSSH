# Windows OpenSSH Build Notes (Sept 2025)
- Observed: `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2`
- `ssh -Q kex` includes curve25519 and classic DH but **not**:
  - `sntrup761x25519-sha512@openssh.com` (OpenSSH 9.0 default hybrid in 2022)
  - `mlkem768x25519-sha256` (OpenSSH 10.0 default hybrid in 2025)
- Therefore, PQ hybrid KEX will not negotiate on current Windows builds.
- Use fallback today; this bundle will auto-upgrade once support lands.
