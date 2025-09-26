#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-localhost}"
PORT="${2:-22}"

echo "==> Probing $TARGET:$PORT ..."
OUT="$(ssh -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -vvv "$TARGET" exit 2>&1 || true)"
KEX="$(echo "$OUT" | grep -m1 'kex: algorithm:' | awk -F: '{print $NF}' | xargs || true)"

echo "Negotiated KEX: ${KEX:-<unknown>}"
case "${KEX:-}" in
  mlkem768x25519*        ) echo "PASS: PQ hybrid KEX (mlkem768) in use."; exit 0 ;;
  sntrup761x25519*       ) echo "PASS: PQ hybrid KEX (sntrup) in use."; exit 0 ;;
  curve25519-sha256*     ) echo "OK: Fallback curve25519 in use."; exit 0 ;;
  *                      ) echo "WARN: Legacy/non-preferred KEX: ${KEX:-none}"; exit 0 ;;
esac
