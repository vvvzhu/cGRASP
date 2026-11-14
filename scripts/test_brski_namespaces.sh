#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
# BRSKI flood E2E over three Linux network namespaces.
#
# Topology:
#
#   R (Reggie) --- P (Procksy) --- L (Pledji)
#
# Reggie floods AN_join_registrar (41120) on the R--P link.  Procksy sees it
# and floods AN_proxy (41121) on the P--L link.  Pledji must discover the proxy.
#
# Requires root for ip netns/veth.  Does not need tcpdump.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi
CAPTURE_DIR="${CAPTURE_DIR:-$ROOT/captures/brski-e2e}"
RUN_ID="${RUN_ID:-brski-$$}"
NS_R="cgrasp-${RUN_ID}-r"
NS_P="cgrasp-${RUN_ID}-p"
NS_L="cgrasp-${RUN_ID}-l"
PIDS=()
NAMESPACES=("$NS_R" "$NS_P" "$NS_L")

if [[ "${EUID}" -ne 0 ]]; then
  echo "This test requires root for ip netns and veth." >&2
  exit 77
fi

cleanup() {
  local status=$?
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  sleep 0.2
  for pid in "${PIDS[@]:-}"; do
    kill -9 "$pid" 2>/dev/null || true
  done
  for ns in "${NAMESPACES[@]}"; do
    ip netns del "$ns" 2>/dev/null || true
  done
  return "$status"
}
trap cleanup EXIT

rm -rf "$CAPTURE_DIR"
mkdir -p "$CAPTURE_DIR"

ip netns add "$NS_R"
ip netns add "$NS_P"
ip netns add "$NS_L"

ip link add br-r type veth peer name br-p1
ip link set br-r netns "$NS_R"
ip link set br-p1 netns "$NS_P"
ip link add br-p2 type veth peer name br-l
ip link set br-p2 netns "$NS_P"
ip link set br-l netns "$NS_L"

for ns in "${NAMESPACES[@]}"; do
  ip -n "$ns" link set lo up
done
ip -n "$NS_R" link set br-r up
ip -n "$NS_P" link set br-p1 up
ip -n "$NS_P" link set br-p2 up
ip -n "$NS_L" link set br-l up

# Allow IPv6 link-local addresses to finish DAD.
sleep 1

start_node() {
  local ns=$1 log=$2
  shift 2
  ip netns exec "$ns" "$PYTHON_BIN" -u "$@" >"$CAPTURE_DIR/$log" 2>&1 &
  PIDS+=("$!")
}

start_node "$NS_L" pledji.log "$ROOT/ASA-examples/Pledji.py" \
  --bind :: --coap-port 5683 --interval 1
start_node "$NS_P" procksy.log "$ROOT/ASA-examples/Procksy.py" \
  --bind :: --coap-port 5683 --interval 1 --ttl-ms 5000
start_node "$NS_R" reggie.log "$ROOT/ASA-examples/Reggie.py" \
  --bind :: --coap-port 5683 --interval 1 --ttl-ms 5000 --value EST-TLS

deadline=$((SECONDS + 25))
while (( SECONDS < deadline )); do
  if grep -q 'registrar=' "$CAPTURE_DIR/procksy.log" 2>/dev/null && \
     grep -q 'flooded proxy' "$CAPTURE_DIR/procksy.log" 2>/dev/null && \
     grep -q 'discovered join proxy' "$CAPTURE_DIR/pledji.log" 2>/dev/null; then
    break
  fi
  sleep 0.5
done

ok=1
grep -q 'registrar=' "$CAPTURE_DIR/procksy.log" || ok=0
grep -q 'flooded proxy' "$CAPTURE_DIR/procksy.log" || ok=0
grep -q 'discovered join proxy' "$CAPTURE_DIR/pledji.log" || ok=0

{
  echo "BRSKI namespace E2E"
  echo "  topology: R(Reggie) --- P(Procksy) --- L(Pledji)"
  if (( ok )); then
    echo "  result: PASS"
    grep 'registrar=' "$CAPTURE_DIR/procksy.log" || true
    grep 'flooded proxy' "$CAPTURE_DIR/procksy.log" | tail -1 || true
    grep 'discovered join proxy' "$CAPTURE_DIR/pledji.log" | tail -1 || true
  else
    echo "  result: FAIL"
  fi
} | tee "$CAPTURE_DIR/report.txt"

if (( ! ok )); then
  echo "--- reggie.log ---" >&2
  cat "$CAPTURE_DIR/reggie.log" >&2 || true
  echo "--- procksy.log ---" >&2
  cat "$CAPTURE_DIR/procksy.log" >&2 || true
  echo "--- pledji.log ---" >&2
  cat "$CAPTURE_DIR/pledji.log" >&2 || true
  exit 1
fi

echo "PASS: BRSKI namespace flood chain; captures: $CAPTURE_DIR"
