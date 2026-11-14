#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
# E2E-07: two peers use one cGRASP session ID without cross-exchange delivery.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
CAPTURE_DIR="${CAPTURE_DIR:-$ROOT/captures/session-collision}"
RUN_ID="${RUN_ID:-e2e07-$$}"
SESSION_ID="${SESSION_ID:-3792101383}"
NS_A="cgrasp-${RUN_ID}-alpha"
NS_B="cgrasp-${RUN_ID}-bravo"
NS_S="cgrasp-${RUN_ID}-server"
NAMESPACES=("$NS_A" "$NS_B" "$NS_S")
PIDS=()
CAPTURE_PIDS=()
MANIFEST_STARTED=0

if [[ "${EUID}" -ne 0 ]]; then
  echo "This test requires root for ip netns, veth and tcpdump." >&2
  exit 77
fi

cleanup() {
  local status=$?
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for ns in "${NAMESPACES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ "$MANIFEST_STARTED" == "1" && "$status" -ne 0 ]]; then
    "$PYTHON_BIN" "$ROOT/scripts/write_e2e_manifest.py" \
      --output "$CAPTURE_DIR/run-manifest.json" --run-id "$RUN_ID" \
      --scenario E2E-07 --topology 'A--S--B' --result FAIL \
      --parameter "session_id=$SESSION_ID" --parameter clients=2 || true
  fi
  return "$status"
}
trap cleanup EXIT
cleanup
mkdir -p "$CAPTURE_DIR"
"$PYTHON_BIN" "$ROOT/scripts/write_e2e_manifest.py" \
  --output "$CAPTURE_DIR/run-manifest.json" --run-id "$RUN_ID" \
  --scenario E2E-07 --topology 'A--S--B' --result RUNNING \
  --parameter "session_id=$SESSION_ID" --parameter clients=2
MANIFEST_STARTED=1

for ns in "${NAMESPACES[@]}"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

ip link add va0 type veth peer name vs0
ip link set va0 netns "$NS_A"
ip link set vs0 netns "$NS_S"
ip -n "$NS_A" link set va0 up
ip -n "$NS_S" link set vs0 up
ip -n "$NS_A" -6 addr add fd00:7:1::1/64 dev va0
ip -n "$NS_S" -6 addr add fd00:7:1::2/64 dev vs0

ip link add vb0 type veth peer name vs1
ip link set vb0 netns "$NS_B"
ip link set vs1 netns "$NS_S"
ip -n "$NS_B" link set vb0 up
ip -n "$NS_S" link set vs1 up
ip -n "$NS_B" -6 addr add fd00:7:2::1/64 dev vb0
ip -n "$NS_S" -6 addr add fd00:7:2::2/64 dev vs1

for spec in "server-alpha:vs0" "server-bravo:vs1"; do
  name=${spec%%:*}
  iface=${spec##*:}
  ip netns exec "$NS_S" tcpdump -U -s 0 -i "$iface" \
    -w "$CAPTURE_DIR/$name.pcap" udp port 5683 \
    >"$CAPTURE_DIR/$name.tcpdump.log" 2>&1 &
  CAPTURE_PIDS+=("$!")
  PIDS+=("$!")
done

ip netns exec "$NS_S" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" collision-server \
  --bind :: --port 5683 --obj 47907 --expected-clients 2 --timeout-ms 7000 \
  >"$CAPTURE_DIR/server.log" 2>&1 &
SERVER_PID=$!
PIDS+=("$SERVER_PID")

for _ in $(seq 1 50); do
  if grep -q '"event": "ready"' "$CAPTURE_DIR/server.log"; then break; fi
  sleep 0.1
done
if ! grep -q '"event": "ready"' "$CAPTURE_DIR/server.log"; then
  echo "Collision server did not become ready" >&2
  exit 1
fi

ip netns exec "$NS_A" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" collision-client \
  --bind :: --local-port 15683 --obj 47907 --value alpha \
  --peer-uri 'coap://[fd00:7:1::2]:5683' --forced-session-id "$SESSION_ID" \
  --timeout-ms 7000 >"$CAPTURE_DIR/client-alpha.log" 2>&1 &
CLIENT_A_PID=$!
PIDS+=("$CLIENT_A_PID")
ip netns exec "$NS_B" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" collision-client \
  --bind :: --local-port 15683 --obj 47907 --value bravo \
  --peer-uri 'coap://[fd00:7:2::2]:5683' --forced-session-id "$SESSION_ID" \
  --timeout-ms 7000 >"$CAPTURE_DIR/client-bravo.log" 2>&1 &
CLIENT_B_PID=$!
PIDS+=("$CLIENT_B_PID")

set +e
wait "$CLIENT_A_PID"; CLIENT_A_STATUS=$?
wait "$CLIENT_B_PID"; CLIENT_B_STATUS=$?
wait "$SERVER_PID"; SERVER_STATUS=$?
set -e
if [[ "$CLIENT_A_STATUS" -ne 0 || "$CLIENT_B_STATUS" -ne 0 || "$SERVER_STATUS" -ne 0 ]]; then
  echo "Collision roles failed: alpha=$CLIENT_A_STATUS bravo=$CLIENT_B_STATUS server=$SERVER_STATUS" >&2
  exit 1
fi

for pid in "${CAPTURE_PIDS[@]}"; do kill -INT "$pid" 2>/dev/null || true; done
for pid in "${CAPTURE_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
sleep 0.2

"$PYTHON_BIN" "$ROOT/scripts/check_session_collision_pcaps.py" "$CAPTURE_DIR" \
  --report "$CAPTURE_DIR/session-collision-report.txt" \
  --server-log "$CAPTURE_DIR/server.log" \
  --client-a-log "$CAPTURE_DIR/client-alpha.log" \
  --client-b-log "$CAPTURE_DIR/client-bravo.log" \
  --session-id "$SESSION_ID"
"$PYTHON_BIN" "$ROOT/scripts/render_namespace_interactions.py" "$CAPTURE_DIR" \
  --mode e2e07 --output "$CAPTURE_DIR/res1_1_5683_session_collision.txt"
"$PYTHON_BIN" "$ROOT/scripts/write_e2e_manifest.py" \
  --output "$CAPTURE_DIR/run-manifest.json" --run-id "$RUN_ID" \
  --scenario E2E-07 --topology 'A--S--B' --result PASS \
  --parameter "session_id=$SESSION_ID" --parameter clients=2
echo "PASS: E2E-07 same-SID peer isolation; captures: $CAPTURE_DIR"
echo "REPORT: $CAPTURE_DIR/res1_1_5683_session_collision.txt"
