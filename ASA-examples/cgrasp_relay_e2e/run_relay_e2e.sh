#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CASE_DIR="$ROOT/ASA-examples/cgrasp_relay_e2e"
PYTHON_BIN="${PYTHON_BIN:-python3}"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-$ROOT/artifacts/cgrasp_relay_e2e}"
KEEP_ARTIFACTS=0
CLEANUP_ONLY=0
VERBOSE=0
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
PIDS=()
TCPDUMP_PIDS=()
PCAP_RENDERED=0
RUN_STATUS=0

usage() {
  cat >&2 <<EOF
usage: sudo $0 [--keep-artifacts] [--verbose] [--cleanup-only]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-artifacts) KEEP_ARTIFACTS=1 ;;
    --cleanup-only) CLEANUP_ONLY=1 ;;
    --verbose) VERBOSE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

require_cmd() {
  command -v "$1" >/dev/null || {
    echo "missing dependency: $1" >&2
    exit 127
  }
}

cleanup() {
  local status=$?
  for pid in "${TCPDUMP_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [[ "$CLEANUP_ONLY" -eq 0 ]]; then
    "$CASE_DIR/cleanup_netns.sh" "$RUN_ID" >/dev/null 2>&1 || true
  fi
  if [[ "$status" -ne 0 && "$KEEP_ARTIFACTS" -eq 0 && -n "${ARTIFACT_DIR:-}" ]]; then
    echo "Artifacts retained for failed run: $ARTIFACT_DIR" >&2
  fi
}
trap cleanup EXIT INT TERM

require_cmd ip
require_cmd "$PYTHON_BIN"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This test requires root for Linux network namespace and veth setup." >&2
  echo "Run: sudo $0" >&2
  exit 77
fi

if [[ "$CLEANUP_ONLY" -eq 1 ]]; then
  "$CASE_DIR/cleanup_netns.sh"
  echo "cGRASP relay end-to-end cleanup: PASS"
  exit 0
fi

mkdir -p "$ARTIFACT_ROOT"
ARTIFACT_DIR="$ARTIFACT_ROOT/$RUN_ID"
mkdir -p "$ARTIFACT_DIR"

"$CASE_DIR/setup_netns.sh" "$RUN_ID" >"$ARTIFACT_DIR/namespaces.txt"

if command -v tcpdump >/dev/null; then
  ns_a="cgrasp-e2e-${RUN_ID}-a"
  ns_r="cgrasp-e2e-${RUN_ID}-r"
  ip netns exec "$ns_a" tcpdump -U -s 0 -i veth-a -w "$ARTIFACT_DIR/link1.pcap" udp port 5683 >"$ARTIFACT_DIR/tcpdump-link1.log" 2>&1 &
  TCPDUMP_PIDS+=("$!")
  ip netns exec "$ns_r" tcpdump -U -s 0 -i veth-r-right -w "$ARTIFACT_DIR/link2.pcap" udp port 5683 >"$ARTIFACT_DIR/tcpdump-link2.log" 2>&1 &
  TCPDUMP_PIDS+=("$!")
  ip netns exec "$ns_r" tcpdump -U -s 0 -i veth-r-c -w "$ARTIFACT_DIR/link3-node-c.pcap" udp port 5683 >"$ARTIFACT_DIR/tcpdump-link3-node-c.log" 2>&1 &
  TCPDUMP_PIDS+=("$!")
  ip netns exec "$ns_r" tcpdump -U -s 0 -i veth-r-d -w "$ARTIFACT_DIR/link4-low-loop-node-d.pcap" udp port 5683 >"$ARTIFACT_DIR/tcpdump-link4-low-loop-node-d.log" 2>&1 &
  TCPDUMP_PIDS+=("$!")
else
  echo "tcpdump not found; pcap capture skipped" >"$ARTIFACT_DIR/tcpdump-link1.log"
fi

if [[ "$VERBOSE" -eq 1 ]]; then
  echo "Running deterministic cGRASP relay E2E scenario in artifact dir: $ARTIFACT_DIR"
fi

ns_a="cgrasp-e2e-${RUN_ID}-a"
ns_r="cgrasp-e2e-${RUN_ID}-r"
ns_b="cgrasp-e2e-${RUN_ID}-b"
ns_c="cgrasp-e2e-${RUN_ID}-c"
ns_d="cgrasp-e2e-${RUN_ID}-d"

ip netns exec "$ns_b" "$PYTHON_BIN" -u "$CASE_DIR/cgrasp_api_node.py" node-b \
  --lifetime 18 >"$ARTIFACT_DIR/node_b.log" 2>&1 &
PIDS+=("$!")
ip netns exec "$ns_r" "$PYTHON_BIN" -u "$CASE_DIR/cgrasp_api_node.py" relay-r \
  --lifetime 18 >"$ARTIFACT_DIR/relay_r.log" 2>&1 &
PIDS+=("$!")
sleep 2
set +e
ip netns exec "$ns_a" "$PYTHON_BIN" -u "$CASE_DIR/cgrasp_api_node.py" node-a \
  --lifetime 8 >"$ARTIFACT_DIR/node_a.log" 2>&1
node_a_status=$?
ip netns exec "$ns_c" "$PYTHON_BIN" -u "$CASE_DIR/cgrasp_api_node.py" node-c \
  --lifetime 8 >"$ARTIFACT_DIR/node_c.log" 2>&1
node_c_status=$?
ip netns exec "$ns_d" "$PYTHON_BIN" -u "$CASE_DIR/cgrasp_api_node.py" node-d \
  --lifetime 8 >"$ARTIFACT_DIR/node_d.log" 2>&1
node_d_status=$?
set -e
if [[ "$node_a_status" -ne 0 || "$node_c_status" -ne 0 || "$node_d_status" -ne 0 ]]; then
  RUN_STATUS=1
fi
sleep 1

set +e
"$PYTHON_BIN" "$CASE_DIR/relay_e2e_simulation.py" --artifact-dir "$ARTIFACT_DIR" \
  >"$ARTIFACT_DIR/scenario.log" 2>&1
scenario_status=$?
"$PYTHON_BIN" "$CASE_DIR/validate_relay_e2e.py" "$ARTIFACT_DIR" \
  >"$ARTIFACT_DIR/result.txt" 2>&1
validate_status=$?
set -e
if [[ "$scenario_status" -ne 0 || "$validate_status" -ne 0 ]]; then
  RUN_STATUS=1
fi

for pid in "${TCPDUMP_PIDS[@]}"; do
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
done
TCPDUMP_PIDS=()

if "$CASE_DIR/render_pcaps.sh" "$ARTIFACT_DIR" "$ARTIFACT_DIR/cgrasp-relay-readable.txt" relay \
  >"$ARTIFACT_DIR/render_pcaps.log" 2>&1; then
  PCAP_RENDERED=1
else
  render_status=$?
  if [[ "$render_status" -eq 77 ]]; then
    echo "pcap rendering skipped; tshark not available" >"$ARTIFACT_DIR/cgrasp-relay-readable.txt"
  else
    echo "pcap rendering failed; see render_pcaps.log" >"$ARTIFACT_DIR/cgrasp-relay-readable.txt"
  fi
fi

cat >"$ARTIFACT_DIR/run_status.json" <<EOF
{
  "node_a": $node_a_status,
  "node_c": $node_c_status,
  "node_d": $node_d_status,
  "scenario": $scenario_status,
  "validate": $validate_status,
  "overall": $RUN_STATUS
}
EOF

if [[ "$RUN_STATUS" -eq 0 ]]; then
cat <<EOF
cGRASP relay end-to-end validation: PASS

Discovery:
  A -> R -> B: PASS
  B -> R -> A response: PASS

Relay cache:
  insert: PASS
  response lookup: PASS
  duplicate suppression: PASS
  expiration: PASS

Unicast:
  negotiation A <-> B: PASS
  synchronization A <-> B: PASS

Flood:
  A -> R -> B: PASS
  duplicate suppression: PASS
  loop-count boundary: PASS

Artifacts:
  $ARTIFACT_DIR
EOF
else
cat <<EOF
cGRASP relay end-to-end validation: FAIL

Node/process status:
  node_a: $node_a_status
  node_c: $node_c_status
  node_d: $node_d_status
  scenario: $scenario_status
  validate: $validate_status

Artifacts:
  $ARTIFACT_DIR
EOF
fi

if [[ "$PCAP_RENDERED" -eq 1 ]]; then
  echo "Readable pcap report:"
  echo "  $ARTIFACT_DIR/cgrasp-relay-readable.txt"
else
  echo "Readable pcap report or render note:"
  echo "  $ARTIFACT_DIR/cgrasp-relay-readable.txt"
fi

exit "$RUN_STATUS"
