#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
# A--R--B or A--R--{B,C}: replies return from R with A's one token.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${PYTHON_BIN:-}" ]]; then
  # Prefer the repository virtualenv when it exists so manual runs do not
  # silently fall back to a system Python without aiocoap/dpkt.
  if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi
CAPTURE_DIR="${CAPTURE_DIR:-$ROOT/captures/relay-multi}"
RUN_ID="${RUN_ID:-wp4-$$}"
RESPONDER_COUNT="${RESPONDER_COUNT:-2}"
TEST_MODE="${TEST_MODE:-normal}"
NS_A="cgrasp-${RUN_ID}-a"
NS_R="cgrasp-${RUN_ID}-r"
NS_B="cgrasp-${RUN_ID}-b"
NS_C="cgrasp-${RUN_ID}-c"
PIDS=()
NAMESPACES=("$NS_A" "$NS_R" "$NS_B")
MANIFEST_STARTED=0
MANIFEST_PARAMETERS=()

if [[ "$RESPONDER_COUNT" != "1" && "$RESPONDER_COUNT" != "2" ]]; then
  echo "RESPONDER_COUNT must be 1 or 2" >&2
  exit 2
fi
if [[ "$TEST_MODE" != "normal" && "$TEST_MODE" != "late-response" ]]; then
  echo "TEST_MODE must be normal or late-response" >&2
  exit 2
fi
if [[ "$TEST_MODE" == "late-response" && "$RESPONDER_COUNT" != "1" ]]; then
  echo "late-response mode requires RESPONDER_COUNT=1" >&2
  exit 2
fi
if [[ "$RESPONDER_COUNT" == "2" ]]; then
  NAMESPACES+=("$NS_C")
fi

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
      --scenario "$SCENARIO" --topology "$TOPOLOGY" --result FAIL \
      "${MANIFEST_PARAMETERS[@]}" \
      --parameter "max_forward_delay_ms=400" || true
  fi
  return "$status"
}
trap cleanup EXIT
cleanup
mkdir -p "$CAPTURE_DIR"
SCENARIO="E2E-02"
TOPOLOGY="A--R--B"
MANIFEST_PARAMETERS=(--parameter "responder_count=$RESPONDER_COUNT")
if [[ "$TEST_MODE" == "late-response" ]]; then
  SCENARIO="E2E-06"
  MANIFEST_PARAMETERS+=(
    --parameter responder_egress_delay_ms=2000
    --parameter relay_hard_timeout_ms=500
  )
elif [[ "$RESPONDER_COUNT" == "2" ]]; then
  SCENARIO="E2E-03"
  TOPOLOGY="A--R--{B,C}"
fi
"$PYTHON_BIN" "$ROOT/scripts/write_e2e_manifest.py" \
  --output "$CAPTURE_DIR/run-manifest.json" --run-id "$RUN_ID" \
  --scenario "$SCENARIO" --topology "$TOPOLOGY" --result RUNNING \
  "${MANIFEST_PARAMETERS[@]}" \
  --parameter "max_forward_delay_ms=400"
MANIFEST_STARTED=1

for ns in "${NAMESPACES[@]}"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

link() {
  local left_ns=$1 left_if=$2 left_addr=$3 right_ns=$4 right_if=$5 right_addr=$6
  local left_mac=${7:-} right_mac=${8:-}
  ip link add "$left_if" type veth peer name "$right_if"
  ip link set "$left_if" netns "$left_ns"
  ip link set "$right_if" netns "$right_ns"
  if [[ -n "$left_mac" ]]; then
    ip -n "$left_ns" link set "$left_if" address "$left_mac"
  fi
  if [[ -n "$right_mac" ]]; then
    ip -n "$right_ns" link set "$right_if" address "$right_mac"
  fi
  ip -n "$left_ns" link set "$left_if" up
  ip -n "$right_ns" link set "$right_if" up
  ip -n "$left_ns" -6 addr add "$left_addr/64" dev "$left_if"
  ip -n "$right_ns" -6 addr add "$right_addr/64" dev "$right_if"
}

link "$NS_A" va0 fe80::101 "$NS_R" vr0 fe80::102
link "$NS_R" vr1 fe80::201 "$NS_B" vb0 fe80::202 \
  02:00:00:00:02:01 02:00:00:00:02:02
if [[ "$RESPONDER_COUNT" == "2" ]]; then
  link "$NS_R" vr2 fe80::301 "$NS_C" vc0 fe80::302
fi
if [[ "$TEST_MODE" == "late-response" ]]; then
  # Keep IPv6 neighbor discovery outside the delayed data path. Deterministic
  # veth MACs make the setup independent of ICMP echo availability.
  ip -n "$NS_R" -6 neigh replace fe80::202 \
    lladdr 02:00:00:00:02:02 nud permanent dev vr1
  ip -n "$NS_B" -6 neigh replace fe80::201 \
    lladdr 02:00:00:00:02:01 nud permanent dev vb0
  ip netns exec "$NS_B" tc qdisc add dev vb0 root netem delay 2000ms
fi

CAPTURE_SPECS=("relay-left:vr0" "relay-b:vr1")
RESPONDER_SPECS=("$NS_B:responder-b")
DOWNSTREAM_ARGS=(--downstream-pcap relay-b.pcap)
if [[ "$RESPONDER_COUNT" == "2" ]]; then
  CAPTURE_SPECS+=("relay-c:vr2")
  RESPONDER_SPECS+=("$NS_C:responder-c")
  DOWNSTREAM_ARGS+=(--downstream-pcap relay-c.pcap)
fi
for spec in "${CAPTURE_SPECS[@]}"; do
  name=${spec%%:*}; iface=${spec##*:}
  ip netns exec "$NS_R" tcpdump -U -s 0 -i "$iface" -w "$CAPTURE_DIR/$name.pcap" udp port 5683 \
    >"$CAPTURE_DIR/$name.tcpdump.log" 2>&1 &
  PIDS+=("$!")
done

for spec in "${RESPONDER_SPECS[@]}"; do
  ns=${spec%%:*}; name=${spec##*:}
  ip netns exec "$ns" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" discovery-server \
    --non-dull --bind :: --port 5683 --obj 47901 --lifetime 12 >"$CAPTURE_DIR/$name.log" 2>&1 &
  PIDS+=("$!")
done
RELAY_ARGS=()
if [[ "$TEST_MODE" == "late-response" ]]; then
  RELAY_ARGS+=(
    --relay-interface vr0 --relay-interface vr1
    --relay-quiet-timeout-ms 200 --relay-hard-timeout-ms 500
  )
fi
ip netns exec "$NS_R" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" relay \
  --bind :: --port 5683 --lifetime 12 "${RELAY_ARGS[@]}" >"$CAPTURE_DIR/relay.log" 2>&1 &
RELAY_PID=$!
PIDS+=("$RELAY_PID")
sleep 3

if [[ "$TEST_MODE" == "late-response" ]]; then
  ip netns exec "$NS_A" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" discovery-client-none \
    --non-dull --bind :: --port 5683 --obj 47901 --timeout-ms 3000 \
    >"$CAPTURE_DIR/initiator.log" 2>&1
else
  ip netns exec "$NS_A" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" discovery-client \
    --non-dull --bind :: --port 5683 --obj 47901 --timeout-ms 7000 \
    --min-locators "$RESPONDER_COUNT" \
    >"$CAPTURE_DIR/initiator.log" 2>&1
fi

if grep -R '"fallback_count": [1-9]\|"legacy_udp_messages": [1-9]\|"tcp_connections": [1-9]' "$CAPTURE_DIR"/*.log; then
  echo "Legacy transport or fallback observed" >&2
  exit 1
fi
# Let the relay exit normally so its final state snapshot is durable evidence,
# rather than terminating it from the EXIT cleanup trap before it can report.
wait "$RELAY_PID"
if ! grep -q '"remaining_transactions": 0' "$CAPTURE_DIR/relay.log"; then
  echo "Relay did not report zero remaining Discovery transactions" >&2
  exit 1
fi
sleep 1
if [[ "$TEST_MODE" == "late-response" ]]; then
  "$PYTHON_BIN" "$ROOT/scripts/check_late_response_pcaps.py" "$CAPTURE_DIR" \
    --report "$CAPTURE_DIR/late-response-report.txt" \
    --relay-log "$CAPTURE_DIR/relay.log" \
    --initiator-log "$CAPTURE_DIR/initiator.log" \
    --min-late-delay-ms 1000 \
    --expected-relay-hard-timeout-ms 500 \
    --expected-relay-quiet-timeout-ms 200
else
  "$PYTHON_BIN" "$ROOT/scripts/check_relay_multi_pcaps.py" "$CAPTURE_DIR" \
    --report "$CAPTURE_DIR/relay-multi-report.txt" --max-forward-delay-ms 400 \
    --expected-responses "$RESPONDER_COUNT" "${DOWNSTREAM_ARGS[@]}"
fi
"$PYTHON_BIN" "$ROOT/scripts/render_namespace_interactions.py" "$CAPTURE_DIR" \
  --mode relay-multi --output "$CAPTURE_DIR/res1_1_5683_relay_multi.txt"
"$PYTHON_BIN" "$ROOT/scripts/write_e2e_manifest.py" \
  --output "$CAPTURE_DIR/run-manifest.json" --run-id "$RUN_ID" \
  --scenario "$SCENARIO" --topology "$TOPOLOGY" --result PASS \
  "${MANIFEST_PARAMETERS[@]}" \
  --parameter "max_forward_delay_ms=400"
echo "PASS: relay namespace test mode=$TEST_MODE with $RESPONDER_COUNT responder(s); captures: $CAPTURE_DIR"
echo "REPORT: $CAPTURE_DIR/res1_1_5683_relay_multi.txt"
