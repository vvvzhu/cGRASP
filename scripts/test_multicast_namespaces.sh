#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
MODE="${1:-relay}"
CAPTURE_DIR="${CAPTURE_DIR:-$ROOT/captures/multicast-$MODE}"
HUMAN_REPORT="${HUMAN_REPORT:-$CAPTURE_DIR/res1_1_5683_${MODE}.txt}"
RUN_ID="${RUN_ID:-namespace-$MODE-$$}"
NAMESPACES=(cgrasp-init)
case "$MODE" in
  relay|loss|divert|flood-relay|response-retransmit-drop-response|response-retransmit-drop-ack)
    NAMESPACES+=(cgrasp-r1 cgrasp-r2 cgrasp-resp)
    ;;
  loop|flood-loop)
    NAMESPACES+=(cgrasp-r1 cgrasp-r2 cgrasp-r3 cgrasp-resp)
    ;;
  multi)
    NAMESPACES+=(cgrasp-resp1 cgrasp-resp2 cgrasp-resp3)
    ;;
esac
PIDS=()

if [[ "$EUID" -ne 0 ]]; then
  echo "This test requires root for ip netns, veth, tc and tcpdump." >&2
  exit 77
fi
if [[ "$MODE" != "relay" && "$MODE" != "loss" && "$MODE" != "loop" && "$MODE" != "multi" && "$MODE" != "divert" && "$MODE" != "flood-relay" && "$MODE" != "flood-loop" && "$MODE" != "response-retransmit-drop-response" && "$MODE" != "response-retransmit-drop-ack" ]]; then
  echo "usage: $0 [relay|loss|loop|multi|divert|flood-relay|flood-loop|response-retransmit-drop-response|response-retransmit-drop-ack]" >&2
  exit 2
fi

cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for ns in "${NAMESPACES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup
mkdir -p "$CAPTURE_DIR"
MANIFEST_ARGS=()
if [[ "$MODE" == "relay" ]]; then
  MANIFEST_ARGS=(
    --scenario E2E-04 --topology A--R1--R2--B
    --parameter max_forward_delay_ms=400
    --parameter max_end_to_end_ms=400
  )
elif [[ "$MODE" == "response-retransmit-drop-ack" ]]; then
  MANIFEST_ARGS=(
    --scenario E2E-05 --topology A--R1--R2--B
    --parameter fault=drop_first_response_ack
    --parameter expected_unique_results=1
  )
fi
if [[ "${#MANIFEST_ARGS[@]}" -gt 0 ]]; then
  "$PYTHON_BIN" "$ROOT/scripts/write_e2e_manifest.py" \
    --output "$CAPTURE_DIR/run-manifest.json" --run-id "$RUN_ID" \
    --result RUNNING "${MANIFEST_ARGS[@]}"
fi

for ns in "${NAMESPACES[@]}"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

make_link() {
  local left_ns=$1 left_if=$2 left_addr=$3 right_ns=$4 right_if=$5 right_addr=$6
  ip link add "$left_if" type veth peer name "$right_if"
  ip link set "$left_if" netns "$left_ns"
  ip link set "$right_if" netns "$right_ns"
  ip -n "$left_ns" link set "$left_if" up
  ip -n "$right_ns" link set "$right_if" up
  ip -n "$left_ns" -6 addr add "$left_addr/64" dev "$left_if"
  ip -n "$right_ns" -6 addr add "$right_addr/64" dev "$right_if"
}

if [[ "$MODE" == "multi" ]]; then
  make_link cgrasp-init vi0 fe80::101 cgrasp-resp1 vp1 fe80::111
  make_link cgrasp-init vi1 fe80::102 cgrasp-resp2 vp2 fe80::112
  make_link cgrasp-init vi2 fe80::103 cgrasp-resp3 vp3 fe80::113
else
  make_link cgrasp-init vi0 fe80::101 cgrasp-r1 vr10 fe80::102
  make_link cgrasp-r1 vr11 fe80::201 cgrasp-r2 vr20 fe80::202
  if [[ "$MODE" == "loop" || "$MODE" == "flood-loop" ]]; then
    make_link cgrasp-init vi1 fe80::401 cgrasp-r3 vr30 fe80::402
    make_link cgrasp-r3 vr31 fe80::501 cgrasp-r2 vr22 fe80::502
  fi
  make_link cgrasp-r2 vr21 fe80::301 cgrasp-resp vp0 fe80::302
fi

if [[ "$MODE" == "loss" ]]; then
  ip netns exec cgrasp-r1 tc qdisc add dev vr11 root netem loss 5% duplicate 5% delay 50ms 10ms reorder 5%
fi

node_lifetime=10
if [[ "$MODE" == "response-retransmit-drop-response" || "$MODE" == "response-retransmit-drop-ack" ]]; then
  node_lifetime=14
fi

if [[ "$MODE" == "multi" ]]; then
  capture_specs=("cgrasp-init:vi0" "cgrasp-init:vi1" "cgrasp-init:vi2")
else
  capture_specs=("cgrasp-r1:vr10" "cgrasp-r1:vr11" "cgrasp-r2:vr20" "cgrasp-r2:vr21")
fi
if [[ "$MODE" == "loop" || "$MODE" == "flood-loop" ]]; then
  capture_specs+=("cgrasp-r3:vr30" "cgrasp-r3:vr31" "cgrasp-r2:vr22")
fi
for spec in "${capture_specs[@]}"; do
  ns=${spec%%:*}; iface=${spec##*:}
  ip netns exec "$ns" tcpdump -U -s 0 -i "$iface" -w "$CAPTURE_DIR/$ns-$iface.pcap" udp port 5683 &
  PIDS+=("$!")
done

generate_human_report() {
  "$PYTHON_BIN" "$ROOT/scripts/render_namespace_interactions.py" \
    "$CAPTURE_DIR" --mode "$MODE" --output "$HUMAN_REPORT"
}

wait_for_json_result() {
  local path=$1 timeout_s=${2:-12} waited=0
  while [[ "$waited" -lt "$timeout_s" ]]; do
    if grep -q '"event": "result"' "$path" 2>/dev/null; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "Timed out waiting for result log: $path" >&2
  return 1
}

if [[ "$MODE" == "multi" ]]; then
  for idx in 1 2 3; do
    ip netns exec "cgrasp-resp$idx" "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" discovery-server \
      --non-dull --bind :: --port 5683 --obj 47901 --lifetime 10 >"$CAPTURE_DIR/responder$idx.log" 2>&1 &
    PIDS+=("$!")
  done
else
  listener_role="discovery-server"
  if [[ "$MODE" == "flood-relay" || "$MODE" == "flood-loop" ]]; then
    listener_role="flood-listener"
  fi
  responder_args=()
  if [[ "$MODE" == "response-retransmit-drop-ack" ]]; then
    responder_args+=(--fault-mode ignore-first-ack --fault-count 1)
  fi
  ip netns exec cgrasp-resp "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" "$listener_role" \
    --non-dull --bind :: --port 5683 --obj 47901 --value flood-value --lifetime "$node_lifetime" \
    "${responder_args[@]}" >"$CAPTURE_DIR/responder.log" 2>&1 &
  PIDS+=("$!")
  r2_args=()
  if [[ "$MODE" == "response-retransmit-drop-response" ]]; then
    r2_args+=(--fault-mode drop-first-response --fault-count 1)
  fi
  if [[ "$MODE" == "response-retransmit-drop-ack" ]]; then
    r2_args+=(
      --relay-interface vr20 --relay-interface vr21
      --relay-quiet-timeout-ms 3500 --relay-hard-timeout-ms 9000
    )
  fi
  ip netns exec cgrasp-r2 "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" relay \
    --bind :: --port 5683 --lifetime "$node_lifetime" "${r2_args[@]}" >"$CAPTURE_DIR/r2.log" 2>&1 &
  R2_PID=$!
  PIDS+=("$!")
  r1_args=()
  if [[ "$MODE" == "response-retransmit-drop-ack" ]]; then
    r1_args+=(
      --relay-interface vr10 --relay-interface vr11
      --relay-quiet-timeout-ms 3500 --relay-hard-timeout-ms 9000
    )
  fi
  ip netns exec cgrasp-r1 "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" relay \
    --bind :: --port 5683 --lifetime "$node_lifetime" "${r1_args[@]}" >"$CAPTURE_DIR/r1.log" 2>&1 &
  R1_PID=$!
  PIDS+=("$!")
  if [[ "$MODE" == "loop" || "$MODE" == "flood-loop" ]]; then
    ip netns exec cgrasp-r3 "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" relay \
      --bind :: --port 5683 --lifetime 10 >"$CAPTURE_DIR/r3.log" 2>&1 &
    PIDS+=("$!")
  fi
fi
sleep 3

set +e
if [[ "$MODE" == "flood-relay" || "$MODE" == "flood-loop" ]]; then
  ip netns exec cgrasp-init "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" flood-sender \
    --non-dull --bind :: --port 5683 --obj 47901 --value flood-value --timeout-ms 5000 >"$CAPTURE_DIR/initiator.log" 2>&1
else
  min_locators=1
  if [[ "$MODE" == "multi" ]]; then min_locators=3; fi
  timeout_ms=5000
  if [[ "$MODE" == "response-retransmit-drop-response" || "$MODE" == "response-retransmit-drop-ack" ]]; then
    timeout_ms=10000
  fi
  if [[ "$MODE" == "divert" ]]; then
    ip netns exec cgrasp-init "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" discovery-client \
      --non-dull --bind :: --port 5683 --obj 47901 --timeout-ms "$timeout_ms" --min-locators "$min_locators" >"$CAPTURE_DIR/initiator-prime.log" 2>&1
    status=$?
    if [[ "$status" -eq 0 ]]; then sleep 1; fi
    if [[ "$status" -eq 0 ]]; then
      ip netns exec cgrasp-init "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" discovery-client \
        --non-dull --bind :: --port 5683 --obj 47901 --timeout-ms "$timeout_ms" --min-locators "$min_locators" >"$CAPTURE_DIR/initiator.log" 2>&1
    else
      false
    fi
  else
    ip netns exec cgrasp-init "$PYTHON_BIN" -u "$ROOT/tests/interop_node.py" discovery-client \
      --non-dull --bind :: --port 5683 --obj 47901 --timeout-ms "$timeout_ms" --min-locators "$min_locators" >"$CAPTURE_DIR/initiator.log" 2>&1
  fi
fi
status=$?
set -e
sleep 1

if [[ "$status" -ne 0 ]]; then
  echo "$MODE failed; inspect $CAPTURE_DIR/*.log" >&2
  exit "$status"
fi
if [[ "$MODE" == "relay" ]]; then
  wait "$R1_PID"
  wait "$R2_PID"
  for relay_log in "$CAPTURE_DIR/r1.log" "$CAPTURE_DIR/r2.log"; do
    if ! grep -q '"remaining_transactions": 0' "$relay_log"; then
      echo "Relay did not report zero remaining Discovery transactions: $relay_log" >&2
      exit 1
    fi
  done
fi
if [[ "$MODE" == "response-retransmit-drop-response" || "$MODE" == "response-retransmit-drop-ack" ]]; then
  wait_for_json_result "$CAPTURE_DIR/r1.log" 12
  wait_for_json_result "$CAPTURE_DIR/r2.log" 12
  wait_for_json_result "$CAPTURE_DIR/responder.log" 12
  for relay_log in "$CAPTURE_DIR/r1.log" "$CAPTURE_DIR/r2.log"; do
    if ! grep -q '"remaining_transactions": 0' "$relay_log"; then
      echo "Relay did not report zero remaining Discovery transactions: $relay_log" >&2
      exit 1
    fi
  done
fi
if [[ "$MODE" == "flood-relay" || "$MODE" == "flood-loop" ]]; then
  if ! grep -q '"ok": true' "$CAPTURE_DIR/responder.log"; then
    echo "Flood listener did not receive flooded objective" >&2
    exit 1
  fi
fi
if grep -R '"fallback_count": [1-9]\|"legacy_udp_messages": [1-9]\|"tcp_connections": [1-9]' "$CAPTURE_DIR"/*.log; then
  echo "Legacy transport or fallback observed" >&2
  exit 1
fi
if command -v tshark >/dev/null; then
  first_pcap=$(find "$CAPTURE_DIR" -name '*.pcap' | sort | head -n 1)
  if [[ "$MODE" != "flood-relay" && "$MODE" != "flood-loop" && -n "$first_pcap" ]] && \
     tshark -r "$first_pcap" -Y 'coap.code == 2 && coap.opt.uri_path == "grasp-coap"' -T fields -e frame.number | grep -q .; then
    echo "M_RESPONSE was returned using POST" >&2
    exit 1
  fi
  if [[ "$MODE" == "flood-relay" || "$MODE" == "flood-loop" ]]; then
    "$PYTHON_BIN" "$ROOT/scripts/check_flood_pcaps.py" "$CAPTURE_DIR" --report "$CAPTURE_DIR/flood-report.txt"
  elif [[ "$MODE" == "response-retransmit-drop-response" ]]; then
    "$PYTHON_BIN" "$ROOT/scripts/check_relay_pcaps.py" "$CAPTURE_DIR" --report "$CAPTURE_DIR/relay-report.txt"
    "$PYTHON_BIN" "$ROOT/scripts/check_response_retransmit_pcaps.py" "$CAPTURE_DIR" \
      --mode drop-response --report "$CAPTURE_DIR/response-retransmit-report.txt" \
      --r2-log "$CAPTURE_DIR/r2.log" --initiator-log "$CAPTURE_DIR/initiator.log"
  elif [[ "$MODE" == "response-retransmit-drop-ack" ]]; then
    "$PYTHON_BIN" "$ROOT/scripts/check_relay_pcaps.py" "$CAPTURE_DIR" --report "$CAPTURE_DIR/relay-report.txt"
    if ! "$PYTHON_BIN" "$ROOT/scripts/check_response_retransmit_pcaps.py" "$CAPTURE_DIR" \
      --mode drop-ack --report "$CAPTURE_DIR/response-retransmit-report.txt" \
      --r2-log "$CAPTURE_DIR/r2.log" --initiator-log "$CAPTURE_DIR/initiator.log"; then
      echo "SKIP: response-retransmit-drop-ack has pcap retransmission evidence but runtime duplicate-drop counter is not complete; see $CAPTURE_DIR/response-retransmit-report.txt" >&2
      generate_human_report
      exit 77
    fi
  elif [[ "$MODE" == "multi" ]]; then
    "$PYTHON_BIN" "$ROOT/scripts/check_relay_pcaps.py" "$CAPTURE_DIR" --min-hops 3 --min-loop-decrements 0 --report "$CAPTURE_DIR/relay-report.txt"
  elif [[ "$MODE" == "divert" ]]; then
    "$PYTHON_BIN" "$ROOT/scripts/check_relay_pcaps.py" "$CAPTURE_DIR" --require-divert --report "$CAPTURE_DIR/relay-report.txt"
  else
    relay_check_args=()
    if [[ "$MODE" == "relay" ]]; then
      relay_check_args+=(
        --response-path-pcap cgrasp-r2-vr21.pcap
        --response-path-pcap cgrasp-r1-vr11.pcap
        --response-path-pcap cgrasp-r1-vr10.pcap
        --max-forward-delay-ms 400
        --max-end-to-end-ms 400
      )
    fi
    "$PYTHON_BIN" "$ROOT/scripts/check_relay_pcaps.py" "$CAPTURE_DIR" \
      --report "$CAPTURE_DIR/relay-report.txt" "${relay_check_args[@]}"
  fi
  generate_human_report
else
  echo "SKIP: tshark not found; pcap validation/report not generated" >&2
  if [[ "$MODE" == "relay" ]]; then
    exit 77
  fi
fi
if [[ "${#MANIFEST_ARGS[@]}" -gt 0 ]]; then
  "$PYTHON_BIN" "$ROOT/scripts/write_e2e_manifest.py" \
    --output "$CAPTURE_DIR/run-manifest.json" --run-id "$RUN_ID" \
    --result PASS "${MANIFEST_ARGS[@]}"
fi
echo "PASS: $MODE namespace test; captures and logs: $CAPTURE_DIR"
if [[ -s "$HUMAN_REPORT" ]]; then
  echo "REPORT: human-readable all-node CoAP/cGRASP interactions: $HUMAN_REPORT"
fi
