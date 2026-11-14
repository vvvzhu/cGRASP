#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
CAPTURE="${1:-captures/coap-integration.pcap}"
if [[ "$CAPTURE" == *.* ]]; then
  DEFAULT_REPORT="${CAPTURE%.*}.txt"
else
  DEFAULT_REPORT="${CAPTURE}.txt"
fi
HUMAN_REPORT="${2:-$DEFAULT_REPORT}"
if [[ "$HUMAN_REPORT" == "$CAPTURE" ]]; then
  echo "FAIL: human-readable report path must differ from capture path" >&2
  exit 2
fi
mkdir -p "$(dirname "$CAPTURE")"
mkdir -p "$(dirname "$HUMAN_REPORT")"

# 15683 is the initiator callback endpoint used only because both test nodes
# run on one host and cannot bind local UDP/5683 simultaneously. Do not use
# 5684 here: it is the registered CoAPS/DTLS port.
tcpdump -i any -U -s 0 -w "$CAPTURE" '(udp port 5683) or (udp port 15683) or (tcp port 7017) or (udp port 7017) or (tcp port 7018) or (udp port 7018)' &
TCPDUMP_PID=$!
cleanup() {
  if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
sleep 1
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
  wait "$TCPDUMP_PID" || true
  echo "FAIL: tcpdump did not start; packet-capture privileges are required" >&2
  exit 1
fi

set +e
"$PYTHON_BIN" -m unittest -v tests.test_coap_integration
TEST_STATUS=$?
set -e
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
  wait "$TCPDUMP_PID" || true
  echo "FAIL: tcpdump terminated before the integration suite completed" >&2
  exit 1
fi
# Let packet-buffered tcpdump commit the final test's request/response before
# sending SIGINT. This is especially relevant for the last callback exchange.
sleep 1
cleanup
trap - EXIT

if [[ "$TEST_STATUS" -ne 0 ]]; then
  echo "FAIL: integration tests failed; capture is not accepted as proof" >&2
  exit "$TEST_STATUS"
fi

if tshark -r "$CAPTURE" -Y 'tcp.port == 7017 || udp.port == 7017 || tcp.port == 7018 || udp.port == 7018' -T fields -e frame.number | grep -q .; then
  echo "FAIL: legacy 7017/7018 traffic found in $CAPTURE" >&2
  exit 1
fi

if ! tshark -r "$CAPTURE" -Y 'udp.port == 5683' -T fields -e frame.number | grep -q .; then
  echo "FAIL: no UDP/5683 traffic found in $CAPTURE" >&2
  exit 1
fi

if tshark -r "$CAPTURE" -Y 'coap.opt.uri_path == "dr"' -T fields -e frame.number | grep -q .; then
  echo "FAIL: obsolete /cgrasp/dr callback traffic found" >&2
  exit 1
fi

"$PYTHON_BIN" scripts/check_multicast_pcap.py "$CAPTURE"

if ! tshark -r "$CAPTURE" -Y 'coap.opt.block_number' -T fields -e frame.number | grep -q .; then
  echo "FAIL: large-payload test produced no CoAP Block1/Block2 options" >&2
  exit 1
fi

# Generate the compact human-readable interaction format used by the
# historical res1_*.txt files. Decode-as makes the non-standard callback port
# available to the CoAP/CBOR dissectors too.
TSHARK_VERBOSE=$(mktemp)
trap 'rm -f "$TSHARK_VERBOSE"' EXIT
tshark -d udp.port==15683,coap -r "$CAPTURE" -V > "$TSHARK_VERBOSE"
"$PYTHON_BIN" parse_tshark_v_coap_cgrasp.py "$TSHARK_VERBOSE" -o "$HUMAN_REPORT"
rm -f "$TSHARK_VERBOSE"
trap - EXIT

if [[ ! -s "$HUMAN_REPORT" ]] || ! grep -q 'cGRASP:' "$HUMAN_REPORT"; then
  echo "FAIL: human-readable interaction report was not generated correctly: $HUMAN_REPORT" >&2
  exit 1
fi

if grep -q 'M_WAIT' "$HUMAN_REPORT"; then
  echo "FAIL: baseline cGRASP profile emitted M_WAIT" >&2
  exit 1
fi

echo "PASS: baseline cGRASP (M_WAIT unsupported), UDP/5683, and CoAP Blockwise present; no TCP/UDP 7017/7018 traffic found: $CAPTURE"
echo "REPORT: human-readable CoAP/cGRASP interactions: $HUMAN_REPORT"
