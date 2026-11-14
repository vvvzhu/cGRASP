#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
CAPTURE_DIR="${1:?capture/artifact directory required}"
OUTPUT="${2:-$CAPTURE_DIR/cgrasp-relay-readable.txt}"
MODE="${3:-relay}"

if [[ ! -d "$CAPTURE_DIR" ]]; then
  echo "capture directory does not exist: $CAPTURE_DIR" >&2
  exit 2
fi
if ! command -v tshark >/dev/null; then
  echo "SKIP: tshark is required to render pcap files" >&2
  exit 77
fi
if ! find "$CAPTURE_DIR" -maxdepth 1 -name '*.pcap' -size +24c | grep -q .; then
  mkdir -p "$(dirname "$OUTPUT")"
  {
    echo "No non-empty pcap files were available for rendering."
    echo "Capture directory: $CAPTURE_DIR"
  } >"$OUTPUT"
  echo "REPORT: no non-empty pcap files; wrote note to $OUTPUT"
  exit 0
fi

"$PYTHON_BIN" "$ROOT/scripts/render_namespace_interactions.py" \
  "$CAPTURE_DIR" --mode "$MODE" --output "$OUTPUT"
