#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
set -euo pipefail

RUN_ID="${1:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "cleanup_netns.sh requires root for ip netns cleanup." >&2
  exit 77
fi
command -v ip >/dev/null || {
  echo "missing dependency: ip" >&2
  exit 127
}

if [[ -n "$RUN_ID" ]]; then
  for suffix in a r b c d; do
    ip netns del "cgrasp-e2e-${RUN_ID}-${suffix}" 2>/dev/null || true
  done
else
  while read -r ns; do
    case "$ns" in
      cgrasp-e2e-*-a|cgrasp-e2e-*-r|cgrasp-e2e-*-b|cgrasp-e2e-*-c|cgrasp-e2e-*-d)
        ip netns del "$ns" 2>/dev/null || true
        ;;
    esac
  done < <(ip netns list | awk '{print $1}')
fi
