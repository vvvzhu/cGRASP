#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
set -euo pipefail

RUN_ID="${1:?run id required}"
PREFIX="cgrasp-e2e-${RUN_ID}"
NS_A="${PREFIX}-a"
NS_R="${PREFIX}-r"
NS_B="${PREFIX}-b"
NS_C="${PREFIX}-c"
NS_D="${PREFIX}-d"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "setup_netns.sh requires root for ip netns and veth setup." >&2
    exit 77
  fi
}

require_cmd() {
  command -v "$1" >/dev/null || {
    echo "missing dependency: $1" >&2
    exit 127
  }
}

require_root
require_cmd ip

ip netns add "$NS_A"
ip netns add "$NS_R"
ip netns add "$NS_B"
ip netns add "$NS_C"
ip netns add "$NS_D"

ip -n "$NS_A" link set lo up
ip -n "$NS_R" link set lo up
ip -n "$NS_B" link set lo up
ip -n "$NS_C" link set lo up
ip -n "$NS_D" link set lo up

ip link add veth-a type veth peer name veth-r-left
ip link set veth-a netns "$NS_A"
ip link set veth-r-left netns "$NS_R"

ip link add veth-r-right type veth peer name veth-b
ip link set veth-r-right netns "$NS_R"
ip link set veth-b netns "$NS_B"

ip link add veth-r-c type veth peer name veth-c
ip link set veth-r-c netns "$NS_R"
ip link set veth-c netns "$NS_C"

ip link add veth-r-d type veth peer name veth-d
ip link set veth-r-d netns "$NS_R"
ip link set veth-d netns "$NS_D"

ip -n "$NS_A" link set veth-a up
ip -n "$NS_R" link set veth-r-left up
ip -n "$NS_R" link set veth-r-right up
ip -n "$NS_R" link set veth-r-c up
ip -n "$NS_R" link set veth-r-d up
ip -n "$NS_B" link set veth-b up
ip -n "$NS_C" link set veth-c up
ip -n "$NS_D" link set veth-d up

ip -n "$NS_A" -6 addr add fd00:1::1/64 dev veth-a nodad
ip -n "$NS_R" -6 addr add fd00:1::fe/64 dev veth-r-left nodad
ip -n "$NS_R" -6 addr add fd00:2::fe/64 dev veth-r-right nodad
ip -n "$NS_R" -6 addr add fd00:3::fe/64 dev veth-r-c nodad
ip -n "$NS_R" -6 addr add fd00:4::fe/64 dev veth-r-d nodad
ip -n "$NS_B" -6 addr add fd00:2::1/64 dev veth-b nodad
ip -n "$NS_C" -6 addr add fd00:3::1/64 dev veth-c nodad
ip -n "$NS_D" -6 addr add fd00:4::1/64 dev veth-d nodad

ip -n "$NS_A" -6 route add fd00:2::/64 via fd00:1::fe dev veth-a
ip -n "$NS_A" -6 route add fd00:3::/64 via fd00:1::fe dev veth-a
ip -n "$NS_A" -6 route add fd00:4::/64 via fd00:1::fe dev veth-a
ip -n "$NS_B" -6 route add fd00:1::/64 via fd00:2::fe dev veth-b
ip -n "$NS_B" -6 route add fd00:3::/64 via fd00:2::fe dev veth-b
ip -n "$NS_B" -6 route add fd00:4::/64 via fd00:2::fe dev veth-b
ip -n "$NS_C" -6 route add fd00:1::/64 via fd00:3::fe dev veth-c
ip -n "$NS_C" -6 route add fd00:2::/64 via fd00:3::fe dev veth-c
ip -n "$NS_C" -6 route add fd00:4::/64 via fd00:3::fe dev veth-c
ip -n "$NS_D" -6 route add fd00:1::/64 via fd00:4::fe dev veth-d
ip -n "$NS_D" -6 route add fd00:2::/64 via fd00:4::fe dev veth-d
ip -n "$NS_D" -6 route add fd00:3::/64 via fd00:4::fe dev veth-d
ip netns exec "$NS_R" sysctl -q -w net.ipv6.conf.all.forwarding=1

cat <<EOF
${NS_A}
${NS_R}
${NS_B}
${NS_C}
${NS_D}
EOF
