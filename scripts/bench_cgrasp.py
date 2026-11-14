#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Micro-benchmarks for the cGRASP codec, relay state and leisure policy.

These are not protocol throughput numbers; they exist to catch accidental
algorithmic regressions in the hot helpers.  Run from the repository root:

    python scripts/bench_cgrasp.py

The output is Markdown so it can be pasted into documentation/performance.md.
"""

from __future__ import annotations

import argparse
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cgrasp.cgrasp_engine import CgraspEngine  # noqa: E402
from cgrasp.cgrasp_multicast import (  # noqa: E402
    DiscoveryKey, RelayConfig, RelayState, TokenBucket,
    decode_message, decrement_loop_count, encode_canonical,
)

DISCOVERY = [
    1,
    1234,
    bytes.fromhex("fe800000000000000000000000000001"),
    [42, 1, 6, "x"],
]


def _time(fn, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    return time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20000)
    args = parser.parse_args()
    n = args.iterations

    encoded = encode_canonical(DISCOVERY)
    config = RelayConfig(("a", "b"))
    engine = CgraspEngine(config)

    benchmarks = []

    benchmarks.append(("encode_canonical", n,
                       _time(lambda: encode_canonical(DISCOVERY), n)))
    benchmarks.append(("decode_message", n,
                       _time(lambda: decode_message(encoded), n)))
    benchmarks.append(("decrement_loop_count", n,
                       _time(lambda: decrement_loop_count(DISCOVERY), n)))

    state = RelayState(config)

    def create_close(i=[0]):
        i[0] += 1
        key = DiscoveryKey(b"\xfe" * 16, i[0])
        state.create_discovery(key, incoming_interface="a",
                               upstream_remote=None, upstream_token=b"",
                               upstream_request_context=None)
        state.close_discovery(key, reason="bench")

    benchmarks.append(("relay create+close", n, _time(create_close, n)))

    bucket = TokenBucket(rate=1_000_000, burst=1_000_000)

    def allow():
        bucket.allow(time.monotonic())

    benchmarks.append(("token bucket allow", n, _time(allow, n)))
    benchmarks.append(("engine leisure", n,
                       _time(engine.responder_leisure_seconds, n)))

    print(f"<!-- python {platform.python_version()} on {platform.platform()} -->")
    print()
    print("| benchmark | ops | total ms | ops/s |")
    print("|---|---:|---:|---:|")
    for name, ops, elapsed in benchmarks:
        print(f"| {name} | {ops} | {elapsed * 1000:.1f} | {ops / elapsed:,.0f} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
