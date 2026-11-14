# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Repository-wide lifecycle assertions for cGRASP tests and diagnostics."""

from __future__ import annotations

import json
from typing import Iterable


def assert_quiescent(*, relay_state=None, bridge=None,
                     exchanges: Iterable[object] = ()) -> dict:
    """Return component snapshots or raise with every observed live resource."""
    snapshots: dict[str, object] = {}
    violations: dict[str, object] = {}

    if relay_state is not None:
        relay = relay_state.snapshot()
        snapshots["relay"] = relay
        live_relay = {
            key: relay[key]
            for key in (
                "active_discovery_transactions",
                "active_downstream_branches",
                "response_digests",
            )
            if relay.get(key)
        }
        if live_relay:
            violations["relay"] = live_relay

    if bridge is not None:
        bridge_snapshot = bridge.snapshot()
        snapshots["bridge"] = bridge_snapshot
        live_bridge = {
            key: bridge_snapshot.get(key)
            for key in ("active_sessions", "active_exchanges")
            if bridge_snapshot.get(key)
        }
        if live_bridge:
            live_bridge["sessions"] = bridge_snapshot.get("sessions", ())
            live_bridge["exchanges"] = bridge_snapshot.get("exchanges", ())
            violations["bridge"] = live_bridge

    exchange_snapshots = []
    for index, exchange in enumerate(exchanges):
        snapshot = exchange.snapshot()
        exchange_snapshots.append(snapshot)
        live = {
            key: snapshot.get(key)
            for key in ("closed", "token_registered", "pending_responses")
            if ((key == "closed" and not snapshot.get(key)) or
                (key != "closed" and snapshot.get(key)))
        }
        if live:
            violations[f"exchange[{index}]"] = live
    if exchange_snapshots:
        snapshots["exchanges"] = tuple(exchange_snapshots)

    if violations:
        raise AssertionError(
            "cGRASP lifecycle is not quiescent: "
            + json.dumps(violations, sort_keys=True, default=str)
        )
    return snapshots
