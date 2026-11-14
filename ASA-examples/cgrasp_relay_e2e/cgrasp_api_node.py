#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""cGRASP API driven nodes for relay E2E pcap generation."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cgrasp import cgrasp as cg  # noqa: E402
from cgrasp.cgrasp_multicast import RelayConfig  # noqa: E402


OBJECTIVE_NUM = 47991
OBJECTIVE_NAME = "EXAMPLE_RELAY_OBJECTIVE"
NODE_B_URI = "coap://[fd00:2::1]:5683/.well-known/grasp-coap"


def emit(event: str, **fields) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True, default=str), flush=True)


def neg_objective(value=None):
    obj = cg.cobjective(OBJECTIVE_NUM)
    obj.discoverable = True
    obj.neg = True
    obj.synch = False
    obj.loop_count = 4
    obj.value = value if value is not None else OBJECTIVE_NAME
    return obj


def synch_objective(value=None):
    obj = cg.cobjective(OBJECTIVE_NUM)
    obj.discoverable = True
    obj.neg = False
    obj.synch = True
    obj.loop_count = 4
    obj.value = value if value is not None else OBJECTIVE_NAME
    return obj


def low_loop_neg_objective(value=None):
    obj = neg_objective(value)
    obj.loop_count = 1
    return obj


def low_loop_synch_objective(value=None):
    obj = synch_objective(value)
    obj.loop_count = 1
    return obj


def init(role: str, *, bind: str = "::", relay: bool = False):
    cg.skip_dialogue(testing=True, selfing=False, diagnosing=False, be_dull=False)
    relay_config = None
    if relay:
        relay_config = RelayConfig(
            ("veth-r-left", "veth-r-right", "veth-r-c", "veth-r-d"),
            discovery_hard_timeout_ms=4000,
        )
    handle = cg.enable_coap_transport(
        True,
        bind=bind,
        port=5683,
        path=".well-known/grasp-coap",
        autostart=True,
        strict_coap=True,
        allow_tcp_fallback=False,
        allow_legacy_multicast=False,
        standard_multicast=True,
        relay_config=relay_config,
    )
    err, asa = cg.register_asa(f"relay-e2e-{role}-{time.time_ns()}")
    if err:
        raise RuntimeError(f"register_asa failed: {err}")
    cg.reset_transport_audit()
    return handle, asa


def uri_locator(uri: str):
    loc = cg.asa_locator(uri.rstrip("/"), 0, False)
    loc.is_uri = True
    loc.is_ipaddress = False
    loc.is_fqdn = False
    return loc


def node_b(args) -> int:
    _handle, asa = init("node-b", bind="::")
    obj = neg_objective(50)
    err = cg.register_obj(asa, obj, discoverable=True)
    if err:
        emit("result", role="node-b", ok=False, stage="register-neg", error=err)
        return 1

    state = {"negotiated": None, "flooded": None, "sync_ready": False}
    stop = threading.Event()
    sync_ready = threading.Event()
    sync_holder = {"obj": None}

    def negotiation_loop():
        try:
            err1, shandle, requested = cg.listen_negotiate(asa, obj)
            if err1:
                emit("negotiation", role="node-b", ok=False, error=err1)
                return
            requested.value = 60
            err2, shandle2, received = cg.negotiate_step(asa, shandle, requested, 5000)
            if err2:
                emit("negotiation", role="node-b", ok=False, error=err2)
                return
            state["negotiated"] = getattr(received, "value", None)
            err3 = cg.end_negotiate(asa, shandle2, True)
            emit("negotiation", role="node-b", ok=err3 == cg.errors.ok, error=err3,
                 value=state["negotiated"])
            cg.deregister_obj(asa, obj)
            sync_obj = synch_objective(50)
            err4 = cg.register_obj(asa, sync_obj, discoverable=True)
            if err4:
                emit("sync-register", role="node-b", ok=False, error=err4)
                return
            err5 = cg.listen_synchronize(asa, sync_obj)
            emit("sync-listen", role="node-b", ok=err5 == cg.errors.ok, error=err5)
            if err5:
                return
            sync_holder["obj"] = sync_obj
            state["sync_ready"] = True
            sync_ready.set()
        except Exception as exc:
            emit("negotiation", role="node-b", ok=False, exception=str(exc))

    threading.Thread(target=negotiation_loop, daemon=True).start()
    emit("ready", role="node-b")
    deadline = time.time() + args.lifetime
    while time.time() < deadline and not stop.is_set():
        if not sync_ready.is_set():
            time.sleep(0.1)
            continue
        err, flooded = cg.get_flood(asa, sync_holder["obj"])
        if err == cg.errors.ok:
            for item in flooded:
                value = getattr(getattr(item, "objective", None), "value", None)
                if value == 70:
                    state["flooded"] = value
                    emit("flood", role="node-b", ok=True, value=value)
                    stop.set()
                    break
        time.sleep(0.1)
    emit("result", role="node-b", ok=True, state=state, audit=cg.get_transport_audit())
    return 0


def relay_r(args) -> int:
    _handle, _asa = init("relay-r", bind="::", relay=True)
    emit("ready", role="relay-r", interfaces=len(getattr(cg, "_ll_zone_ids", ())))
    time.sleep(args.lifetime)
    relay_state = getattr(cg, "_coap_relay_state", None)
    emit("result", role="relay-r", ok=relay_state is not None,
         counters=getattr(relay_state, "counters", {}) if relay_state else {},
         audit=cg.get_transport_audit())
    return 0


def node_a(args) -> int:
    _handle, asa = init("node-a", bind="::")
    obj = neg_objective(40)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        emit("result", role="node-a", ok=False, stage="register-neg", error=err)
        return 1

    emit("phase", role="node-a", name="discover")
    err, locators = cg.discover(asa, obj, 5000, flush=True)
    emit("discover", role="node-a", error=err, locators=len(locators or []))
    if err:
        emit("result", role="node-a", ok=False, phase="discover", error=err)
        return 1

    peer = uri_locator(NODE_B_URI)

    emit("phase", role="node-a", name="negotiate")
    obj.value = 40
    err, shandle, answer = cg.req_negotiate(asa, obj, peer, 5000)
    if err or shandle is None:
        emit("result", role="node-a", ok=False, phase="negotiate-start", error=err,
             answer=getattr(answer, "value", None))
        return 1
    answer.value = 50
    err, shandle2, final = cg.negotiate_step(asa, shandle, answer, 5000)
    emit("negotiate", role="node-a", error=err, shandle_closed=shandle2 is None,
         final=getattr(final, "value", None))
    if err:
        emit("result", role="node-a", ok=False, phase="negotiate-step", error=err)
        return 1
    cg.deregister_obj(asa, obj)

    emit("phase", role="node-a", name="synchronize")
    sync_obj = synch_objective()
    err, synced = cg.synchronize(asa, sync_obj, peer, 5000)
    emit("synchronize", role="node-a", error=err, value=getattr(synced, "value", None))
    if err:
        emit("result", role="node-a", ok=False, phase="synchronize", error=err)
        return 1

    emit("phase", role="node-a", name="flood")
    flood_obj = synch_objective(70)
    err = cg.register_obj(asa, flood_obj, discoverable=False)
    if err:
        emit("result", role="node-a", ok=False, phase="register-flood", error=err)
        return 1
    err = cg.flood(asa, 5000, cg.tagged_objective(flood_obj, None))
    emit("flood", role="node-a", error=err)
    time.sleep(0.5)
    emit("result", role="node-a", ok=err == cg.errors.ok, audit=cg.get_transport_audit())
    return 0 if err == cg.errors.ok else 1


def node_c(args) -> int:
    _handle, asa = init("node-c", bind="::")
    obj = synch_objective()
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        emit("result", role="node-c", ok=False, stage="register-discovery", error=err)
        return 1
    emit("phase", role="node-c", name="discover-after-relay-cache")
    err, locators = cg.discover(asa, obj, 5000, flush=True)
    emit("discover", role="node-c", error=err, locators=len(locators or []))
    ok = err == cg.errors.ok and len(locators or []) >= 1
    emit("result", role="node-c", ok=ok, phase="discover-after-relay-cache",
         error=err, locators=len(locators or []), audit=cg.get_transport_audit())
    return 0 if ok else 1


def node_d(args) -> int:
    _handle, asa = init("node-d", bind="::")

    disc_obj = low_loop_neg_objective()
    err = cg.register_obj(asa, disc_obj, discoverable=False)
    if err:
        emit("result", role="node-d", ok=False, stage="register-low-loop-discovery", error=err)
        return 1

    emit("phase", role="node-d", name="low-loop-discovery")
    err, locators = cg.discover(asa, disc_obj, 2500, flush=True)
    discovery_blocked = err != cg.errors.ok or len(locators or []) == 0
    emit("low-loop-discovery", role="node-d", blocked=discovery_blocked,
         error=err, locators=len(locators or []), expected="blocked")
    cg.deregister_obj(asa, disc_obj)

    flood_obj = low_loop_synch_objective(99)
    err = cg.register_obj(asa, flood_obj, discoverable=False)
    if err:
        emit("result", role="node-d", ok=False, stage="register-low-loop-flood", error=err)
        return 1

    emit("phase", role="node-d", name="low-loop-flood")
    flood_err = cg.flood(asa, 2500, cg.tagged_objective(flood_obj, None))
    emit("low-loop-flood", role="node-d", error=flood_err, expected="not-forwarded", value=99)
    ok = discovery_blocked and flood_err == cg.errors.ok
    emit("result", role="node-d", ok=ok, phase="low-loop-boundary",
         discovery_blocked=discovery_blocked, flood_error=flood_err,
         audit=cg.get_transport_audit())
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["node-a", "relay-r", "node-b", "node-c", "node-d"])
    parser.add_argument("--lifetime", type=float, default=8.0)
    args = parser.parse_args()
    if args.role == "node-a":
        return node_a(args)
    if args.role == "relay-r":
        return relay_r(args)
    if args.role == "node-c":
        return node_c(args)
    if args.role == "node-d":
        return node_d(args)
    return node_b(args)


if __name__ == "__main__":
    raise SystemExit(main())
