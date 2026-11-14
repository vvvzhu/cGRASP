#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Finite-process interoperability roles used by the integration tests."""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
from cgrasp import cgrasp as cg
from cgrasp.cgrasp_multicast import add_relay_arguments, relay_config_from_args


def emit(event: str, **fields) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def init(port: int, *, listen_self: bool = False, bind: str = "::1",
         be_dull: bool = True, relay_config=None, fault_mode: str = "", fault_count: int = 0):
    cg.skip_dialogue(testing=True, selfing=listen_self, diagnosing=False, be_dull=be_dull)
    if fault_mode:
        cg.configure_coap_receive_fault(fault_mode, fault_count)
    cg.enable_coap_transport(
        bind=bind,
        port=port,
        strict_coap=True,
        allow_tcp_fallback=False,
        allow_legacy_multicast=False,
        standard_multicast=True,
        relay_config=relay_config,
    )
    err, asa = cg.register_asa(f"interop-{port}-{time.time_ns()}")
    if err:
        raise RuntimeError(f"register_asa failed: {err}")
    cg.reset_transport_audit()
    return asa


def relay_config_or_none(args):
    config_path = getattr(args, "relay_config", None)
    interfaces = getattr(args, "relay_interfaces", None)
    overrides = (
        getattr(args, "relay_hard_timeout_ms", None),
        getattr(args, "relay_quiet_timeout_ms", None),
        getattr(args, "relay_rate", None),
        getattr(args, "relay_burst", None),
    )
    if not config_path and not interfaces:
        if any(value is not None for value in overrides):
            raise ValueError(
                "relay overrides require --relay-interface or --relay-config")
        return None
    return relay_config_from_args(args)


def objective(num: int, *, neg=False, synch=False, value=None):
    obj = cg.cobjective(num)
    obj.neg = neg
    obj.synch = synch
    obj.discoverable = True
    obj.value = value
    return obj


def peer(port: int):
    loc = cg.asa_locator(f"coap://[::1]:{port}", 0, False)
    loc.is_uri = True
    loc.is_ipaddress = False
    loc.is_fqdn = False
    return loc


def peer_uri(uri: str):
    loc = cg.asa_locator(uri, 0, False)
    loc.is_uri = True
    loc.is_ipaddress = False
    loc.is_fqdn = False
    return loc


class _OneShotPrng:
    """Force only the next locally allocated cGRASP session ID."""

    def __init__(self, session_id: int, fallback):
        self.session_id = int(session_id)
        self.fallback = fallback
        self.used = False

    def randint(self, lower: int, upper: int) -> int:
        if not self.used:
            self.used = True
            if not lower <= self.session_id <= upper:
                raise ValueError("forced session ID is outside allocator range")
            return self.session_id
        return self.fallback.randint(lower, upper)


def finish(ok: bool, **fields) -> int:
    audit = cg.get_transport_audit()
    emit("result", ok=ok, audit=audit, **fields)
    cg.disable_coap_transport()
    return 0 if ok else 1


def baseline_wait_disabled() -> int:
    cg.enable_coap_transport(autostart=False)
    err = cg.negotiate_wait(None, None, 1000)
    return finish(err == cg.errors.unspec, error=err)


def sync_server(args) -> int:
    asa = init(args.port)
    value = ("B" * args.payload_size) if args.payload_size else args.value
    obj = objective(args.obj, synch=True, value=value)
    err = cg.register_obj(asa, obj, discoverable=True)
    if not err:
        err = cg.listen_synchronize(asa, obj)
    emit("ready", role="sync-server", error=err)
    time.sleep(args.lifetime)
    return finish(err == cg.errors.ok)


def sync_client(args) -> int:
    asa = init(args.local_port)
    obj = objective(args.obj, synch=True)
    err, received = cg.synchronize(asa, obj, peer(args.port), args.timeout_ms)
    expected = ("B" * args.payload_size) if args.payload_size else args.value
    value = getattr(received, "value", None)
    return finish(err == cg.errors.ok and value == expected,
                  error=err, value_size=len(value) if isinstance(value, str) else None)


def neg_server(args, multiround: bool) -> int:
    asa = init(args.port)
    obj = objective(args.obj, neg=True)
    err = cg.register_obj(asa, obj, discoverable=True)
    emit("ready", role="multiround-server" if multiround else "fast-server", error=err)
    if err:
        return finish(False, error=err)
    err, sh, requested = cg.listen_negotiate(asa, obj)
    if err:
        return finish(False, error=err)
    if not multiround:
        err = cg.end_negotiate(asa, sh, True)
        return finish(err == cg.errors.ok, error=err, requested=getattr(requested, "value", None))

    requested.value = "counter"
    err, sh2, received = cg.negotiate_step(asa, sh, requested, args.timeout_ms)
    ok = err == cg.errors.ok and sh2 is not None and getattr(received, "value", None) == "final"
    if ok:
        err = cg.end_negotiate(asa, sh2, True)
        ok = err == cg.errors.ok
    return finish(ok, error=err, received=getattr(received, "value", None))


def neg_client(args, multiround: bool) -> int:
    asa = init(args.local_port)
    obj = objective(args.obj, neg=True, value="initial")
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        return finish(False, error=err)
    err, sh, received = cg.req_negotiate(asa, obj, peer(args.port), args.timeout_ms)
    if not multiround:
        return finish(err == cg.errors.ok and sh is None, error=err)
    ok = err == cg.errors.ok and sh is not None and getattr(received, "value", None) == "counter"
    if ok:
        received.value = "final"
        err, sh2, _received2 = cg.negotiate_step(asa, sh, received, args.timeout_ms)
        ok = err == cg.errors.ok and sh2 is None
    return finish(ok, error=err)


def collision_server(args) -> int:
    asa = init(args.port, bind=args.bind)
    obj = objective(args.obj, neg=True)
    err = cg.register_obj(asa, obj, discoverable=False)
    emit("ready", role="collision-server", error=err,
         expected_clients=args.expected_clients)
    if err:
        return finish(False, error=err)

    results = []
    results_lock = threading.Lock()

    def serve_one() -> None:
        step = {"ok": False}
        listen_err, sh, requested = cg.listen_negotiate(asa, obj)
        step.update(error=listen_err, session_id=getattr(sh, "id_value", None),
                    peer=(getattr(sh, "id_source", b"") or b"").hex(),
                    requested=getattr(requested, "value", None))
        if listen_err == cg.errors.ok and sh is not None and requested is not None:
            incoming = requested.value
            requested.value = f"reply:{incoming}"
            step_err, sh2, received = cg.negotiate_step(
                asa, sh, requested, args.timeout_ms)
            expected = f"final:{incoming}"
            ok = (step_err == cg.errors.ok and sh2 is not None and
                  getattr(received, "value", None) == expected)
            if ok:
                step_err = cg.end_negotiate(asa, sh2, True)
                ok = step_err == cg.errors.ok
            step.update(ok=ok, error=step_err,
                        received=getattr(received, "value", None))
        with results_lock:
            results.append(step)

    workers = [threading.Thread(target=serve_one) for _ in range(args.expected_clients)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=max(5.0, args.timeout_ms / 1000 + 5.0))
    alive = sum(worker.is_alive() for worker in workers)
    time.sleep(0.2)
    bridge = cg.get_coap_bridge_snapshot() or {}
    ok = (alive == 0 and len(results) == args.expected_clients and
          all(item.get("ok") for item in results) and
          len({item.get("peer") for item in results}) == args.expected_clients and
          len({item.get("session_id") for item in results}) == 1 and
          bridge.get("active_sessions") == 0 and
          bridge.get("active_exchanges") == 0)
    return finish(ok, error=err, workers_alive=alive,
                  sessions=sorted(results, key=lambda item: str(item.get("requested"))),
                  bridge=bridge)


def collision_client(args) -> int:
    asa = init(args.local_port, bind=args.bind)
    obj = objective(args.obj, neg=True, value=args.value)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        return finish(False, error=err, forced_session_id=args.forced_session_id)

    original_prng = cg._prng
    forced_prng = _OneShotPrng(args.forced_session_id, original_prng)
    cg._prng = forced_prng
    try:
        err, sh, received = cg.req_negotiate(
            asa, obj, peer_uri(args.peer_uri), args.timeout_ms)
    finally:
        cg._prng = original_prng
    expected_reply = f"reply:{args.value}"
    observed_sid = getattr(sh, "id_value", None)
    ok = (forced_prng.used and err == cg.errors.ok and sh is not None and
          observed_sid == args.forced_session_id and
          getattr(received, "value", None) == expected_reply)
    reply = getattr(received, "value", None)
    if ok:
        received.value = f"final:{args.value}"
        err, sh2, _ = cg.negotiate_step(asa, sh, received, args.timeout_ms)
        ok = err == cg.errors.ok and sh2 is None
    return finish(ok, error=err, forced_session_id=args.forced_session_id,
                  session_id=observed_sid, sent=args.value, received=reply)


def discovery_self(args) -> int:
    asa = init(args.port, listen_self=True, bind="::")
    obj = objective(args.obj)
    err = cg.register_obj(asa, obj, discoverable=True)
    if err:
        return finish(False, error=err)
    err, locators = cg.discover(asa, obj, args.timeout_ms, flush=True)
    is_coap = any(getattr(x, "is_uri", False) and str(getattr(x, "locator", "")).startswith("coap://") for x in locators)
    return finish(err == cg.errors.ok and is_coap, error=err, locators=len(locators))


def discovery_server(args) -> int:
    asa = init(args.port, bind=args.bind, be_dull=not args.non_dull,
               fault_mode=args.fault_mode, fault_count=args.fault_count)
    obj = objective(args.obj)
    err = cg.register_obj(asa, obj, discoverable=True)
    emit("ready", role="discovery-server", error=err)
    time.sleep(args.lifetime)
    return finish(err == cg.errors.ok, error=err)


def discovery_client(args) -> int:
    asa = init(args.port, bind=args.bind, be_dull=not args.non_dull)
    obj = objective(args.obj)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        return finish(False, error=err)
    err, locators = cg.discover(asa, obj, args.timeout_ms, flush=True)
    is_coap = any(getattr(x, "is_uri", False) and str(getattr(x, "locator", "")).startswith("coap://") for x in locators)
    return finish(err == cg.errors.ok and is_coap and len(locators) >= args.min_locators,
                  error=err, locators=len(locators), min_locators=args.min_locators)


def discovery_client_none(args) -> int:
    asa = init(args.port, bind=args.bind, be_dull=not args.non_dull)
    obj = objective(args.obj)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        return finish(False, error=err, locators=0, expected_locators=0)
    err, locators = cg.discover(asa, obj, args.timeout_ms, flush=True)
    locators = locators or []
    return finish(
        len(locators) == 0,
        error=err,
        locators=len(locators),
        expected_locators=0,
    )


def relay_node(args) -> int:
    from cgrasp.cgrasp_quiescence import assert_quiescent

    requested_config = relay_config_or_none(args)
    init(args.port, bind=args.bind, be_dull=False, relay_config=requested_config,
         fault_mode=args.fault_mode, fault_count=args.fault_count)
    state = getattr(cg, "_coap_relay_state", None)
    active_config = getattr(state, "config", None)
    emit(
        "ready",
        role="relay",
        interfaces=len(getattr(cg, "_ll_zone_ids", ())),
        relay_hard_timeout_ms=getattr(active_config, "discovery_hard_timeout_ms", None),
        relay_quiet_timeout_ms=getattr(active_config, "discovery_quiet_timeout_ms", None),
    )
    time.sleep(args.lifetime)
    state = getattr(cg, "_coap_relay_state", None)
    snapshots = assert_quiescent(relay_state=state) if state is not None else {}
    relay_snapshot = snapshots.get("relay", {})
    return finish(
        state is not None,
        counters=getattr(state, "counters", {}),
        remaining_transactions=relay_snapshot.get("active_discovery_transactions"),
        quiescence=relay_snapshot,
    )


def flood_self(args) -> int:
    asa = init(args.port, listen_self=True, bind="::")
    obj = objective(args.obj, synch=True, value=args.value)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        return finish(False, error=err)
    err = cg.flood(asa, 5000, cg.tagged_objective(obj, None))
    deadline = time.time() + 2.0
    flooded = []
    while err == cg.errors.ok and time.time() < deadline:
        get_err, flooded = cg.get_flood(asa, obj)
        if get_err == cg.errors.ok and any(getattr(x.objective, "value", None) == args.value for x in flooded):
            break
        time.sleep(0.05)
    ok = err == cg.errors.ok and any(getattr(x.objective, "value", None) == args.value for x in flooded)
    return finish(ok, error=err, flooded=len(flooded))


def flood_sender(args) -> int:
    asa = init(args.port, bind=args.bind, be_dull=not args.non_dull)
    obj = objective(args.obj, synch=True, value=args.value)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        return finish(False, error=err)
    err = cg.flood(asa, args.timeout_ms, cg.tagged_objective(obj, None))
    time.sleep(0.5)
    return finish(err == cg.errors.ok, error=err)


def flood_listener(args) -> int:
    asa = init(args.port, bind=args.bind, be_dull=not args.non_dull)
    obj = objective(args.obj, synch=True)
    err = cg.register_obj(asa, obj, discoverable=False)
    emit("ready", role="flood-listener", error=err)
    deadline = time.time() + args.lifetime
    flooded = []
    while err == cg.errors.ok and time.time() < deadline:
        get_err, flooded = cg.get_flood(asa, obj)
        if get_err == cg.errors.ok and any(getattr(x.objective, "value", None) == args.value for x in flooded):
            break
        time.sleep(0.05)
    ok = err == cg.errors.ok and any(getattr(x.objective, "value", None) == args.value for x in flooded)
    return finish(ok, error=err, flooded=len(flooded))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["sync-server", "sync-client", "fast-server", "fast-client",
                                    "multiround-server", "multiround-client",
                                    "collision-server", "collision-client",
                                    "discovery-self", "discovery-server", "discovery-client",
                                    "discovery-client-none", "flood-self",
                                    "flood-sender", "flood-listener",
                                    "relay", "baseline-wait-disabled"])
    p.add_argument("--port", type=int, default=5683)
    # Do not use 5684: it is the registered CoAPS/DTLS port and causes protocol
    # analyzers to decode this plaintext coap:// callback as DTLS.
    p.add_argument("--local-port", type=int, default=15683)
    p.add_argument("--bind", default="::")
    p.add_argument("--obj", type=int, default=47001)
    p.add_argument("--value", default="synced-value")
    p.add_argument("--peer-uri", default="coap://[::1]:5683")
    p.add_argument("--forced-session-id", type=int, default=3792101383)
    p.add_argument("--expected-clients", type=int, default=2)
    p.add_argument("--timeout-ms", type=int, default=3000)
    p.add_argument("--lifetime", type=float, default=4.0)
    p.add_argument("--payload-size", type=int, default=0)
    p.add_argument("--min-locators", type=int, default=1)
    p.add_argument("--non-dull", action="store_true")
    p.add_argument("--fault-mode", choices=["", "drop-first-response", "ignore-first-ack"],
                   default="")
    p.add_argument("--fault-count", type=int, default=1)
    add_relay_arguments(p)
    args = p.parse_args()
    if args.role == "baseline-wait-disabled":
        return baseline_wait_disabled()
    if args.role == "sync-server":
        return sync_server(args)
    if args.role == "sync-client":
        return sync_client(args)
    if args.role == "fast-server":
        return neg_server(args, False)
    if args.role == "fast-client":
        return neg_client(args, False)
    if args.role == "multiround-server":
        return neg_server(args, True)
    if args.role == "multiround-client":
        return neg_client(args, True)
    if args.role == "collision-server":
        return collision_server(args)
    if args.role == "collision-client":
        return collision_client(args)
    if args.role == "flood-self":
        return flood_self(args)
    if args.role == "flood-sender":
        return flood_sender(args)
    if args.role == "flood-listener":
        return flood_listener(args)
    if args.role == "discovery-server":
        return discovery_server(args)
    if args.role == "discovery-client":
        return discovery_client(args)
    if args.role == "discovery-client-none":
        return discovery_client_none(args)
    if args.role == "relay":
        return relay_node(args)
    return discovery_self(args)


if __name__ == "__main__":
    raise SystemExit(main())
