#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""Gray ASA implemented with cGRASP over CoAP.

Gray is the requester/client side:
- optionally synchronizes EX2 from Briggs.
- negotiates EX3 by asking Briggs for NZD funds.

Same-namespace local test:
  terminal A: python3 ASA-examples/cBriggs.py --listen-self
  terminal B: python3 ASA-examples/cGray.py --listen-self --same-host

By default Gray uses cGRASP discovery. Use --peer for a direct CoAP URI locator,
or --same-host for coap://[::1]:5683 when both ASAs run in the same namespace.
"""

from __future__ import annotations

import argparse
import os
import random
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cgrasp import cgrasp as cg  # noqa: E402


EX2_SYNCH = 70003
EX3_NEGOTIATE = 70001


def make_objective(num: int, *, neg: bool = False, synch: bool = False, value=None):
    obj = cg.cobjective(int(num))
    obj.neg = bool(neg)
    obj.synch = bool(synch)
    obj.discoverable = True
    obj.loop_count = int(getattr(cg, "GRASP_DEF_LOOPCT", 6))
    obj.value = value
    return obj


def make_uri_locator(uri: str):
    loc = cg.asa_locator(str(uri).rstrip("/"), 0, False)
    loc.is_uri = True
    loc.is_ipaddress = False
    loc.is_fqdn = False
    return loc


def err_text(err: int) -> str:
    try:
        return cg.etext[int(err)]
    except Exception:
        return str(err)


def setup_cgrasp(args):
    cg.skip_dialogue(
        testing=bool(args.test_mode),
        selfing=bool(args.listen_self),
        diagnosing=bool(args.diagnose),
        be_dull=True,
    )
    return cg.enable_coap_transport(
        True,
        bind=str(args.bind),
        port=int(args.coap_port),
        path=str(args.path),
        mc_uri_path=(".well-known", "grasp-coap"),
        autostart=True,
        strict_coap=True,
        allow_tcp_fallback=False,
        allow_legacy_multicast=False,
        standard_multicast=True,
    )


def install_stop_handlers(stopping, handle):
    state = {"count": 0}

    def stop(_signum, _frame):
        state["count"] += 1
        if state["count"] >= 2:
            os._exit(130)
        stopping[0] = True
        print("\n[gray] stopping... press Ctrl+C again to force", flush=True)
        try:
            if handle is not None:
                handle.stop()
        except Exception:
            pass

    signal.signal(signal.SIGINT, stop)
    try:
        signal.signal(signal.SIGTERM, stop)
    except Exception:
        pass


def choose_peer(asa_handle, obj, args):
    peer = str(args.peer or "").strip()
    if bool(getattr(args, "same_host", False)) and not peer:
        peer = "coap://[::1]:5683"
    if peer:
        return make_uri_locator(peer)

    err, locators = cg.discover(asa_handle, obj,1000, flush=bool(args.flush_discovery))
    if err or not locators:
        print(f"[gray] discovery failed err={err} locators={len(locators or [])}", flush=True)
        return None
    loc = locators[0]
    print(f"[gray] discovered {getattr(loc, 'locator', loc)}", flush=True)
    return loc


def run_sync(asa_handle, args):
    if args.no_sync:
        return
    obj = make_objective(args.obj_ex2, synch=True)
    peer = choose_peer(asa_handle, obj, args)
    if peer is None:
        return
    err, result = cg.synchronize(asa_handle, obj, peer, 5000)
    if err:
        print(f"[gray] synchronize EX2 failed err={err}", flush=True)
        return
    print(f"[gray] synchronized EX2 value={getattr(result, 'value', None)}", flush=True)


def negotiate_once(asa_handle, obj, peer, args, prng) -> bool:
    iwant = int(args.fixed_request) if int(args.fixed_request) > 0 else prng.randint(10, 500)
    obj.value = ["NZD", iwant]
    obj.loop_count = prng.randint(12, 24)
    obj.dry = bool(iwant & 4)
    if bool(args.test_bad_currency) and not iwant % 7:
        obj.value[0] = "USD"

    print(f"[gray] asking for {obj.value[0]} {iwant}; dry={obj.dry}; loop={obj.loop_count}", flush=True)

    err, shandle, answer = cg.req_negotiate(asa_handle, obj, peer, 5000)
    if err:
        print(f"[gray] req_negotiate failed err={err} ({err_text(err)}) answer={answer}", flush=True)
        return False
    if shandle is None:
        print(f"[gray] negotiation accepted immediately value={getattr(answer, 'value', None)}", flush=True)
        return True

    try:
        offered = int(answer.value[1])
        currency = str(answer.value[0])
    except Exception:
        cg.end_negotiate(asa_handle, shandle, False, reason="Invalid offer")
        return False

    limit = int(0.7 * iwant)
    proffer = int(0.9 * iwant)
    step = 1

    while True:
        if currency != "NZD":
            cg.end_negotiate(asa_handle, shandle, False, reason="Invalid currency")
            print(f"[gray] declined invalid currency {currency}", flush=True)
            return False

        if offered >= proffer:
            err = cg.end_negotiate(asa_handle, shandle, True)
            print(f"[gray] accepted offer {offered}; err={err}", flush=True)
            return err == cg.errors.ok

        answer.value = ["NZD", int(proffer)]
        print(f"[gray] step={step} counter={proffer}; peer offered={offered}", flush=True)
        err, new_shandle, answer = cg.negotiate_step(asa_handle, shandle, answer,1000)
        if err == cg.errors.ok and new_shandle is None:
            print("[gray] negotiation concluded by peer", flush=True)
            return True
        if err:
            print(f"[gray] negotiate_step failed err={err} ({err_text(err)}) answer={answer}", flush=True)
            return False

        shandle = new_shandle
        try:
            offered = int(answer.value[1])
            currency = str(answer.value[0])
        except Exception:
            cg.end_negotiate(asa_handle, shandle, False, reason="Invalid offer")
            return False

        step += 1
        proffer = int(0.9 * proffer)
        if proffer < limit:
            cg.end_negotiate(asa_handle, shandle, False, reason="You are mean!")
            print("[gray] declined: proffer below limit", flush=True)
            return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Gray cGRASP requester ASA")
    ap.add_argument("--asa-name", default="Gray-cGRASP")
    ap.add_argument("--bind", default="::")
    ap.add_argument("--coap-port", type=int, default=15683)
    ap.add_argument("--path", default=".well-known/grasp-coap")
    ap.add_argument("--peer", default="", help="Direct peer base URI; default empty value uses cGRASP discovery")
    ap.add_argument("--same-host", action="store_true", help="Shortcut for --peer coap://[::1]:5683")
    ap.add_argument("--timeout-ms", type=int, default=60000)
    ap.add_argument("--sleep-s", type=float, default=5.0)
    ap.add_argument("--iterations", type=int, default=0, help="0 means run forever")
    ap.add_argument("--fixed-request", type=int, default=0)
    ap.add_argument("--flush-discovery", action="store_true")
    ap.add_argument("--no-sync", action="store_true")
    ap.add_argument("--test-bad-currency", action="store_true")
    ap.add_argument("--listen-self", action="store_true")
    ap.add_argument("--diagnose", action="store_true")
    ap.add_argument("--test-mode", action="store_true")
    ap.add_argument("--obj-ex2", type=int, default=EX2_SYNCH)
    ap.add_argument("--obj-ex3", type=int, default=EX3_NEGOTIATE)
    args = ap.parse_args(argv)

    handle = setup_cgrasp(args)
    stopping = [False]
    install_stop_handlers(stopping, handle)

    err, asa_handle = cg.register_asa(str(args.asa_name))
    if err:
        print(f"[gray] register_asa failed err={err}", flush=True)
        return 2

    obj3 = make_objective(args.obj_ex3, neg=True)
    err = cg.register_obj(asa_handle, obj3, overlap=True, discoverable=False)
    if err:
        print(f"[gray] register EX3 failed err={err}", flush=True)
        return 2

    print(
        f"[gray] ready: local=coap://[{args.bind}]:{args.coap_port}/{args.path.strip('/')} "
        f"peer={(args.peer or 'coap://[::1]:5683') if args.same_host else (args.peer or '<discovery>')} "
        f"EX2={args.obj_ex2} EX3={args.obj_ex3}",
        flush=True,
    )

    run_sync(asa_handle, args)

    prng = random.SystemRandom()
    attempts = 0
    successes = 0
    while not stopping[0] and (int(args.iterations) <= 0 or attempts < int(args.iterations)):
        peer = choose_peer(asa_handle, obj3, args)
        if peer is None:
            time.sleep(args.sleep_s)
            continue
        attempts += 1
        if negotiate_once(asa_handle, obj3, peer, args, prng):
            successes += 1
        time.sleep(args.sleep_s)

    try:
        cg.deregister_asa(asa_handle, str(args.asa_name))
    except Exception:
        pass
    print(f"[gray] attempts={attempts} successes={successes} audit={cg.get_transport_audit()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
