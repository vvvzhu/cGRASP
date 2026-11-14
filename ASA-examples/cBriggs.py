#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""Briggs ASA implemented with cGRASP over CoAP.

Briggs is the responder/banker side:
- EX1: periodically floods a timestamp value.
- EX2: answers synchronization requests immediately with M_SYNCH.
- EX3: listens for negotiation requests and offers NZD funds.

Same-namespace local test:
  terminal A: python3 ASA-examples/cBriggs.py --listen-self
  terminal B: python3 ASA-examples/cGray.py --listen-self --same-host

This baseline profile does not support M_WAIT.
"""

from __future__ import annotations

import argparse
import datetime
import os
import random
import signal
import socket
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

from cgrasp import cgrasp as cg  # noqa: E402


EX1_FLOOD = 70002
EX2_SYNCH = 70003
EX3_NEGOTIATE = 70001


def make_objective(num: int, *, neg: bool = False, synch: bool = False, value=None):
    obj = cg.cobjective(int(num))
    obj.neg = bool(neg)
    obj.synch = bool(synch)
    obj.discoverable = True
    obj.loop_count = 4
    obj.value = value
    return obj


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
        print("\n[briggs] stopping... press Ctrl+C again to force", flush=True)
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


class Flooder(threading.Thread):
    def __init__(self, asa_handle, obj, *, interval_s: float, ttl_ms: int, stopping):
        super().__init__(daemon=True)
        self.asa_handle = asa_handle
        self.obj = obj
        self.interval_s = float(interval_s)
        self.ttl_ms = int(ttl_ms)
        self.stopping = stopping

    def run(self):
        while not self.stopping[0]:
            time.sleep(self.interval_s)
            if self.stopping[0]:
                return
            self.obj.value = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC from Briggs")
            err = cg.flood(self.asa_handle, self.ttl_ms, cg.tagged_objective(self.obj, None))
            if err:
                print(f"[briggs] flood EX1 failed err={err}", flush=True)


class Negotiator(threading.Thread):
    def __init__(self, asa_handle, shandle, requested, *, stopping):
        super().__init__(daemon=True)
        self.asa_handle = asa_handle
        self.shandle = shandle
        self.requested = requested
        self.stopping = stopping

    def end_decline(self, reason: str):
        err = cg.end_negotiate(self.asa_handle, self.shandle, False, reason=reason)
        if err:
            print(f"[briggs] end_negotiate decline failed err={err}", flush=True)

    def run(self):
        prng = random.SystemRandom()
        reserves = prng.randint(100, 400)

        try:
            currency = str(self.requested.value[0])
            amount = int(self.requested.value[1])
        except Exception:
            self.end_decline("Invalid request value")
            return

        print(f"[briggs] request {currency} {amount}; reserves={reserves}; dry={self.requested.dry}", flush=True)

        if currency != "NZD":
            self.end_decline("Invalid currency")
            return

        if amount <= reserves // 2:
            err = cg.end_negotiate(self.asa_handle, self.shandle, True)
            print(f"[briggs] accepted initial request err={err}", flush=True)
            return

        offer = max(1, reserves // 2)
        answer = self.requested
        answer.value = ["NZD", offer]

        step = 1
        while not self.stopping[0]:
            err, new_shandle, peer_obj = cg.negotiate_step(self.asa_handle, self.shandle, answer, 1000)
            if err == cg.errors.ok and new_shandle is None:
                print("[briggs] negotiation concluded", flush=True)
                return
            if err:
                print(f"[briggs] negotiate_step failed err={err}", flush=True)
                return

            self.shandle = new_shandle
            answer = peer_obj
            try:
                currency = str(answer.value[0])
                amount = int(answer.value[1])
            except Exception:
                self.end_decline("Invalid counter value")
                return

            if currency != "NZD":
                self.end_decline("Invalid currency")
                return
            if amount <= reserves:
                err = cg.end_negotiate(self.asa_handle, self.shandle, True)
                print(f"[briggs] accepted counter {amount}; err={err}", flush=True)
                return

            offer = min(reserves, max(offer + 10, reserves))
            answer.value = ["NZD", int(offer)]
            print(f"[briggs] step={step} peer asks={amount}; offer={offer}", flush=True)
            step += 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Briggs cGRASP responder ASA")
    ap.add_argument("--asa-name", default="Briggs-cGRASP")
    ap.add_argument("--bind", default="::")
    ap.add_argument("--coap-port", type=int, default=5683)
    ap.add_argument("--path", default=".well-known/grasp-coap")
    ap.add_argument("--listen-self", action="store_true")
    ap.add_argument("--diagnose", action="store_true")
    ap.add_argument("--test-mode", action="store_true")
    ap.add_argument("--flood-interval-s", type=float, default=60.0)
    ap.add_argument("--flood-ttl-ms", type=int, default=59000)
    ap.add_argument("--obj-ex1", type=int, default=EX1_FLOOD)
    ap.add_argument("--obj-ex2", type=int, default=EX2_SYNCH)
    ap.add_argument("--obj-ex3", type=int, default=EX3_NEGOTIATE)
    args = ap.parse_args(argv)

    handle = setup_cgrasp(args)
    stopping = [False]
    install_stop_handlers(stopping, handle)

    err, asa_handle = cg.register_asa(str(args.asa_name))
    if err:
        print(f"[briggs] register_asa failed err={err}", flush=True)
        return 2

    obj1 = make_objective(args.obj_ex1, synch=True)
    err = cg.register_obj(asa_handle, obj1, overlap=True, discoverable=True)
    if err:
        print(f"[briggs] register EX1 failed err={err}", flush=True)
        return 2
    Flooder(asa_handle, obj1, interval_s=args.flood_interval_s, ttl_ms=args.flood_ttl_ms, stopping=stopping).start()

    obj2 = make_objective(args.obj_ex2, synch=True, value=[1, "two", 3])
    err = cg.register_obj(asa_handle, obj2, overlap=True, discoverable=True)
    if err:
        print(f"[briggs] register EX2 failed err={err}", flush=True)
        return 2
    err = cg.listen_synchronize(asa_handle, obj2)
    print(f"[briggs] EX2 synchronization listener err={err}", flush=True)

    obj3 = make_objective(args.obj_ex3, neg=True, value=["NZD", 0])
    err = cg.register_obj(asa_handle, obj3, overlap=True, discoverable=True)
    if err:
        print(f"[briggs] register EX3 failed err={err}", flush=True)
        return 2

    print(
        f"[briggs] ready: coap://[{args.bind}]:{args.coap_port}/{args.path.strip('/')} "
        f"EX1={args.obj_ex1} EX2={args.obj_ex2} EX3={args.obj_ex3}",
        flush=True,
    )

    def listen_loop():
        while not stopping[0]:
            try:
                err, shandle, req_obj = cg.listen_negotiate(asa_handle, obj3)
            except Exception as ex:
                print(f"[briggs] listener exception: {ex}", flush=True)
                return
            if err:
                print(f"[briggs] listen_negotiate err={err}", flush=True)
                continue
            # listen_negotiate() is a sequential GRASP API: complete this
            # negotiation before re-entering listen_negotiate(). The CoAP
            # bridge may still carry a slow result as a separate response.
            Negotiator(asa_handle, shandle, req_obj, stopping=stopping).run()

    threading.Thread(target=listen_loop, daemon=True, name="briggs-listen-negotiate").start()

    while not stopping[0]:
        time.sleep(0.2)

    try:
        cg.deregister_asa(asa_handle, str(args.asa_name))
    except Exception:
        pass
    print(f"[briggs] audit={cg.get_transport_audit()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
