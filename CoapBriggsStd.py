#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""CoAP-based Briggs ASA (listener) using cgrasp.cgrasp standard CoAP multicast.

This is a "Briggs-like" demonstration ASA adapted from Briggs.py, but running on
cgrasp.cgrasp with:
- Standard CoAP multicast Discovery: ff02::fd:5683, resource /.well-known/grasp-coap
    (responders return M_RESPONSE as the FETCH Content response on the same
    /.well-known/grasp-coap resource; callback POST is disabled)
- Unicast negotiation over CoAP (responder side)
- Flood + get_flood demo (EX1-like)
- Synchronization listener demo (EX2-like)

Typical usage (two terminals, same host):
  Terminal A (listener):
    python3 CoapBriggsStd.py --listen-self --coap-port 5683

  Terminal B (initiator):
    python3 CoapGrayStd.py --listen-self --coap-port 15683

Notes:
- Runs in DULL mode by default to avoid ACP/TLS dependencies.
- Ctrl+C is handled: first Ctrl+C requests a graceful stop, second forces exit.
- listen_negotiate() is blocking; we run it in a daemon worker thread so Ctrl+C
  can exit immediately.
"""

from __future__ import annotations

import argparse
import datetime
import os
import queue
import random
import signal
import socket
import threading
import time
from typing import Optional

try:
    from cgrasp import cgrasp as cg
except Exception:  # pragma: no cover
    from cgrasp import cgrasp as cg  # type: ignore


DEFAULT_OBJ_EX1 = 70002  # flood objective
DEFAULT_OBJ_EX2 = 70003  # synchronize objective
DEFAULT_OBJ_EX3 = 70001  # negotiation objective


def _obj_to_list(obj) -> list:
    """Encode a cgrasp.cgrasp objective instance as the on-the-wire list."""
    num = int(getattr(obj, "num"))
    discoverable = bool(getattr(obj, "discoverable", True))
    neg = bool(getattr(obj, "neg", False))
    synch = bool(getattr(obj, "synch", False))
    dry = bool(getattr(obj, "dry", False))
    loop_count = int(getattr(obj, "loop_count", 1))
    value = getattr(obj, "value", None)

    flags = 0
    if discoverable:
        flags |= 1 << 0
    if neg:
        flags |= 1 << 1
    if synch:
        flags |= 1 << 2
    if dry:
        flags |= 1 << 3

    return [num, flags, loop_count, value]


def _install_sig_handlers(on_stop) -> None:
    state = {"count": 0}

    def _handler(signum, frame):
        state["count"] += 1
        if state["count"] >= 2:
            os._exit(130)
        try:
            on_stop(signum, frame)
        except Exception:
            pass

    signal.signal(signal.SIGINT, _handler)
    try:
        signal.signal(signal.SIGTERM, _handler)
    except Exception:
        pass


def _common_init(args):
    cg.skip_dialogue(
        testing=bool(args.test_mode),
        selfing=bool(args.listen_self),
        diagnosing=bool(args.diagnose),
        be_dull=True,
    )

    handle = cg.enable_coap_transport(
        True,
        bind=str(args.bind),
        port=int(args.coap_port),
        path=str(args.path),
        mc_uri_path=(".well-known", "grasp-coap"),
        autostart=True,
        strict_coap=bool(args.strict_coap),
        allow_tcp_fallback=False if args.strict_coap else None,
        allow_legacy_multicast=False if args.strict_coap else None,
        standard_multicast=True,
        enable_wait=bool(args.enable_wait),
    )

    # Be explicit about the knobs the new discover() depends on.
    # (enable_coap_transport() already sets these, but keeping them here makes
    # this demo resilient to older/newer library defaults.)
    try:
        cg.set_standard_coap_multicast(True, uri_path=(".well-known", "grasp-coap"))
    except Exception:
        pass
    try:
        cg.set_advertise_coap_unicast(True, port=int(args.coap_port), path=str(args.path))
    except Exception:
        pass

    return handle


def _print_ifaces() -> None:
    try:
        ifaces = socket.if_nameindex()
    except Exception:
        ifaces = []
    if ifaces:
        print("[hint] interfaces:")
        for idx, name in ifaces:
            print(f"  - {name} (ifindex={idx})")


class Flooder(threading.Thread):
    def __init__(self, asa_handle, obj, *, interval_s: float, ttl_ms: int, stopping_flag):
        super().__init__(daemon=True)
        self.asa_handle = asa_handle
        self.obj = obj
        self.interval_s = float(interval_s)
        self.ttl_ms = int(ttl_ms)
        self.stopping_flag = stopping_flag

    def run(self):
        while not self.stopping_flag[0]:
            time.sleep(self.interval_s)
            if self.stopping_flag[0]:
                break
            self.obj.value = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC from Briggs-CoAP")
            to = cg.tagged_objective(self.obj, None)
            err = cg.flood(self.asa_handle, self.ttl_ms, to)
            if err:
                print(f"[briggs] Flood failure err={err}")


class Negotiator(threading.Thread):
    def __init__(self, asa_handle, shandle, requested_obj, *, stopping_flag, send_grasp_wait: bool = False):
        super().__init__(daemon=True)
        self.asa_handle = asa_handle
        self.shandle = shandle
        self.obj = requested_obj
        self.stopping_flag = stopping_flag
        self.send_grasp_wait = bool(send_grasp_wait)

    def run(self):
        prng = random.SystemRandom()

        # reserves and wait time per session
        reserves = prng.randint(100, 400)
        wt = prng.randint(9000, 20000)

        try:
            currency = str(self.obj.value[0])
            amount = int(self.obj.value[1])
        except Exception:
            currency, amount = "", 0

        print(f"[briggs] New session reserves={reserves} wait={wt}ms request={currency} {amount} dry={getattr(self.obj, 'dry', False)}")

        if currency != "NZD":
            cg.end_negotiate(self.asa_handle, self.shandle, False, reason="Invalid currency")
            return

        # Decide first offer
        if amount > reserves // 2:
            proffer = reserves // 2
        else:
            proffer = amount

        # Offer loop
        answer = self.obj
        try:
            answer.value = ["NZD", int(proffer)]
        except Exception:
            pass

        step = 1
        while not self.stopping_flag[0]:
            # optional WAIT path (random)
            if self.send_grasp_wait and (reserves ^ step) & 1:
                we = cg.negotiate_wait(self.asa_handle, self.shandle, wt)
                if we == cg.errors.ok:
                    time.sleep(min(10.0, wt / 1000.0))

            err, tsh, peer_obj = cg.negotiate_step(self.asa_handle, self.shandle, answer, 1000)

            if err == cg.errors.ok and tsh is None:
                print("[briggs] Negotiation concluded")
                return

            if err:
                # peer rejected / loop exhausted etc.
                print(f"[briggs] negotiate_step err={err}")
                return

            self.shandle = tsh
            answer = peer_obj

            try:
                currency = str(answer.value[0])
                amount = int(answer.value[1])
            except Exception:
                currency, amount = "", 0

            if currency != "NZD":
                cg.end_negotiate(self.asa_handle, self.shandle, False, reason="Invalid currency")
                return

            # peer is asking again; adjust proffer upward a bit if we can
            if amount > reserves:
                # not enough resource
                reason = "Insufficient funds" if (reserves % 2) else "Недостаточно средств"
                cg.end_negotiate(self.asa_handle, self.shandle, False, reason=reason)
                return

            # be a bit mean, but move toward acceptance
            proffer = min(reserves, max(proffer + 10, amount - 1))
            answer.value = ["NZD", int(proffer)]
            print(f"[briggs] Step {step}: peer asks {amount}; offering {proffer}")
            step += 1


class NegotiatorWaitPushDemo(threading.Thread):
    """Demo mode to validate WAIT->responder push behavior.

    Flow:
      1) Responder sends initial M_NEGOTIATE using gsend (non-blocking).
      2) Wait for peer M_WAIT.
      3) When "resource becomes available", push a new M_NEGOTIATE.
      4) Optionally wait for peer M_END to show session completion.
    """

    def __init__(self, asa_handle, shandle, requested_obj, *, stopping_flag):
        super().__init__(daemon=True)
        self.asa_handle = asa_handle
        self.shandle = shandle
        self.obj = requested_obj
        self.stopping_flag = stopping_flag

    def run(self):
        sid = int(getattr(self.shandle, "id_value"))

        prng = random.SystemRandom()
        reserves = prng.randint(150, 350)
        delay_s = prng.uniform(0.4, 1.8)

        try:
            currency = str(self.obj.value[0])
            amount = int(self.obj.value[1])
        except Exception:
            currency, amount = "", 0

        print(f"[briggs][wait-push-demo] sid={sid} reserves={reserves} request={currency} {amount}")

        if currency != "NZD":
            cg.end_negotiate(self.asa_handle, self.shandle, False, reason="Invalid currency")
            return

        # Build and send an initial offer without blocking.
        proffer = max(1, min(reserves // 2, amount))
        try:
            self.obj.value = ["NZD", int(proffer)]
        except Exception:
            pass
        self.obj.neg = True
        self.obj.discoverable = True

        msg0 = [cg.M_NEGOTIATE, sid, _obj_to_list(self.obj)]
        se = cg.gsend(self.asa_handle, self.shandle, msg0)
        print(f"[briggs][wait-push-demo] sent initial offer={proffer} gsend err={se}")
        if se:
            return

        rounds_left = prng.randint(1, 3)

        while rounds_left > 0 and not self.stopping_flag[0]:
            err, payload = cg.grecv(self.asa_handle, self.shandle, 10000)
            if err:
                print(f"[briggs][wait-push-demo] grecv err={err}")
                return
            try:
                mtype = int(payload[0])
            except Exception:
                mtype = -1

            if mtype == cg.M_END:
                print(f"[briggs][wait-push-demo] sid={sid} peer ended: {payload}")
                return

            if mtype == cg.M_NEGOTIATE:
                try:
                    amount = int(payload[2][3][1])
                except Exception:
                    amount = amount

                decision = prng.random()
                if decision < 0.2:
                    e = cg.end_negotiate(self.asa_handle, self.shandle, True)
                    print(f"[briggs][wait-push-demo] sid={sid} ended early accept, err={e}")
                    return
                wt = prng.randint(1200, 4500)
                we = cg.negotiate_wait(self.asa_handle, self.shandle, wt)
                print(f"[briggs][wait-push-demo] sid={sid} got counter; sent WAIT ttl={wt}ms err={we}")
                time.sleep(delay_s)

                bump = prng.randint(10, 35)
                proffer2 = min(reserves, max(proffer + bump, amount))
                try:
                    self.obj.value = ["NZD", int(proffer2)]
                except Exception:
                    pass
                msg1 = [cg.M_NEGOTIATE, sid, _obj_to_list(self.obj)]
                se2 = cg.gsend(self.asa_handle, self.shandle, msg1)
                print(f"[briggs][wait-push-demo] pushed offer={proffer2} gsend err={se2}")

                rounds_left -= 1
                continue

            if mtype == cg.M_WAIT:
                print(f"[briggs][wait-push-demo] sid={sid} got WAIT; will push new offer after {delay_s:.2f}s")
                time.sleep(delay_s)
                bump = prng.randint(10, 35)
                proffer2 = min(reserves, max(proffer + bump, amount))
                try:
                    self.obj.value = ["NZD", int(proffer2)]
                except Exception:
                    pass
                msg1 = [cg.M_NEGOTIATE, sid, _obj_to_list(self.obj)]
                se2 = cg.gsend(self.asa_handle, self.shandle, msg1)
                print(f"[briggs][wait-push-demo] pushed offer={proffer2} gsend err={se2}")
                rounds_left -= 1
                continue

            print(f"[briggs][wait-push-demo] sid={sid} unexpected payload {payload}")
            return

        # Best-effort: wait for peer END so capture shows completion.
        err2, payload2 = cg.grecv(self.asa_handle, self.shandle, 10000)
        if err2:
            print(f"[briggs][wait-push-demo] sid={sid} final grecv err={err2}")
            return
        try:
            mtype2 = int(payload2[0])
        except Exception:
            mtype2 = -1
        if mtype2 == cg.M_END:
            print("[briggs][wait-push-demo] got END; done")
        else:
            print(f"[briggs][wait-push-demo] got {payload2}")


def main(argv: Optional[list[str]] = None) -> int:
    cg.configure_logging()
    ap = argparse.ArgumentParser()
    ap.add_argument("--asa-name", default="Briggs-CoAP")

    ap.add_argument("--obj-ex1", type=int, default=DEFAULT_OBJ_EX1)
    ap.add_argument("--obj-ex2", type=int, default=DEFAULT_OBJ_EX2)
    ap.add_argument("--obj-ex3", type=int, default=DEFAULT_OBJ_EX3)

    ap.add_argument("--bind", default="::", help="Bind address for in-process CoAP server")
    ap.add_argument("--coap-port", type=int, default=5683, help="UDP port for local CoAP endpoint")
    ap.add_argument("--path", default=".well-known/grasp-coap", help="CoAP resource path")

    ap.add_argument("--listen-self", action="store_true", help="Listen to own LL multicasts (testing only)")
    ap.add_argument("--diagnose", action="store_true", help="Enable inbound parse diagnostics")
    ap.add_argument("--test-mode", action="store_true", help="Enable extra GRASP debug prints")
    ap.add_argument("--strict-coap", action="store_true", help="Forbid TCP and legacy multicast fallback")
    ap.add_argument("--enable-wait", action="store_true", help="Enable experimental M_WAIT support (not in baseline)")

    ap.add_argument("--flood-interval-s", type=float, default=60.0)
    ap.add_argument("--flood-ttl-ms", type=int, default=59000)
    ap.add_argument(
        "--send-grasp-wait",
        action="store_true",
        help="Send GRASP M_WAIT messages during negotiation (debug only; CoAP transport already has a polling WAIT/NOOP mechanism)",
    )
    ap.add_argument(
        "--wait-push-demo",
        action="store_true",
        help="Demo: initiator sends M_WAIT; responder later pushes M_NEGOTIATE using a new responder->initiator ClientContext (no M_NOOP polling)",
    )
    ap.add_argument(
        "--wait-only",
        action="store_true",
        help="Responder only: immediately reply with GRASP M_WAIT to each new negotiation request (no NEGOTIATE/END)",
    )
    ap.add_argument(
        "--wait-ttl-ms",
        type=int,
        default=5000,
        help="TTL (ms) for M_WAIT when using --wait-only",
    )

    args = ap.parse_args(argv)
    if (args.send_grasp_wait or args.wait_push_demo or args.wait_only) and not args.enable_wait:
        ap.error("WAIT options require --enable-wait (experimental, not baseline)")

    handle = _common_init(args)

    err, asa_handle = cg.register_asa(str(args.asa_name))
    if err:
        print(f"[briggs] register_asa failed err={err}")
        return 2

    _print_ifaces()

    stopping_flag = [False]

    def _on_stop(_signum, _frame):
        if not stopping_flag[0]:
            print("\n[briggs] stopping... (press Ctrl+C again to force)")
        stopping_flag[0] = True
        try:
            if handle is not None:
                handle.stop()
        except Exception:
            pass

    _install_sig_handlers(_on_stop)

    print(f"[briggs] ASA={args.asa_name} local_coap=coap://[{args.bind}]:{args.coap_port}/{str(args.path).strip('/')}" )

    # EX1: flood objective
    obj1 = cg.cobjective(int(args.obj_ex1))
    obj1.synch = True
    obj1.loop_count = 4
    e1 = cg.register_obj(asa_handle, obj1, overlap=True, discoverable=True)
    if e1:
        print(f"[briggs] register_obj EX1 failed err={e1}")
        return 2

    Flooder(asa_handle, obj1, interval_s=float(args.flood_interval_s), ttl_ms=int(args.flood_ttl_ms), stopping_flag=stopping_flag).start()
    print("[briggs] Flooder started")

    # EX2: synchronize listener objective
    obj2 = cg.cobjective(int(args.obj_ex2))
    obj2.synch = True
    obj2.loop_count = 4
    obj2.value = [1, "two", 3]
    # Rapid Mode is outside the supported cGRASP baseline; register the
    # synchronize objective without it.
    e2 = cg.register_obj(asa_handle, obj2, overlap=True, discoverable=True)
    if e2:
        print(f"[briggs] register_obj EX2 failed err={e2}")
        return 2

    ls = cg.listen_synchronize(asa_handle, obj2)
    print(f"[briggs] Listening for synch requests on EX2 err={ls}")

    # EX3: negotiation listener objective
    obj3 = cg.cobjective(int(args.obj_ex3))
    obj3.neg = True
    obj3.discoverable = True
    obj3.value = ["NZD", 0]

    e3 = cg.register_obj(asa_handle, obj3, overlap=True, discoverable=True)
    if e3:
        print(f"[briggs] register_obj EX3 failed err={e3}")
        return 2

    print(f"[briggs] Ready to negotiate EX3 (obj={args.obj_ex3}) as listener")

    q: "queue.Queue[tuple]" = queue.Queue()

    def _listen_worker():
        while True:
            try:
                item = cg.listen_negotiate(asa_handle, obj3)
                q.put(item)
            except Exception as ex:
                q.put((9999, None, ex))
                return

    threading.Thread(target=_listen_worker, daemon=True, name="listen_negotiate_worker").start()

    while not stopping_flag[0]:
        try:
            item = q.get(timeout=0.25)
        except queue.Empty:
            continue

        err, shandle, req_obj = item
        if err == 9999:
            print(f"[briggs] listen worker exception: {req_obj}")
            continue
        if err:
            print(f"[briggs] listen_negotiate err={err}")
            continue

        if bool(args.wait_only):
            wt = max(50, int(args.wait_ttl_ms))
            we = cg.negotiate_wait(asa_handle, shandle, wt)
            print(f"[briggs][wait-only] sent M_WAIT ttl={wt}ms err={we}")
            continue

        if bool(args.wait_push_demo):
            NegotiatorWaitPushDemo(asa_handle, shandle, req_obj, stopping_flag=stopping_flag).start()
        else:
            Negotiator(asa_handle, shandle, req_obj, stopping_flag=stopping_flag, send_grasp_wait=bool(args.send_grasp_wait)).start()

    try:
        cg.deregister_asa(asa_handle, str(args.asa_name))
    except Exception:
        pass
    audit = cg.get_transport_audit() if hasattr(cg, "get_transport_audit") else {}
    print(f"[briggs] TEST_RESULT audit={audit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
