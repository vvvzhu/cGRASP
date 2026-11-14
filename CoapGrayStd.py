#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""CoAP-based Gray ASA (initiator) using cgrasp.cgrasp standard CoAP multicast.

This is a "Gray-like" demonstration ASA adapted from Gray.py, but running on
cgrasp.cgrasp with:
- Standard CoAP multicast Discovery: ff02::fd:5683, resource /.well-known/grasp-coap
    (responders return M_RESPONSE as the FETCH Content response on the same
    /.well-known/grasp-coap resource; callback POST is disabled)
- Unicast negotiation over CoAP using discovered URI locators

Typical usage (two terminals, same host):
  Terminal A (listener):
    python3 CoapBriggsStd.py --listen-self --coap-port 5683

  Terminal B (initiator):
    python3 CoapGrayStd.py --listen-self --coap-port 15683

On two different hosts, both can use the default port 5683.

Notes:
- Runs in DULL mode by default to avoid ACP/TLS dependencies.
- Ctrl+C is handled: first Ctrl+C requests a graceful stop, second forces exit.
"""

from __future__ import annotations

import argparse
import os
import queue
import random
import signal
import socket
import sys
import threading
import time
from typing import Optional

try:
    from cgrasp import cgrasp as cg
except Exception:  # pragma: no cover
    from cgrasp import cgrasp as cg  # type: ignore


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


def _parse_payload_as_msg(payload):
    """Best-effort parse of a decoded GRASP list into a cgrasp.cgrasp message object."""
    try:
        return cg._parse_msg(payload)
    except Exception:
        return None


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
    try:
        cg.set_standard_coap_multicast(True, uri_path=(".well-known", "grasp-coap"))
    except Exception:
        pass
    try:
        cg.set_advertise_coap_unicast(True, port=int(args.coap_port), path=str(args.path))
    except Exception:
        pass

    return handle


def _make_obj(num: int, *, neg: bool, synch: bool = False, value=None):
    obj = cg.cobjective(int(num))
    obj.neg = bool(neg)
    obj.synch = bool(synch)
    obj.dry = False
    obj.discoverable = bool(args.discoverable) if False else True  # overwritten by register_obj args
    obj.loop_count = int(getattr(cg, "GRASP_DEF_LOOPCT", 6))
    obj.value = value
    return obj


def _print_ifaces() -> None:
    try:
        ifaces = socket.if_nameindex()
    except Exception:
        ifaces = []
    if ifaces:
        print("[hint] interfaces:")
        for idx, name in ifaces:
            print(f"  - {name} (ifindex={idx})")


def _discover_peer(asa_handle, obj, *, timeout_ms: int, flush: bool) -> list:
    derr, locs = cg.discover(asa_handle, obj, timeout_ms, flush=flush)
    if derr:
        print(f"[gray] discover err={derr}")
        return []
    return locs or []


def main(argv: Optional[list[str]] = None) -> int:
    cg.configure_logging()
    ap = argparse.ArgumentParser()
    ap.add_argument("--asa-name", default="Gray-CoAP")

    ap.add_argument("--obj", type=int, default=DEFAULT_OBJ_EX3, help="Negotiation objective number")
    ap.add_argument("--timeout-ms", type=int, default=3000)
    ap.add_argument("--sleep-s", type=float, default=5.0)

    ap.add_argument("--bind", default="::", help="Bind address for in-process CoAP server")
    ap.add_argument("--coap-port", type=int, default=15683, help="Local plaintext CoAP UDP port for same-host tests")
    ap.add_argument("--path", default=".well-known/grasp-coap", help="CoAP resource path")

    ap.add_argument("--listen-self", action="store_true", help="Listen to own LL multicasts (testing only)")
    ap.add_argument("--diagnose", action="store_true", help="Enable inbound parse diagnostics")
    ap.add_argument("--test-mode", action="store_true", help="Enable extra GRASP debug prints")
    ap.add_argument("--strict-coap", action="store_true", help="Forbid TCP and legacy multicast fallback")
    ap.add_argument("--enable-wait", action="store_true", help="Enable experimental M_WAIT support (not in baseline)")
    ap.add_argument("--test-iterations", type=int, default=0, help="Exit after N negotiation attempts (0 = run forever)")
    ap.add_argument("--fixed-request", type=int, default=0, help="Use a fixed NZD request amount for deterministic tests")

    ap.add_argument("--no-sync-tests", action="store_true", help="Skip initial synchronize() test calls")
    ap.add_argument(
        "--send-grasp-wait",
        action="store_true",
        help="Send GRASP M_WAIT messages during negotiation (debug only; CoAP transport already has a polling WAIT/NOOP mechanism)",
    )
    ap.add_argument(
        "--wait-push-demo",
        action="store_true",
        help="Demo: send M_WAIT then block on grecv to receive responder-pushed M_NEGOTIATE (no M_NOOP polling)",
    )

    args = ap.parse_args(argv)
    if (args.send_grasp_wait or args.wait_push_demo) and not args.enable_wait:
        ap.error("WAIT options require --enable-wait (experimental, not baseline)")

    handle = _common_init(args)

    err, asa_handle = cg.register_asa(str(args.asa_name))
    if err:
        print(f"[gray] register_asa failed err={err}")
        return 2

    stopping = False

    def _on_stop(_signum, _frame):
        nonlocal stopping
        if not stopping:
            print("\n[gray] stopping... (press Ctrl+C again to force)")
        stopping = True
        try:
            if handle is not None:
                handle.stop()
        except Exception:
            pass

    _install_sig_handlers(_on_stop)

    _print_ifaces()

    # Negotiation objective (like EX3)
    obj3 = cg.cobjective(int(args.obj))
    obj3.neg = True
    obj3.discoverable = True

    rerr = cg.register_obj(asa_handle, obj3, overlap=True, discoverable=True)
    if rerr:
        print(f"[gray] register_obj failed err={rerr}")
        return 2

    prng = random.SystemRandom()
    failct = 0
    attempts = 0
    successes = 0

    print(f"[gray] ASA={args.asa_name} obj={args.obj} local_coap=coap://[{args.bind}]:{args.coap_port}/{str(args.path).strip('/')}" )
    print("[gray] Ready to negotiate as requester")

    while not stopping and (int(args.test_iterations) <= 0 or attempts < int(args.test_iterations)):
        attempts += 1
        iwant = int(args.fixed_request) if int(args.fixed_request) > 0 else prng.randint(10, 500)
        limit = int(0.7 * iwant)

        obj3.value = ["NZD", iwant]
        obj3.loop_count = prng.randint(4, 20)
        # obj3.loop_count = 1
        obj3.dry = bool(iwant & 4)

        if not iwant % 7:
            obj3.value[0] = "USD"  # intentionally wrong sometimes

        print(f"[gray] Asking for {obj3.value[0]} {iwant}; dry={obj3.dry}; loop={obj3.loop_count}")

        # discover a peer
        flush = bool(failct > 3)
        if flush:
            print("[gray] Flushing discovery cache")
            failct = 0

        locs = _discover_peer(asa_handle, obj3, timeout_ms=int(args.timeout_ms), flush=flush)
        if not locs:
            print("[gray] Discovery failed")
            failct += 1
            time.sleep(min(args.sleep_s, 2.0))
            continue

        peer = locs[0]
        try:
            print(f"[gray] Discovered locator: {getattr(peer, 'locator', peer)}")
        except Exception:
            pass

        # attempt negotiation
        nerr, shandle, answer = cg.req_negotiate(asa_handle, obj3, peer, int(args.timeout_ms))

        if nerr:
            print(f"[gray] req_negotiate error={nerr} answer={answer}")
            failct += 1
            time.sleep(args.sleep_s)
            continue

        if shandle is None:
            # accepted immediately
            print(f"[gray] Negotiation succeeded immediately: {getattr(answer, 'value', None)}")
            successes += 1
            time.sleep(args.sleep_s)
            continue

        # strict multi-round negotiation
        try:
            offered = int(answer.value[1])
            currency = str(answer.value[0])
        except Exception:
            offered = 0
            currency = ""

        print(f"[gray] Peer offered {currency} {offered}")

        proffer = int(0.9 * iwant)
        step = 1
        concluded = False

        while not concluded and not stopping:
            if currency != "NZD":
                print(f"[gray] Rejecting invalid currency: {currency}")
                cg.end_negotiate(asa_handle, shandle, False, reason="Invalid currency")
                break

            if bool(args.wait_push_demo):
                sid = int(getattr(shandle, "id_value"))
                rounds_left = prng.randint(1, 3)

                while rounds_left > 0 and not concluded and not stopping:
                    # Step A: send counter M_NEGOTIATE (randomized).
                    bump = prng.randint(1, 12)
                    target = max(1, int(0.8 * iwant))
                    counter = max(1, min(iwant, max(int(offered) + bump, target)))
                    try:
                        answer.value = ["NZD", int(counter)]
                    except Exception:
                        pass
                    msg_step = [cg.M_NEGOTIATE, sid, _obj_to_list(answer)]
                    se = cg.gsend(asa_handle, shandle, msg_step)
                    print(f"[gray][wait-push-demo] sid={sid} sent counter M_NEGOTIATE={counter} gsend err={se}")
                    if se:
                        concluded = True
                        break

                    ge1, payload1 = cg.grecv(asa_handle, shandle, int(args.timeout_ms))
                    if ge1:
                        print(f"[gray][wait-push-demo] sid={sid} wait-stage grecv err={ge1}")
                        cg.end_negotiate(asa_handle, shandle, False, reason="No response from responder")
                        concluded = True
                        break

                    msg1 = _parse_payload_as_msg(payload1)
                    if not msg1:
                        print(f"[gray][wait-push-demo] sid={sid} invalid response payload={payload1}")
                        cg.end_negotiate(asa_handle, shandle, False, reason="Invalid response payload")
                        concluded = True
                        break

                    msg = msg1
                    if msg1.mtype == cg.M_WAIT:
                        wt = int(getattr(msg1, "ttl", 0) or 0)
                        print(f"[gray][wait-push-demo] sid={sid} got WAIT ttl={wt}ms; waiting for pushed reply")
                        extra_wait = prng.randint(2000, 6000)
                        ge2, payload2 = cg.grecv(asa_handle, shandle, max(1000, wt + extra_wait))
                        if ge2:
                            print(f"[gray][wait-push-demo] sid={sid} push-stage grecv err={ge2}")
                            cg.end_negotiate(asa_handle, shandle, False, reason="Timeout waiting for pushed reply")
                            concluded = True
                            break
                        msg2 = _parse_payload_as_msg(payload2)
                        if not msg2:
                            print(f"[gray][wait-push-demo] sid={sid} invalid pushed payload={payload2}")
                            cg.end_negotiate(asa_handle, shandle, False, reason="Invalid pushed message")
                            concluded = True
                            break
                        msg = msg2

                    if msg.mtype == cg.M_END:
                        print(f"[gray][wait-push-demo] sid={sid} got END; done")
                        concluded = True
                        break

                    if msg.mtype == cg.M_NEGOTIATE:
                        try:
                            offered2 = int(msg.obj.value[1])
                            currency2 = str(msg.obj.value[0])
                        except Exception:
                            offered2, currency2 = 0, ""
                        print(f"[gray][wait-push-demo] sid={sid} got offer {currency2} {offered2}")

                        decision = prng.random()
                        if currency2 == "NZD" and offered2 > 0 and decision < 0.35:
                            e = cg.end_negotiate(asa_handle, shandle, True)
                            print(f"[gray][wait-push-demo] sid={sid} accepted offer, end_negotiate err={e}")
                            concluded = True
                            break
                        if decision > 0.9:
                            e = cg.end_negotiate(asa_handle, shandle, False, reason="Random decline")
                            print(f"[gray][wait-push-demo] sid={sid} declined offer, end_negotiate err={e}")
                            concluded = True
                            break

                        offered = offered2
                        rounds_left -= 1
                        continue

                    if msg.mtype == cg.M_WAIT:
                        rounds_left -= 1
                        continue

                    print(f"[gray][wait-push-demo] sid={sid} unexpected mtype={msg.mtype}")
                    cg.end_negotiate(asa_handle, shandle, False, reason="Unexpected response")
                    concluded = True
                    break

                if not concluded:
                    e = cg.end_negotiate(asa_handle, shandle, True)
                    print(f"[gray][wait-push-demo] sid={sid} final accept, end_negotiate err={e}")
                    concluded = True
                break

            if offered >= proffer:
                # acceptable
                e = cg.end_negotiate(asa_handle, shandle, True)
                print(f"[gray] Accepted offer {offered}, end_negotiate err={e}")
                concluded = True
                if e == cg.errors.ok:
                    successes += 1
                break

            # counter-offer
            try:
                answer.value[1] = int(proffer)
            except Exception:
                answer.value = ["NZD", int(proffer)]

            # Optional: GRASP-level WAIT (not generally needed for CoAP transport).
            if args.send_grasp_wait and (iwant ^ step) & 1 and int(args.timeout_ms) > 1500:
                wt = prng.randint(500, min(5000, int(args.timeout_ms)))
                we = cg.negotiate_wait(asa_handle, shandle, wt)
                print(f"[gray] Sent WAIT ttl={wt}ms err={we}")

            rerr, tsh, new_answer = cg.negotiate_step(asa_handle, shandle, answer, int(args.timeout_ms))

            if rerr == cg.errors.ok and tsh is None:
                print("[gray] Negotiation concluded by peer")
                concluded = True
                break

            if rerr:
                print(f"[gray] negotiate_step error={rerr} new_answer={new_answer}")
                concluded = True
                break

            shandle = tsh
            answer = new_answer

            try:
                offered = int(answer.value[1])
                currency = str(answer.value[0])
            except Exception:
                offered = 0
                currency = ""

            print(f"[gray] Step {step}: peer now offers {currency} {offered}")
            step += 1

            proffer = int(0.9 * proffer)
            if proffer < limit:
                print("[gray] Proffer below limit; declining")
                cg.end_negotiate(asa_handle, shandle, False, reason="You are mean!")
                concluded = True

        time.sleep(args.sleep_s)

    try:
        cg.deregister_asa(asa_handle, str(args.asa_name))
    except Exception:
        pass
    audit = cg.get_transport_audit() if hasattr(cg, "get_transport_audit") else {}
    print(f"[gray] TEST_RESULT attempts={attempts} successes={successes} audit={audit}")
    try:
        if handle is not None:
            handle.stop()
    except Exception:
        pass
    if int(args.test_iterations) > 0 and successes < 1:
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
