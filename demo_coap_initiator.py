#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import argparse
import asyncio
import threading

from cgrasp import cgrasp as cg

from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge, install_cgrasp_unicast_over_coap
from cgrasp.coap_server import make_default_cgrasp_server
#python3 demo_coap_initiator.py --asa InitiatorASA --objnum 40001 --coap-port 5684 --coap-path .well-known/grasp-coap --mc-path .well-known/grasp-coap --listen-self --dull --discover-timeout-ms 3000 --neg-timeout-ms 5000 --flush

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="cGRASP initiator demo: CoAP-based Discovery (LL multicast wrapped in CoAP) + CoAP-based unicast negotiation.",
    )
    p.add_argument("--objnum", type=int, default=40001, help="Objective number to discover/negotiate (default: 40001)")
    p.add_argument("--asa", type=str, default="InitiatorASA", help="ASA name")
    p.add_argument("--coap-port", type=int, default=5684, help="Local CoAP unicast server UDP port (only needed for peer symmetry)")
    p.add_argument("--coap-path", type=str, default=".well-known/grasp-coap", help="CoAP unicast resource path")
    p.add_argument("--mc-path", type=str, default=".well-known/grasp-coap", help="CoAP Uri-Path used for multicast wrapping")
    p.add_argument(
        "--listen-self",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Whether to process own LL multicasts (needed if running both peers on the same host/interface)",
    )
    p.add_argument(
        "--dull",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run in DULL mode (bypass ACP/QUADS security requirements)",
    )
    p.add_argument("--discover-timeout-ms", type=int, default=3000, help="discover() timeout (ms)")
    p.add_argument("--neg-timeout-ms", type=int, default=5000, help="req_negotiate() timeout (ms)")
    p.add_argument(
        "--flush",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Flush discovery cache before sending discover()",
    )
    return p.parse_args()


def _pretty_locator(loc: object) -> str:
    parts = []
    for k in ("is_uri", "is_ipaddress", "is_fqdn"):
        try:
            if bool(getattr(loc, k)):
                parts.append(k)
        except Exception:
            pass
    try:
        parts.append(f"locator={getattr(loc, 'locator')}")
    except Exception:
        pass
    for k in ("port", "protocol", "ifi", "expire"):
        try:
            parts.append(f"{k}={getattr(loc, k)}")
        except Exception:
            pass
    return "{" + ", ".join(parts) + "}"


def _asa_worker(args: argparse.Namespace, result_holder: dict, done_evt: threading.Event) -> None:
    cg.skip_dialogue(testing=False, selfing=bool(args.listen_self), diagnosing=True, be_dull=bool(args.dull))

    mc_tuple = tuple(seg for seg in args.mc_path.strip("/").split("/") if seg)
    cg.set_multicast_coap(True, uri_path=mc_tuple)

    # Install unicast transport hook (neg/synch over CoAP).
    install_cgrasp_unicast_over_coap(path=str(args.coap_path), default_port=5683)

    err, asa = cg.register_asa(str(args.asa))
    if err:
        raise RuntimeError(f"register_asa failed: {err}")

    obj = cg.cobjective(int(args.objnum))
    obj.neg = True
    obj.loop_count = 6
    obj.value = "hello-from-initiator"

    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        raise RuntimeError(f"register_obj failed: {err}")

    # ---- Discovery (must be CoAP-wrapped multicast) ----
    derr, locs = cg.discover(asa, obj, int(args.discover_timeout_ms), flush=bool(args.flush))
    result_holder["discover_err"] = derr
    result_holder["locs"] = locs

    if derr or not locs:
        done_evt.set()
        return

    peer = locs[0]
    result_holder["peer"] = peer

    # ---- Negotiation over CoAP unicast (via socket factory shim) ----
    nerr, sh, out = cg.req_negotiate(asa, obj, peer, int(args.neg_timeout_ms))
    result_holder["neg_err"] = nerr
    result_holder["sh"] = sh
    result_holder["out"] = out

    # If negotiation continues, accept.
    if nerr == cg.errors.ok and sh is not None:
        eerr = cg.end_negotiate(asa, sh, True)
        result_holder["end_err"] = eerr

    done_evt.set()


async def main() -> None:
    cg.configure_logging()
    args = _parse_args()

    # Start local CoAP unicast endpoint for symmetry (not strictly needed for an initiator-only demo).
    bridge = CgraspCoapApiBridge()
    srv = make_default_cgrasp_server(bridge.handle_post, bind=("::", int(args.coap_port)), base_path=str(args.coap_path))
    await srv.start()
    print(f"[initiator] CoAP unicast endpoint (symmetry): udp/{args.coap_port} /{args.coap_path.strip('/')}")

    result_holder: dict = {}
    done_evt = threading.Event()

    # NOTE: cgrasp.tprint() parses thread names and breaks if they contain
    # parentheses. Python 3.10+ defaults Thread names to "Thread-N (target)"
    # when a target is provided, so we set a safe name here.
    t = threading.Thread(
        target=_asa_worker,
        args=(args, result_holder, done_evt),
        daemon=True,
        name=f"InitiatorWorker-{args.asa}",
    )
    t.start()

    await asyncio.to_thread(done_evt.wait)

    derr = result_holder.get("discover_err")
    locs = result_holder.get("locs") or []

    if derr or not locs:
        print(f"[initiator] discover failed: err={derr} locs={len(locs)}")
        if locs:
            for i, loc in enumerate(locs):
                print(f"[initiator] loc[{i}] = {_pretty_locator(loc)}")
        return

    peer = result_holder.get("peer")
    print(f"[initiator] discover OK: using peer locator = {_pretty_locator(peer)}")

    nerr = result_holder.get("neg_err")
    sh = result_holder.get("sh")
    out = result_holder.get("out")

    if nerr == cg.errors.ok and sh is None:
        print(f"[initiator] negotiation OK: peer accepted immediately; result={out!r}")
        return

    if nerr == cg.errors.ok and sh is not None:
        end_err = result_holder.get("end_err")
        print(f"[initiator] negotiation in-progress; sent END(accept). end_err={end_err} last_offer={out!r}")
        return

    print(f"[initiator] negotiation failed: err={nerr} out={out!r}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
