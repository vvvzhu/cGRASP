#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import argparse
import asyncio
import threading
import time

from cgrasp import cgrasp as cg

from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge, install_cgrasp_unicast_over_coap
from cgrasp.coap_server import make_default_cgrasp_server

#python3 demo_coap_responder.py --asa ResponderASA --objnum 40001 --coap-port 5683 --coap-path .well-known/grasp-coap --mc-path .well-known/grasp-coap --listen-self --dull --once --timeout-ms 5000

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="cGRASP responder demo: CoAP-based Discovery (LL multicast wrapped in CoAP) + CoAP-based unicast negotiation.",
    )
    p.add_argument("--objnum", type=int, default=40001, help="Objective number to serve (default: 40001)")
    p.add_argument("--asa", type=str, default="ResponderASA", help="ASA name")
    p.add_argument("--coap-port", type=int, default=5683, help="Local CoAP unicast server UDP port")
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
    p.add_argument(
        "--once",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Exit after handling one negotiation",
    )
    p.add_argument("--timeout-ms", type=int, default=5000, help="Responder-side step timeouts (ms)")
    return p.parse_args()


def _asa_worker(args: argparse.Namespace, ready_evt: threading.Event, done_evt: threading.Event) -> None:
    # Avoid interactive prompts during cgrasp init.
    cg.skip_dialogue(testing=False, selfing=bool(args.listen_self), diagnosing=True, be_dull=bool(args.dull))

    # Ensure Discovery/Flood multicasts are wrapped as CoAP messages.
    mc_tuple = tuple(seg for seg in args.mc_path.strip("/").split("/") if seg)
    cg.set_multicast_coap(True, uri_path=mc_tuple)

    # Ensure Discovery responses advertise a CoAP unicast URI locator.
    cg.set_advertise_coap_unicast(True, port=int(args.coap_port), path=str(args.coap_path))

    # Install unicast transport hook (neg/synch over CoAP).
    install_cgrasp_unicast_over_coap(path=str(args.coap_path), default_port=int(args.coap_port))

    err, asa = cg.register_asa(str(args.asa))
    if err:
        raise RuntimeError(f"register_asa failed: {err}")

    obj = cg.cobjective(int(args.objnum))
    obj.neg = True
    obj.loop_count = 6
    obj.value = "responder-default"

    # Make discoverable immediately (avoids races); we still call listen_negotiate to serve requests.
    err = cg.register_obj(asa, obj, discoverable=True)
    if err:
        raise RuntimeError(f"register_obj failed: {err}")

    # Signal to the asyncio main that ASA is ready.
    ready_evt.set()

    handled = 0
    while True:
        err, sh, req_obj = cg.listen_negotiate(asa, obj)
        if err:
            time.sleep(0.2)
            continue

        handled += 1
        print(f"[responder] got req: obj={req_obj.num} value={getattr(req_obj, 'value', None)!r} loop={req_obj.loop_count}")

        # Demo policy: accept immediately.
        err2 = cg.end_negotiate(asa, sh, True)
        print(f"[responder] end_negotiate -> {err2}")

        if bool(args.once) and handled >= 1:
            done_evt.set()
            return


async def main() -> None:
    cg.configure_logging()
    args = _parse_args()

    ready_evt = threading.Event()
    done_evt = threading.Event()

    # Start local CoAP unicast endpoint that bridges inbound POSTs into cgrasp.
    bridge = CgraspCoapApiBridge()
    srv = make_default_cgrasp_server(bridge.handle_post, bind=("::", int(args.coap_port)), base_path=str(args.coap_path))
    await srv.start()
    print(f"[responder] CoAP unicast endpoint: udp/{args.coap_port} /{args.coap_path.strip('/')}")

    # NOTE: cgrasp.tprint() parses thread names and breaks if they contain
    # parentheses. Python 3.10+ defaults Thread names to "Thread-N (target)"
    # when a target is provided, so we set a safe name here.
    t = threading.Thread(
        target=_asa_worker,
        args=(args, ready_evt, done_evt),
        daemon=True,
        name=f"ResponderWorker-{args.asa}",
    )
    t.start()

    # Wait until ASA finished init (so discovery replies are available).
    await asyncio.to_thread(ready_evt.wait)
    print(f"[responder] cgrasp ready: multicast wrapped path=/{args.mc_path.strip('/')} advertise-unicast=coap://:<{args.coap_port}>/{args.coap_path.strip('/')} dull={args.dull}")

    if bool(args.once):
        await asyncio.to_thread(done_evt.wait)
    else:
        await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
