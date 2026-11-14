#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""AskDNSSD: DNS-SD requester ASA over cGRASP/CoAP.

Ported from graspy's ``ASA-examples/AskDNSSD.py``.  It discovers (or is given)
a GetDNSSD responder, negotiates the demonstration objective 41101
(``DNS-SD``), and prints the returned records.

Run (terminal 1, server):

    python ASA-examples/GetDNSSD.py --bind ::1 --coap-port 5683

Run (terminal 2, client):

    python ASA-examples/AskDNSSD.py --bind ::1 --coap-port 15683 \
        --peer coap://[::1]:5683 --domain _http._tcp.local
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cgrasp import cgrasp as cg  # noqa: E402
from _common import (  # noqa: E402
    OBJ_DNS_SD,
    add_common_args,
    err_text,
    objective,
    peer_locator,
    start,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="AskDNSSD: DNS-SD requester over cGRASP/CoAP")
    add_common_args(ap, default_port=15683)
    ap.add_argument("--peer", default="",
                    help="direct peer base URI, e.g. coap://[::1]:5683")
    ap.add_argument("--same-host", action="store_true",
                    help="use coap://[::1]:--peer-port as the peer")
    ap.add_argument("--peer-port", type=int, default=5683,
                    help="peer port used by --same-host")
    ap.add_argument("--domain", action="append", default=[],
                    help="DNS-SD domain to query (repeatable)")
    ap.add_argument("--timeout-ms", type=int, default=5000)
    ap.add_argument("--iterations", type=int, default=1,
                    help="number of query rounds; 0 means loop forever")
    args = ap.parse_args(argv)

    if not args.domain:
        args.domain = ["_http._tcp.local"]

    asa = start(args, "AskDNSSD")
    obj = objective(OBJ_DNS_SD, neg=True, discoverable=False)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        print(f"[AskDNSSD] register_obj failed: {err_text(err)}", flush=True)
        return 2

    peer_desc = args.peer or (f"coap://[::1]:{args.peer_port}" if args.same_host else "<discovery>")
    print(f"[AskDNSSD] ready; peer={peer_desc}", flush=True)

    rounds = 0
    ok = True
    while args.iterations <= 0 or rounds < args.iterations:
        rounds += 1
        for domain in args.domain:
            peer = peer_locator(args, asa, obj, args.timeout_ms)
            if peer is None:
                print(f"[AskDNSSD] no responder discovered for {domain}", flush=True)
                ok = False
                continue
            obj.value = domain
            obj.loop_count = 8
            err, shandle, answer = cg.req_negotiate(asa, obj, peer, args.timeout_ms)
            if err:
                print(f"[AskDNSSD] req_negotiate: {err_text(err)}", flush=True)
                ok = False
                continue
            records = getattr(answer, "value", None)
            if shandle is not None:
                cg.end_negotiate(asa, shandle, True)
            print(f"[AskDNSSD] {domain} -> {json.dumps(records, ensure_ascii=False)}",
                  flush=True)

    try:
        cg.deregister_asa(asa, "AskDNSSD")
    except Exception:
        pass
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
