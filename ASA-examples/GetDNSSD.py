#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""GetDNSSD: DNS-SD responder ASA over cGRASP/CoAP.

Ported from graspy's ``ASA-examples/GetDNSSD.py``.  It registers the
demonstration objective 41101 (``DNS-SD``), accepts a domain name by
negotiation, and returns DNS-SD records.

If ``dnspython`` is installed, PTR/SRV/TXT records are resolved live.  Without
it, a small static demonstration database is used, so the example also works
offline.

Run (terminal 1, server):

    python ASA-examples/GetDNSSD.py --bind ::1 --coap-port 5683

Run (terminal 2, client):

    python ASA-examples/AskDNSSD.py --bind ::1 --coap-port 15683 \
        --peer coap://[::1]:5683 --domain _http._tcp.local
"""

from __future__ import annotations

import argparse
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
from _common import (  # noqa: E402
    OBJ_DNS_SD,
    add_common_args,
    err_text,
    install_stop_handlers,
    objective,
    start,
)

# Offline fallback records.  Keys are the query names used by AskDNSSD.py.
DEMO_DB = {
    "_http._tcp.local": [
        {"name": "demo._http._tcp.local", "target": "demo.local",
         "port": 80, "priority": 0, "weight": 0, "txt": ["path=/"]},
    ],
    "_printer._sub._http._tcp.dns-sd.org.": [
        {"name": "printer._http._tcp.dns-sd.org.", "target": "printer.local",
         "port": 631, "priority": 0, "weight": 0, "txt": ["rp=printers/demo"]},
    ],
    "_ipp._tcp.local": [
        {"name": "office._ipp._tcp.local", "target": "office.local",
         "port": 631, "priority": 0, "weight": 0, "txt": ["rp=ipp/print"]},
    ],
}


def _live_lookup(domain: str):
    """Resolve DNS-SD PTR/SRV/TXT records if dnspython is available."""
    try:
        import dns.resolver
    except ImportError:
        return []
    records = []
    try:
        ptr_answers = dns.resolver.resolve(domain, "PTR")
    except Exception:
        return []
    for ptr in ptr_answers:
        instance = str(getattr(ptr, "target", ptr)).rstrip(".")
        item = {"name": instance, "target": instance, "port": 0,
                "priority": 0, "weight": 0, "txt": []}
        try:
            srv = dns.resolver.resolve(instance, "SRV")[0]
            item.update(target=str(srv.target).rstrip("."), port=int(srv.port),
                        priority=int(srv.priority), weight=int(srv.weight))
        except Exception:
            pass
        try:
            for txt in dns.resolver.resolve(instance, "TXT"):
                item["txt"].extend(
                    part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
                    for part in txt.strings
                )
        except Exception:
            pass
        records.append(item)
    return records


def lookup(domain: str, *, static: bool = False):
    if not static:
        records = _live_lookup(domain)
        if records:
            return records
    return list(DEMO_DB.get(domain, []))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GetDNSSD: DNS-SD responder over cGRASP/CoAP")
    add_common_args(ap, default_port=5683)
    ap.add_argument("--static", action="store_true",
                    help="always use the offline demonstration database")
    args = ap.parse_args(argv)

    asa = start(args, "GetDNSSD")
    obj = objective(OBJ_DNS_SD, neg=True, discoverable=True)
    err = cg.register_obj(asa, obj, discoverable=True)
    if err:
        print(f"[GetDNSSD] register_obj failed: {err_text(err)}", flush=True)
        return 2
    stopping = [False]
    install_stop_handlers(stopping, "GetDNSSD")

    def serve():
        while not stopping[0]:
            err, shandle, request = cg.listen_negotiate(asa, obj)
            if err:
                print(f"[GetDNSSD] listen_negotiate: {err_text(err)}", flush=True)
                continue
            domain = str(getattr(request, "value", ""))
            records = lookup(domain, static=bool(args.static))
            print(f"[GetDNSSD] query {domain!r} -> {len(records)} record(s)", flush=True)
            request.value = records
            step_err, shandle2, _reply = cg.negotiate_step(asa, shandle, request, 5000)
            if step_err:
                print(f"[GetDNSSD] negotiate_step: {err_text(step_err)}", flush=True)
            elif shandle2 is not None:
                cg.end_negotiate(asa, shandle2, True)

    threading.Thread(target=serve, name="GetDNSSD-listener", daemon=True).start()
    time.sleep(0.5)
    print(f"[GetDNSSD] ready on coap://[{args.bind}]:{args.coap_port}/{args.path.strip('/')}",
          flush=True)

    while not stopping[0]:
        time.sleep(0.2)

    try:
        cg.deregister_asa(asa, "GetDNSSD")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
