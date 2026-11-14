#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Mudlark: a demonstration MUD manager over cGRASP/CoAP.

Ported from graspy's ``ASA-examples/Mudlark.py``.  It registers the
demonstration objective 41110 (``MUDURL``), accepts a MUD URL from a
Mudslinger, optionally fetches the MUD JSON, and returns a small status
object.

This is a protocol-flow demo.  It does **not** verify MUD signatures or
enforce policy; production MUD processing is out of scope.

Run (terminal 1, manager):

    python ASA-examples/Mudlark.py --bind ::1 --coap-port 5683

Run (terminal 2, device):

    python ASA-examples/Mudslinger.py --bind ::1 --coap-port 15683 \
        --peer coap://[::1]:5683 --url https://example.org/mud.json
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cgrasp import cgrasp as cg  # noqa: E402
from _common import (  # noqa: E402
    OBJ_MUD_URL,
    add_common_args,
    err_text,
    install_stop_handlers,
    objective,
    start,
)


def fetch_mud(url: str):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read(256 * 1024)
        return {"fetched": True, "bytes": len(body), "content_type": response.headers.get("Content-Type", "")}
    except Exception as exc:
        return {"fetched": False, "error": str(exc)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Mudlark: MUD manager over cGRASP/CoAP")
    add_common_args(ap, default_port=5683)
    ap.add_argument("--fetch", action="store_true",
                    help="fetch the MUD URL and report metadata")
    args = ap.parse_args(argv)

    asa = start(args, "Mudlark")
    obj = objective(OBJ_MUD_URL, neg=True, discoverable=True)
    err = cg.register_obj(asa, obj, discoverable=True)
    if err:
        print(f"[Mudlark] register_obj failed: {err_text(err)}", flush=True)
        return 2
    stopping = [False]
    install_stop_handlers(stopping, "Mudlark")

    def serve():
        while not stopping[0]:
            err, shandle, request = cg.listen_negotiate(asa, obj)
            if err:
                print(f"[Mudlark] listen_negotiate: {err_text(err)}", flush=True)
                continue
            url = str(getattr(request, "value", ""))
            print(f"[Mudlark] received MUD URL {url!r}", flush=True)
            status = {"status": "accepted", "url": url}
            if args.fetch and url.startswith(("http://", "https://")):
                status["fetch"] = fetch_mud(url)
                print(f"[Mudlark] fetch: {status['fetch']}", flush=True)
            request.value = status
            step_err, shandle2, _reply = cg.negotiate_step(asa, shandle, request, 5000)
            if step_err:
                print(f"[Mudlark] negotiate_step: {err_text(step_err)}", flush=True)
            elif shandle2 is not None:
                cg.end_negotiate(asa, shandle2, True)

    threading.Thread(target=serve, name="Mudlark-listener", daemon=True).start()
    time.sleep(0.5)
    print(f"[Mudlark] ready on coap://[{args.bind}]:{args.coap_port}/{args.path.strip('/')}",
          flush=True)

    while not stopping[0]:
        time.sleep(0.2)

    try:
        cg.deregister_asa(asa, "Mudlark")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
