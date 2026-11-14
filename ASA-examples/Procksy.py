#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Procksy: a demonstration BRSKI join proxy over cGRASP/CoAP.

Ported from graspy's ``ASA-examples/Procksy.py``.  It watches for a flooded
``AN_join_registrar`` objective (41120), chooses a registrar, and floods an
``AN_proxy`` objective (41121) advertising its own locator.  Actual BRSKI
transactions are out of scope.

Run on a link-local IPv6 network:

    python ASA-examples/Procksy.py --bind :: --coap-port 5683 \
        --advertise coap://[fe80::2]:5683
"""

from __future__ import annotations

import argparse
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
from _common import (  # noqa: E402
    OBJ_BRSKI_PROXY,
    OBJ_BRSKI_REGISTRAR,
    add_common_args,
    advertise_locator,
    err_text,
    install_stop_handlers,
    objective,
    start,
    uri_locator,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Procksy: BRSKI join proxy over cGRASP/CoAP")
    add_common_args(ap, default_port=5683)
    ap.add_argument("--advertise", default="",
                    help="proxy locator to advertise (default coap://[::1]:<port>)")
    ap.add_argument("--interval", type=float, default=30.0,
                    help="seconds between polls/floods")
    ap.add_argument("--ttl-ms", type=int, default=120000)
    args = ap.parse_args(argv)

    asa = start(args, "Procksy", be_dull=False)
    registrar_obj = objective(OBJ_BRSKI_REGISTRAR, synch=True)
    proxy_obj = objective(OBJ_BRSKI_PROXY, synch=True, value="AN_Proxy")
    for obj in (registrar_obj, proxy_obj):
        err = cg.register_obj(asa, obj, discoverable=False)
        if err:
            print(f"[Procksy] register_obj failed: {err_text(err)}", flush=True)
            return 2

    proxy_locator = uri_locator(args.advertise) if args.advertise else advertise_locator("::1", args.coap_port)
    print(f"[Procksy] proxy locator={proxy_locator.locator}; waiting for registrar floods", flush=True)

    stopping = [False]
    install_stop_handlers(stopping, "Procksy")
    selected = None

    while not stopping[0]:
        err, floods = cg.get_flood(asa, registrar_obj)
        if err:
            print(f"[Procksy] get_flood failed: {err_text(err)}", flush=True)
        elif floods:
            chosen = floods[0]
            selected = getattr(chosen, "source", None)
            if selected is not None:
                print(f"[Procksy] registrar={selected.locator} value={getattr(chosen.objective, 'value', None)}",
                      flush=True)
        if selected is not None:
            err = cg.flood(asa, args.ttl_ms, cg.tagged_objective(proxy_obj, proxy_locator))
            if err:
                print(f"[Procksy] proxy flood failed: {err_text(err)}", flush=True)
            else:
                print(f"[Procksy] flooded proxy {proxy_locator.locator}", flush=True)
        for _ in range(max(1, int(args.interval * 10))):
            if stopping[0]:
                break
            time.sleep(0.1)

    try:
        cg.deregister_asa(asa, "Procksy")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
