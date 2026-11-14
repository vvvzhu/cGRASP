#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Reggie: a demonstration BRSKI registrar contact advertiser.

Ported from graspy's ``ASA-examples/Reggie.py``.  The registrar periodically
floods the demonstration objective 41120 (``AN_join_registrar``) with the
methods it supports (for example ``EST-TLS``) and its locator.  Actual BRSKI
transactions are out of scope.

The flood is sent over the IPv6 link-local multicast interface selected by
cGRASP; use a real interface, not only loopback.

Example:

    python ASA-examples/Reggie.py --bind :: --coap-port 5683 \
        --advertise coap://[fe80::1]:5683 --interval 60

Use ``GetDNSSD``/``Mudlark`` style unicast examples if you only have loopback.
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
    ap = argparse.ArgumentParser(description="Reggie: BRSKI registrar flood source over cGRASP/CoAP")
    add_common_args(ap, default_port=5683)
    ap.add_argument("--value", default="EST-TLS",
                    help="registrar methods advertised in the flooded objective")
    ap.add_argument("--advertise", default="",
                    help="locator to advertise (default coap://[::1]:<port>)")
    ap.add_argument("--interval", type=float, default=60.0,
                    help="seconds between floods")
    ap.add_argument("--ttl-ms", type=int, default=120000,
                    help="flood TTL in milliseconds")
    args = ap.parse_args(argv)

    asa = start(args, "Reggie", be_dull=False)
    obj = objective(OBJ_BRSKI_REGISTRAR, synch=True, value=args.value)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        print(f"[Reggie] register_obj failed: {err_text(err)}", flush=True)
        return 2

    locator = uri_locator(args.advertise) if args.advertise else advertise_locator("::1", args.coap_port)
    print(f"[Reggie] registrar={args.value} locator={locator.locator} ttl={args.ttl_ms}ms",
          flush=True)

    stopping = [False]
    install_stop_handlers(stopping, "Reggie")

    while not stopping[0]:
        err = cg.flood(asa, args.ttl_ms, cg.tagged_objective(obj, locator))
        if err:
            print(f"[Reggie] flood failed: {err_text(err)}", flush=True)
        else:
            print(f"[Reggie] flooded {args.value} ({locator.locator})", flush=True)
        for _ in range(max(1, int(args.interval * 10))):
            if stopping[0]:
                break
            time.sleep(0.1)

    try:
        cg.deregister_asa(asa, "Reggie")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
