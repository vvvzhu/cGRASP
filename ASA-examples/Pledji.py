#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Pledji: a demonstration BRSKI pledge over cGRASP/CoAP.

Ported from graspy's ``ASA-examples/Pledji.py``.  It listens for flooded
``AN_proxy`` objectives (41121) and prints the join proxies it can see.
Actual BRSKI enrollment is out of scope.

Run on a link-local IPv6 network:

    python ASA-examples/Pledji.py --bind :: --coap-port 5683
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
    add_common_args,
    err_text,
    install_stop_handlers,
    objective,
    start,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Pledji: BRSKI pledge over cGRASP/CoAP")
    add_common_args(ap, default_port=5683)
    ap.add_argument("--interval", type=float, default=5.0,
                    help="seconds between flood-cache polls")
    args = ap.parse_args(argv)

    asa = start(args, "Pledji", be_dull=False)
    proxy_obj = objective(OBJ_BRSKI_PROXY, synch=True)
    err = cg.register_obj(asa, proxy_obj, discoverable=False)
    if err:
        print(f"[Pledji] register_obj failed: {err_text(err)}", flush=True)
        return 2
    print("[Pledji] waiting for AN_proxy floods", flush=True)

    stopping = [False]
    install_stop_handlers(stopping, "Pledji")
    seen = set()

    while not stopping[0]:
        err, floods = cg.get_flood(asa, proxy_obj)
        if err:
            print(f"[Pledji] get_flood failed: {err_text(err)}", flush=True)
        else:
            for item in floods or []:
                source = getattr(item, "source", None)
                locator = getattr(source, "locator", None)
                if locator and locator not in seen:
                    seen.add(locator)
                    print(f"[Pledji] discovered join proxy {locator} "
                          f"value={getattr(item.objective, 'value', None)}",
                          flush=True)
        for _ in range(max(1, int(args.interval * 10))):
            if stopping[0]:
                break
            time.sleep(0.1)

    try:
        cg.deregister_asa(asa, "Pledji")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
