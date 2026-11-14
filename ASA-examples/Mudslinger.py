#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Mudslinger: send a MUD URL to a MUD manager over cGRASP/CoAP.

Ported from graspy's ``ASA-examples/Mudslinger.py``.  It negotiates the
demonstration objective 41110 (``MUDURL``) with a Mudlark manager and prints
the manager's response.

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
    objective,
    peer_locator,
    start,
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Mudslinger: send a MUD URL over cGRASP/CoAP")
    add_common_args(ap, default_port=15683)
    ap.add_argument("--peer", default="",
                    help="direct peer base URI, e.g. coap://[::1]:5683")
    ap.add_argument("--same-host", action="store_true",
                    help="use coap://[::1]:--peer-port as the peer")
    ap.add_argument("--peer-port", type=int, default=5683)
    ap.add_argument("--url", default="https://example.org/mud.json",
                    help="MUD file URL to send")
    ap.add_argument("--timeout-ms", type=int, default=5000)
    args = ap.parse_args(argv)

    asa = start(args, "Mudslinger")
    obj = objective(OBJ_MUD_URL, neg=True, discoverable=False, value=args.url)
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        print(f"[Mudslinger] register_obj failed: {err_text(err)}", flush=True)
        return 2

    peer = peer_locator(args, asa, obj, args.timeout_ms)
    if peer is None:
        print("[Mudslinger] no MUD manager discovered", flush=True)
        return 1

    print(f"[Mudslinger] sending MUD URL {args.url} to {peer.locator}", flush=True)
    err, shandle, answer = cg.req_negotiate(asa, obj, peer, args.timeout_ms)
    if err:
        print(f"[Mudslinger] req_negotiate failed: {err_text(err)}", flush=True)
        return 1
    value = getattr(answer, "value", None)
    if shandle is not None:
        cg.end_negotiate(asa, shandle, True)
    print(f"[Mudslinger] manager response: {json.dumps(value, ensure_ascii=False)}",
          flush=True)

    try:
        cg.deregister_asa(asa, "Mudslinger")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
