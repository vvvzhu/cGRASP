#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Verify CoAP-based (CoAP-wrapped) cGRASP discovery.

This script is intentionally simple and operational:
- Run one instance as a *responder* (registers a discoverable objective).
- Run another instance as a *requester* (calls cgrasp.discover()).

When `cgrasp.set_multicast_coap(True)` is enabled, link-local multicast
Discovery/Flood payloads are wrapped in a minimal CoAP message (still over UDP).

Usage (two terminals, same L2):
  Terminal A (responder):
    python3 verify_coap_discovery.py responder --obj 42999

  Terminal B (requester):
    python3 verify_coap_discovery.py requester --obj 42999 --timeout-ms 3000

Notes:
- For test environments without ACP/QUADS, we set DULL mode via skip_dialogue(..., be_dull=True)
  to bypass security checks.
- This script prints an internal sanity check that the wrapped bytes parse as CoAP.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional


def _ensure_local_imports() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (here, os.path.join(here, "src")):
        if path not in sys.path:
            sys.path.insert(0, path)


def _import_cgrasp():
    try:
        from cgrasp import cgrasp as cg  # type: ignore
    except Exception as e:
        raise SystemExit(
            "Failed to import cgrasp.cgrasp. Run from the repository root or fix PYTHONPATH. "
            f"Original error: {e}"
        )
    return cg


def _print_coap_wrap_sanity(cg, objnum: int) -> None:
    """Build one discovery message and show that wrapping parses as CoAP."""
    try:
        # Ensure core globals (like _session_locator) exist.
        # register_asa() triggers _initialise_grasp() if needed.
        pass
    except Exception:
        pass

    try:
        # Build a real discovery message (same helper cgrasp uses).
        fake_sid = 12345
        obj = cg.cobjective(int(objnum))
        msg = cg._ass_message(cg.M_DISCOVERY, fake_sid, getattr(cg, "_session_locator", None), obj)  # type: ignore[attr-defined]
        wrapped = cg._coap_wrap_mc_request(msg)  # type: ignore[attr-defined]
        code, mid, token, payload = cg._coap_parse(wrapped)  # type: ignore[attr-defined]
        print(
            f"[sanity] CoAP-wrapped discovery parses OK: code={code} mid={mid} token_len={len(token)} payload_len={len(payload)}"
        )
    except Exception as e:
        # Not fatal; discovery can still work. But print for visibility.
        print(f"[sanity] CoAP wrap/parse sanity check skipped/failed: {e}")


def run_responder(*, objnum: int, asa_name: str) -> int:
    cg = _import_cgrasp()

    # Bypass security for experiments unless ACP/QUADS is set up.
    cg.skip_dialogue(testing=True, selfing=False, diagnosing=False, be_dull=True)

    # Enable CoAP-wrapped multicast discovery.
    cg.set_multicast_coap(True)

    err, asa = cg.register_asa(asa_name)
    if err:
        print(f"register_asa failed: err={err}")
        return 2

    obj = cg.cobjective(int(objnum))
    obj.neg = False
    obj.synch = False

    # Make objective immediately discoverable (even if not listening).
    err = cg.register_obj(asa, obj, discoverable=True)
    if err:
        print(f"register_obj failed: err={err}")
        return 2

    print(f"[responder] ready: asa={asa_name} obj={objnum} (discoverable=True, multicast=CoAP-wrapped)")
    _print_coap_wrap_sanity(cg, objnum)

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("[responder] exiting")
        return 0


def run_requester(*, objnum: int, asa_name: str, timeout_ms: int) -> int:
    cg = _import_cgrasp()

    cg.skip_dialogue(testing=True, selfing=False, diagnosing=False, be_dull=True)
    cg.set_multicast_coap(True)

    err, asa = cg.register_asa(asa_name)
    if err:
        print(f"register_asa failed: err={err}")
        return 2

    # discover() requires the objective to be registered for this ASA.
    obj = cg.cobjective(int(objnum))
    obj.neg = False
    obj.synch = False
    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        print(f"register_obj failed: err={err}")
        return 2

    _print_coap_wrap_sanity(cg, objnum)

    err, locs = cg.discover(asa, obj, int(timeout_ms))
    if err:
        print(f"discover failed: err={err} locs=[]")
        return 3

    if not locs:
        print("discover ok but no peers found (empty list)")
        return 4

    print(f"discover ok: {len(locs)} locator(s)")
    for i, loc in enumerate(locs, 1):
        # loc is cgrasp.asa_locator
        try:
            kind = "uri" if getattr(loc, "is_uri", False) else ("ip" if getattr(loc, "is_ipaddress", False) else "other")
            print(
                f"  {i}. kind={kind} locator={getattr(loc, 'locator', None)} "
                f"port={getattr(loc, 'port', None)} proto={getattr(loc, 'protocol', None)} ifi={getattr(loc, 'ifi', None)}"
            )
        except Exception:
            print(f"  {i}. {loc}")

    print("PASS: discovery returned at least one locator")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    _ensure_local_imports()

    p = argparse.ArgumentParser(description="Verify CoAP-wrapped cGRASP discovery")
    sub = p.add_subparsers(dest="mode", required=True)

    p_r = sub.add_parser("responder", help="register a discoverable objective and respond to discovery")
    p_r.add_argument("--obj", type=int, required=True, help="objective number")
    p_r.add_argument("--asa", type=str, default="verify-discovery-responder", help="ASA name")

    p_q = sub.add_parser("requester", help="send discover() and print results")
    p_q.add_argument("--obj", type=int, required=True, help="objective number")
    p_q.add_argument("--timeout-ms", type=int, default=3000, help="discover timeout in milliseconds")
    p_q.add_argument("--asa", type=str, default="verify-discovery-requester", help="ASA name")

    args = p.parse_args(argv)

    if args.mode == "responder":
        return run_responder(objnum=args.obj, asa_name=args.asa)
    return run_requester(objnum=args.obj, asa_name=args.asa, timeout_ms=args.timeout_ms)


if __name__ == "__main__":
    raise SystemExit(main())
