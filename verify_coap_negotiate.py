#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Verify CoAP-based cGRASP negotiation (unicast over CoAP).

This script validates the end-to-end path:
- client uses cgrasp.req_negotiate() and friends, but with the unicast socket
  replaced by a CoAP transport shim (set_unicast_socket_factory hook).
- server runs an aiocoap endpoint (default /.well-known/grasp-coap) and bridges inbound
  CoAP POST payloads into cgrasp.listen_negotiate() using public APIs.

Design goals:
- Do NOT reimplement the negotiation state machine.
- Keep cgrasp's on-wire bytes intact (CBOR, optionally QUADS).

Usage (two terminals on same host is OK):
  Terminal A (server):
    python3 verify_coap_negotiate.py server --bind :: --port 5683 --obj 43000

  Terminal B (client):
    python3 verify_coap_negotiate.py client --peer ::1 --port 5683 --obj 43000

Expected:
- client prints PASS after receiving an accepted END.
- server prints the requested objective value and that it accepted.

If you don't have ACP/QUADS configured, this script enables DULL mode via
skip_dialogue(..., be_dull=True) to bypass security checks.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
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


def _import_bridge():
    try:
        from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge, install_cgrasp_unicast_over_coap  # type: ignore
        from cgrasp.coap_server import make_default_cgrasp_server  # type: ignore
    except Exception as e:
        raise SystemExit(
            "Failed to import CoAP bridge modules (aiocoap/cbor2 missing?). "
            "Try: pip3 install aiocoap cbor2\n"
            f"Original error: {e}"
        )
    return CgraspCoapApiBridge, install_cgrasp_unicast_over_coap, make_default_cgrasp_server


def _make_uri_locator(cg, *, uri: str):
    loc = cg.asa_locator(uri, 0, False)
    loc.is_uri = True
    loc.is_ipaddress = False
    loc.is_fqdn = False
    return loc


def _server_listen_once_and_accept(cg, *, asa_handle, objnum: int) -> None:
    obj_t = cg.cobjective(int(objnum))
    obj_t.neg = True
    obj_t.discoverable = True

    err, sh, req_obj = cg.listen_negotiate(asa_handle, obj_t)
    if err:
        print(f"[server] listen_negotiate failed: err={err}")
        return

    try:
        print(f"[server] got request: obj={getattr(req_obj, 'num', None)} value={getattr(req_obj, 'value', None)}")
    except Exception:
        print("[server] got request (could not print request details)")

    err2 = cg.end_negotiate(asa_handle, sh, True)
    if err2:
        print(f"[server] end_negotiate failed: err={err2}")
    else:
        print("[server] accepted (sent END/ACCEPT)")


async def run_server(*, bind: str, port: int, objnum: int, asa_name: str, path: str) -> int:
    cg = _import_cgrasp()
    CgraspCoapApiBridge, _install_unicast_over_coap, make_default_cgrasp_server = _import_bridge()

    cg.skip_dialogue(testing=True, selfing=False, diagnosing=False, be_dull=True)

    err, asa = cg.register_asa(asa_name)
    if err:
        print(f"[server] register_asa failed: err={err}")
        return 2

    obj = cg.cobjective(int(objnum))
    obj.neg = True
    obj.discoverable = True

    err = cg.register_obj(asa, obj, discoverable=True)
    if err:
        print(f"[server] register_obj failed: err={err}")
        return 2

    bridge = CgraspCoapApiBridge(wait_ttl_ms=200)
    srv = make_default_cgrasp_server(bridge.handle_post, bind=(bind, int(port)), base_path=path)

    await srv.start()
    print(f"[server] CoAP endpoint: coap://[{bind}]:{port}/{path.strip('/')}")
    print(f"[server] waiting for one negotiation request for obj={objnum} ...")

    try:
        await asyncio.to_thread(_server_listen_once_and_accept, cg, asa_handle=asa, objnum=int(objnum))
    finally:
        await srv.stop()

    print("[server] done")
    return 0


def run_client(*, peer: str, port: int, objnum: int, asa_name: str, path: str, timeout_ms: int, value: str) -> int:
    cg = _import_cgrasp()
    _CgraspCoapApiBridge, install_cgrasp_unicast_over_coap, _make_default_cgrasp_server = _import_bridge()

    cg.skip_dialogue(testing=True, selfing=False, diagnosing=False, be_dull=True)

    err, asa = cg.register_asa(asa_name)
    if err:
        print(f"[client] register_asa failed: err={err}")
        return 2

    obj = cg.cobjective(int(objnum))
    obj.neg = True
    obj.value = value

    err = cg.register_obj(asa, obj, discoverable=False)
    if err:
        print(f"[client] register_obj failed: err={err}")
        return 2

    # Install unicast-over-CoAP hook so req_negotiate uses CoAP instead of TCP.
    install_cgrasp_unicast_over_coap(path=path, default_port=int(port))

    uri = f"coap://[{peer}]:{port}"
    peer_loc = _make_uri_locator(cg, uri=uri)

    print(f"[client] starting req_negotiate to {uri}/{path.strip('/')} obj={objnum} value={value!r}")

    err, sh, rec = cg.req_negotiate(asa, obj, peer_loc, int(timeout_ms))
    if err:
        print(f"[client] req_negotiate failed: err={err}")
        return 3

    # For the simple accept-fast server, we expect (ok, None, obj)
    if sh is not None:
        print(f"[client] negotiation did not finish immediately: shandle={sh} rec={rec}")
        return 4

    print(f"[client] negotiation accepted. returned={rec}")
    print("PASS: negotiation completed over CoAP")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    _ensure_local_imports()

    p = argparse.ArgumentParser(description="Verify cGRASP negotiation over CoAP (unicast)")
    sub = p.add_subparsers(dest="mode", required=True)

    p_s = sub.add_parser("server")
    p_s.add_argument("--bind", type=str, default="::", help="bind address for CoAP server")
    p_s.add_argument("--port", type=int, default=5683, help="CoAP UDP port")
    p_s.add_argument("--path", type=str, default=".well-known/grasp-coap", help="resource path")
    p_s.add_argument("--obj", type=int, required=True, help="objective number")
    p_s.add_argument("--asa", type=str, default="verify-neg-server", help="ASA name")

    p_c = sub.add_parser("client")
    p_c.add_argument("--peer", type=str, default="::1", help="peer IPv6 address")
    p_c.add_argument("--port", type=int, default=5683, help="CoAP UDP port")
    p_c.add_argument("--path", type=str, default=".well-known/grasp-coap", help="resource path")
    p_c.add_argument("--obj", type=int, required=True, help="objective number")
    p_c.add_argument("--asa", type=str, default="verify-neg-client", help="ASA name")
    p_c.add_argument("--timeout-ms", type=int, default=3000, help="negotiation timeout in ms")
    p_c.add_argument("--value", type=str, default="hello", help="requested value")

    args = p.parse_args(argv)

    if args.mode == "server":
        return asyncio.run(
            run_server(bind=args.bind, port=args.port, objnum=args.obj, asa_name=args.asa, path=args.path)
        )

    return run_client(
        peer=args.peer,
        port=args.port,
        objnum=args.obj,
        asa_name=args.asa,
        path=args.path,
        timeout_ms=args.timeout_ms,
        value=args.value,
    )


if __name__ == "__main__":
    raise SystemExit(main())
