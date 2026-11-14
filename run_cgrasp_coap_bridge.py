# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Run a CoAP endpoint that carries cGRASP messages in CoAP payloads.

This is a thin wrapper around:
- cgrasp.cgrasp_coap_transport.CgraspCoapApiBridge (CoAP -> cgrasp.cgrasp API queueing)
- cgrasp.coap_server.make_default_cgrasp_server (aiocoap server)

Usage:
  python3 run_cgrasp_coap_bridge.py --bind :: --port 5683 --path .well-known/grasp-coap

Notes:
- This only provides the transport endpoint. Your ASA must still run and
  call cgrasp.cgrasp.listen_negotiate()/listen_synchronize() etc.
- To make *outbound* unicast use CoAP too, call:
    from cgrasp.cgrasp_coap_transport import install_cgrasp_unicast_over_coap
    install_cgrasp_unicast_over_coap(path=..., default_port=...)
"""

from __future__ import annotations

import argparse
import asyncio

from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge
from cgrasp.coap_server import make_default_cgrasp_server


async def _amain(bind: str, port: int, path: str) -> None:
    bridge = CgraspCoapApiBridge()
    srv = make_default_cgrasp_server(bridge.handle_post, bind=(bind, int(port)), base_path=path)
    await srv.start()
    print(f"cGRASP-over-CoAP listening: coap://[{bind}]:{port}/{path.strip('/')}")
    await asyncio.get_running_loop().create_future()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="::", help="Bind address (default ::)")
    ap.add_argument("--port", type=int, default=5683, help="UDP port (default 5683)")
    ap.add_argument("--path", default=".well-known/grasp-coap", help="Resource path (default .well-known/grasp-coap)")
    args = ap.parse_args()
    asyncio.run(_amain(args.bind, args.port, args.path))


if __name__ == "__main__":
    main()
