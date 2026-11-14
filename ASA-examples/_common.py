#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Shared helpers for the cGRASP ASA examples.

These helpers keep the examples short and consistent.  They are demonstration
code, not part of the cGRASP package.
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cgrasp import cgrasp as cg  # noqa: E402

DEFAULT_PATH = ".well-known/grasp-coap"

# Private/demonstration objective numbers.  The drafts assign names such as
# "AN_join_registrar"; cGRASP encodes numeric objective identifiers, so these
# examples use private numbers in the 41100-41199 range.
OBJ_DNS_SD = 41101
OBJ_DNS_SD_SRV = 41102
OBJ_MUD_URL = 41110
OBJ_BRSKI_REGISTRAR = 41120
OBJ_BRSKI_PROXY = 41121


def add_common_args(parser: argparse.ArgumentParser, *, default_port: int = 5683) -> None:
    parser.add_argument("--bind", default="::1",
                        help="local IPv6 address (default ::1; use :: for multicast)")
    parser.add_argument("--coap-port", type=int, default=default_port,
                        help="local CoAP/UDP port")
    parser.add_argument("--path", default=DEFAULT_PATH,
                        help="CoAP resource path")
    parser.add_argument("--listen-self", action="store_true",
                        help="accept local/self traffic for single-host demos")
    parser.add_argument("--test-mode", action="store_true",
                        help="enable cGRASP test-mode diagnostics")
    parser.add_argument("--diagnose", action="store_true",
                        help="enable extra cGRASP diagnostics")


def start(args: argparse.Namespace, asa_name: str, *, be_dull: bool = True):
    """Initialise cGRASP over CoAP and register an ASA."""
    cg.skip_dialogue(
        testing=bool(args.test_mode),
        selfing=bool(args.listen_self),
        diagnosing=bool(args.diagnose),
        be_dull=bool(be_dull),
    )
    cg.enable_coap_transport(
        True,
        bind=str(args.bind),
        port=int(args.coap_port),
        path=str(args.path),
        mc_uri_path=(".well-known", "grasp-coap"),
        autostart=True,
        strict_coap=True,
        allow_tcp_fallback=False,
        allow_legacy_multicast=False,
        standard_multicast=True,
    )
    err, asa = cg.register_asa(str(asa_name))
    if err:
        raise SystemExit(f"register_asa failed: {err_text(err)}")
    return asa


def objective(num: int, *, neg: bool = False, synch: bool = False,
              value=None, discoverable: bool = True, loop_count: int = 4):
    obj = cg.cobjective(int(num))
    obj.neg = bool(neg)
    obj.synch = bool(synch)
    obj.discoverable = bool(discoverable)
    obj.loop_count = int(loop_count)
    obj.value = value
    return obj


def uri_locator(uri: str):
    loc = cg.asa_locator(str(uri).rstrip("/"), 0, False)
    loc.is_uri = True
    loc.is_ipaddress = False
    loc.is_fqdn = False
    return loc


def advertise_locator(host: str, port: int):
    return uri_locator(f"coap://[{host}]:{int(port)}")


def peer_locator(args: argparse.Namespace, asa, obj, timeout_ms: int = 3000):
    """Return an explicit peer or discover the objective."""
    peer = str(getattr(args, "peer", "") or "").strip()
    if peer:
        return uri_locator(peer)
    if bool(getattr(args, "same_host", False)):
        return uri_locator(f"coap://[::1]:{int(getattr(args, 'peer_port', 5683))}")
    err, locators = cg.discover(asa, obj, timeout_ms, flush=True)
    if err or not locators:
        return None
    return locators[0]


def err_text(err: int) -> str:
    try:
        return cg.etext[int(err)]
    except Exception:
        return str(err)


def install_stop_handlers(stopping: list[bool], name: str, handle=None) -> None:
    state = {"count": 0}

    def stop(_signum, _frame):
        state["count"] += 1
        if state["count"] >= 2:
            raise SystemExit(130)
        stopping[0] = True
        print(f"\n[{name}] stopping... press Ctrl+C again to force", flush=True)
        try:
            if handle is not None:
                handle.stop()
        except Exception:
            pass

    signal.signal(signal.SIGINT, stop)
    try:
        signal.signal(signal.SIGTERM, stop)
    except Exception:
        pass
