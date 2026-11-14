# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

from __future__ import annotations

import socket

import pytest


def _has_ipv6_loopback() -> bool:
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.bind(("::1", 0))
        finally:
            sock.close()
        return True
    except OSError:
        return False


def pytest_collection_modifyitems(config, items):
    """Apply capability markers and skip tests the host cannot run.

    The project historically had no marker plumbing, so the markers declared
    in ``pyproject.toml`` never selected anything.  This hook derives the
    markers from the test module names and skips end-to-end network tests when
    the host has no usable IPv6 loopback.
    """

    has_ipv6 = _has_ipv6_loopback()

    for item in items:
        nodeid = item.nodeid
        if "test_coap_integration" in nodeid:
            item.add_marker(pytest.mark.network)
            if not has_ipv6:
                item.add_marker(pytest.mark.skip(reason="IPv6 loopback unavailable"))
        elif "test_multicast_core" in nodeid:
            item.add_marker(pytest.mark.multicast)
        elif "test_relay_e2e_real" in nodeid:
            item.add_marker(pytest.mark.relay)
