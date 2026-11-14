# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Unit tests for cgrasp_coap_transport private parsing helpers."""

from __future__ import annotations

import ipaddress
from types import SimpleNamespace

from cgrasp.cgrasp_coap_transport import (
    _parse_aiocoap_remote_ipv6,
    _parse_aiocoap_remote_port,
    _parse_aiocoap_remote_zone,
)


def _request(hostinfo):
    return SimpleNamespace(remote=SimpleNamespace(hostinfo=hostinfo))


def test_parse_remote_ipv6_and_zone():
    request = _request("[fe80::1%eth0]:5683")
    assert _parse_aiocoap_remote_ipv6(request) == ipaddress.IPv6Address("fe80::1")
    assert _parse_aiocoap_remote_zone(request) == "eth0"


def test_parse_remote_ipv6_without_zone():
    request = _request("[2001:db8::1]:5683")
    assert _parse_aiocoap_remote_ipv6(request) == ipaddress.IPv6Address("2001:db8::1")
    assert _parse_aiocoap_remote_zone(request) is None


def test_parse_remote_port_variants():
    assert _parse_aiocoap_remote_port(_request("[::1]:5683")) == 5683
    assert _parse_aiocoap_remote_port(_request("192.0.2.1:1234")) == 1234
    assert _parse_aiocoap_remote_port(_request("::1")) == 0
