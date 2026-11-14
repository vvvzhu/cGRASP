# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

from __future__ import annotations

import inspect
import threading
from types import SimpleNamespace

import pytest

from cgrasp import cgrasp as cgrasp2
def test_error_text_table_matches_codes():
    assert len(cgrasp2.etext) == cgrasp2.errors.sockErr + 1
    assert cgrasp2.etext[cgrasp2.errors.invalidLoc] == "Invalid locator"
    assert cgrasp2.etext[cgrasp2.errors.sockErr] == "Socket error sending gmessage"


def test_new_session_releases_lock_on_exhaustion(monkeypatch):
    monkeypatch.setattr(cgrasp2, "_sess_lock", threading.Lock())
    monkeypatch.setattr(
        cgrasp2, "_session_id_cache", [cgrasp2._session_instance(7, True, None)])
    monkeypatch.setattr(cgrasp2, "_prng", SimpleNamespace(randint=lambda _a, _b: 7))

    with pytest.raises(RuntimeError):
        cgrasp2._new_session(None)

    # The lock must be free after the exception; otherwise every later
    # session-creating call would deadlock.
    assert cgrasp2._sess_lock.acquire(blocking=False)
    cgrasp2._sess_lock.release()


def test_objective_supports_rejects_missing_capability():
    registered = SimpleNamespace(neg=True, dry=False, synch=False)

    assert cgrasp2._objective_supports(
        registered, SimpleNamespace(neg=True, dry=False, synch=False))
    assert not cgrasp2._objective_supports(
        registered, SimpleNamespace(neg=False, dry=False, synch=True))
    assert not cgrasp2._objective_supports(
        registered, SimpleNamespace(neg=True, dry=True, synch=False))


def test_register_obj_locators_default_is_none():
    signature = inspect.signature(cgrasp2.register_obj)
    assert signature.parameters["locators"].default is None


def test_parse_opt_rejects_deep_divert_nesting():
    option = [cgrasp2.O_DIVERT, [cgrasp2.O_IPv6_LOCATOR, b"x", 17, 1]]
    for _ in range(20):
        option = [cgrasp2.O_DIVERT, option]

    assert cgrasp2._parse_opt(option) is None


def test_all_exports_exist():
    missing = [name for name in cgrasp2.__all__ if not hasattr(cgrasp2, name)]
    assert missing == []


def test_tprint_uses_logging_not_stdout(capsys, caplog):
    import logging

    with caplog.at_level(logging.INFO, logger="cgrasp"):
        cgrasp2.tprint("hello")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hello" in caplog.text


def test_session_key_includes_peer_port():
    from ipaddress import IPv6Address

    from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge

    peer = IPv6Address("::1")
    assert (CgraspCoapApiBridge._session_key(1, peer, 5683) !=
            CgraspCoapApiBridge._session_key(1, peer, 5684))


def test_parse_aiocoap_remote_port():
    from cgrasp.cgrasp_coap_transport import _parse_aiocoap_remote_port

    def request(hostinfo):
        return SimpleNamespace(remote=SimpleNamespace(hostinfo=hostinfo))

    assert _parse_aiocoap_remote_port(request("[::1]:5683")) == 5683
    assert _parse_aiocoap_remote_port(request("[fe80::1%eth0]:61616")) == 61616
    assert _parse_aiocoap_remote_port(request("::1")) == 0
    assert _parse_aiocoap_remote_port(request("192.0.2.1:1234")) == 1234


def test_post_grasp_rejects_non_coap_scheme():
    import asyncio

    from cgrasp.cgrasp_coap_transport import CgraspCoapTransport

    transport = CgraspCoapTransport(bind=("::1", 0))
    with pytest.raises(ValueError):
        asyncio.run(transport.post_grasp("file:///etc/passwd", b"x"))


def test_validate_peer_uri_rejects_multicast_and_unspecified():
    from cgrasp.cgrasp_coap_transport import _validate_peer_uri

    for uri in ("coap://[ff02::1]/x", "coap://[::]/x"):
        with pytest.raises(ValueError):
            _validate_peer_uri(uri)
    _validate_peer_uri("coap://[::1]/x")
    _validate_peer_uri("coap://[2001:db8::1]/x")


def test_validate_peer_uri_allowlist(monkeypatch):
    from cgrasp.cgrasp_coap_transport import _validate_peer_uri

    monkeypatch.setenv("CGRASP_PEER_ALLOWLIST", "2001:db8::/32")
    _validate_peer_uri("coap://[2001:db8::1]/x")
    with pytest.raises(ValueError):
        _validate_peer_uri("coap://[2001:db9::1]/x")


def test_responder_leisure_uses_relay_config(monkeypatch):
    class Config:
        responder_leisure_min_ms = 10
        responder_leisure_max_ms = 10

    class State:
        config = Config()

    monkeypatch.setattr(cgrasp2, "_coap_relay_state", State())
    assert cgrasp2._responder_leisure_seconds() == pytest.approx(0.01)


def test_responder_leisure_default_range(monkeypatch):
    monkeypatch.setattr(cgrasp2, "_coap_relay_state", None)
    values = [cgrasp2._responder_leisure_seconds() for _ in range(50)]
    assert all(0.05 <= value <= 0.25 for value in values)


def test_relay_config_from_args_reads_leisure():
    from cgrasp.cgrasp_multicast import relay_config_from_args

    args = SimpleNamespace(
        relay_interfaces=["a", "b"],
        relay_config=None,
        relay_hard_timeout_ms=None,
        relay_quiet_timeout_ms=None,
        relay_rate=None,
        relay_burst=None,
        relay_leisure_min_ms=5,
        relay_leisure_max_ms=7,
    )
    config = relay_config_from_args(args)
    assert config.responder_leisure_min_ms == 5
    assert config.responder_leisure_max_ms == 7


def test_engine_owns_independent_relay_state_and_leisure():
    from cgrasp.cgrasp_engine import CgraspEngine
    from cgrasp.cgrasp_multicast import RelayConfig

    engine_a = CgraspEngine(RelayConfig(
        ("a", "b"), responder_leisure_min_ms=10, responder_leisure_max_ms=10))
    engine_b = CgraspEngine(RelayConfig(
        ("a", "b"), responder_leisure_min_ms=20, responder_leisure_max_ms=20))

    assert engine_a.responder_leisure_seconds() == pytest.approx(0.01)
    assert engine_b.responder_leisure_seconds() == pytest.approx(0.02)
    assert engine_a.relay_state is not engine_b.relay_state
    assert engine_a.snapshot()["relay_state"]["active_discovery_transactions"] == 0


def test_engine_install_bridges_relay_state(monkeypatch):
    from cgrasp.cgrasp_engine import CgraspEngine
    from cgrasp.cgrasp_multicast import RelayConfig

    engine = CgraspEngine(RelayConfig(("a", "b")))
    monkeypatch.setattr(cgrasp2, "_coap_relay_state", None)
    engine.install()
    assert cgrasp2._coap_relay_state is engine.relay_state


def test_engine_owns_independent_registries():
    from cgrasp.cgrasp_engine import CgraspEngine

    engine_a = CgraspEngine()
    engine_b = CgraspEngine()
    assert engine_a.asa_registry is not engine_b.asa_registry
    assert engine_a.obj_registry is not engine_b.obj_registry
    assert engine_a.asa_lock is not engine_b.asa_lock

    engine_a.asa_registry.append("asa")
    assert engine_b.asa_registry == []


def test_engine_attach_binds_module_globals(monkeypatch):
    from cgrasp.cgrasp_engine import CgraspEngine

    engine = CgraspEngine()
    for name in ("_asa_registry", "_obj_registry", "_session_id_cache",
                 "_flood_cache", "_asa_lock", "_sess_lock"):
        monkeypatch.setattr(cgrasp2, name, None)

    engine.attach()

    assert cgrasp2._asa_registry is engine.asa_registry
    assert cgrasp2._obj_registry is engine.obj_registry
    assert cgrasp2._sess_lock is engine.sess_lock
    assert cgrasp2._flood_cache is engine.flood_cache


def test_duplicate_coap_request_returns_cached_response():
    import asyncio

    from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge

    bridge = CgraspCoapApiBridge()
    calls = []

    async def fake(payload, request):
        calls.append(payload)
        return b"cached-reply"

    bridge._handle_post_uncached = fake
    request = SimpleNamespace(token=b"tok", remote=SimpleNamespace(hostinfo="[::1]:5683"))

    first = asyncio.run(bridge.handle_post(b"payload", request))
    second = asyncio.run(bridge.handle_post(b"payload", request))
    assert first == second == b"cached-reply"
    assert calls == [b"payload"]
    assert bridge._counters.get("duplicate_request_cache_hit") == 1

    other_token = SimpleNamespace(token=b"tok2", remote=SimpleNamespace(hostinfo="[::1]:5683"))
    assert asyncio.run(bridge.handle_post(b"payload", other_token)) == b"cached-reply"
    assert calls == [b"payload", b"payload"]


def test_exchange_pop_response_async():
    import asyncio
    from ipaddress import IPv6Address

    from cgrasp.cgrasp_coap_transport import CoapServerExchange

    async def scenario():
        exchange = CoapServerExchange(
            sid=1, peer_addr=IPv6Address("::1"), token=b"tok",
            direction="inbound", on_close=lambda _exchange: None)
        waiter = asyncio.create_task(exchange.pop_response_async(timeout_s=1.0))
        await asyncio.sleep(0.01)
        assert exchange.route_response(b"reply")
        return await waiter

    assert asyncio.run(scenario()) == b"reply"


def test_exchange_pop_response_async_timeout():
    import asyncio
    from ipaddress import IPv6Address

    from cgrasp.cgrasp_coap_transport import CoapServerExchange

    async def scenario():
        exchange = CoapServerExchange(
            sid=1, peer_addr=IPv6Address("::1"), token=b"tok",
            direction="inbound", on_close=lambda _exchange: None)
        return await exchange.pop_response_async(timeout_s=0.05)

    assert asyncio.run(scenario()) is None
