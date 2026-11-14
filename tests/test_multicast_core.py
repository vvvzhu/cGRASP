# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import asyncio
import argparse
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import cbor2

from cgrasp.cgrasp_multicast import (
    add_relay_arguments,
    CodecError, DiscoveryKey, FloodKey, InterfaceInfo, InterfaceManager,
    RelayConfig, RelayState, TokenBucket, decode_message,
    decrement_loop_count, encode_canonical, relay_config_from_args, response_digest,
)
from cgrasp.cgrasp_quiescence import assert_quiescent
from cgrasp.coap_multicast_adapter import (
    PipeHandlerResource, StreamingResponsePayloadTooLarge,
    aiocoap_adapter_version, assert_aiocoap_private_contract,
    assert_supported_aiocoap,
)
from cgrasp.coap_client import CoapClient
from cgrasp.coap_multicast_adapter import MulticastExchange


INITIATOR = bytes.fromhex("fe800000000000000000000000000001")


def discovery(loop=3):
    return [1, 7, INITIATOR, [42, 1, loop, "x"]]


def response(locator=None):
    locator = locator or bytes.fromhex("fe800000000000000000000000000002")
    return [2, 7, INITIATOR, 1000, [103, locator, 17, 5683]]


def flood(loop=3):
    return [9, 7, INITIATOR, 1000, [[42, 4, loop, "x"], []], [[43, 4, loop, "y"], []]]


class CodecTests(unittest.TestCase):
    def test_roundtrips_and_canonical_is_stable(self):
        for message in (discovery(), response(), flood()):
            encoded = encode_canonical(message)
            self.assertEqual(decode_message(encoded), message)
            self.assertEqual(encoded, encode_canonical(decode_message(encoded)))

    def test_decrement_does_not_mutate(self):
        original = flood(2)
        changed = decrement_loop_count(original)
        self.assertEqual(original[4][0][2], 2)
        self.assertEqual(changed[4][0][2], 1)
        self.assertEqual(changed[5][0][2], 1)

    def test_zero_loop_is_not_forwardable(self):
        with self.assertRaises(CodecError):
            decrement_loop_count(discovery(0))

    def test_response_digest_is_semantic(self):
        first = response()
        noncanonical = cbor2.dumps(first, canonical=False)
        self.assertEqual(response_digest(first), response_digest(decode_message(noncanonical)))
        other = response(bytes.fromhex("fe800000000000000000000000000003"))
        self.assertNotEqual(response_digest(first), response_digest(other))

    def test_malformed_messages_rejected(self):
        bad = flood(2)
        bad[5][0][2] = 1
        for payload in (b"", b"not-cbor", cbor2.dumps([1]), cbor2.dumps(bad)):
            with self.assertRaises(CodecError):
                decode_message(payload)


class ConfigAndInterfaceTests(unittest.TestCase):
    def test_config_validation(self):
        RelayConfig(("eth0",))
        with self.assertRaises(ValueError):
            RelayConfig(())
        with self.assertRaises(ValueError):
            RelayConfig(("eth0",), discovery_hard_timeout_ms=0)
        with self.assertRaises(ValueError):
            RelayConfig(("eth0",), max_responders_per_objective_interface=0)
        with self.assertRaises(ValueError):
            RelayConfig(("eth0",), multicast_group="2001:db8::1")

    def test_interface_selection_never_reflects(self):
        inventory = [InterfaceInfo("a", 1, "fe80::1"), InterfaceInfo("b", 2, "fe80::2")]
        manager = InterfaceManager(("a", "b"), inventory=inventory)
        self.assertEqual([x.name for x in manager.eligible_outgoing_interfaces("a")], ["b"])
        self.assertEqual(manager.get_interface_by_index(2).name, "b")


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.state = RelayState(RelayConfig(("a", "b"), discovery_hard_timeout_ms=100,
                                            flood_seen_timeout_ms=100), clock=lambda: self.now)

    def test_duplicate_discovery_preserves_first_upstream(self):
        key = DiscoveryKey(INITIATOR, 7)
        first = self.state.create_discovery(key, incoming_interface="a", upstream_remote="one",
                                            upstream_token=b"one", upstream_request_context=None)
        deadline = first.hard_deadline
        duplicate = self.state.create_discovery(key, incoming_interface="b", upstream_remote="two",
                                                upstream_token=b"two", upstream_request_context=None)
        self.assertIsNone(duplicate)
        self.assertEqual(self.state.discovery[key].upstream_token, b"one")
        self.assertEqual(self.state.discovery[key].hard_deadline, deadline)

    def test_flood_cache_expires(self):
        key = FloodKey(INITIATOR, 7)
        self.assertTrue(self.state.remember_flood(key, "a", ("b",)))
        self.assertFalse(self.state.remember_flood(key, "a", ("b",)))
        self.now += 0.2
        self.assertTrue(self.state.remember_flood(key, "a", ("b",)))

    def test_responder_cache_uses_response_ttl(self):
        self.state.remember_responder(42, ("coap://node",), "b", 100)
        self.assertEqual(len(self.state.get_responders(42)), 1)
        self.now += 0.2
        self.assertEqual(self.state.get_responders(42), [])

    def test_distinct_responders_on_same_interface_are_preserved(self):
        self.state.remember_responder(42, ((103, b"one"),), "b", 1000)
        self.state.remember_responder(42, ((103, b"two"),), "b", 1000)
        entries = self.state.get_responders(42)
        self.assertEqual(len(entries), 2)
        self.assertEqual({entry.locators for entry in entries}, {
            ((103, b"one"),), ((103, b"two"),),
        })

    def test_responder_identity_refreshes_without_overwriting_peer(self):
        shared = ([106, "coap://node", 17, 5683],)
        updated = ([106, "coap://node/new", 17, 5683],)
        self.state.remember_responder(
            42, shared, "b", 1000, responder_identity=("fe80::1", 5683))
        self.state.remember_responder(
            42, shared, "b", 1000, responder_identity=("fe80::2", 5683))
        self.state.remember_responder(
            42, updated, "b", 1000, responder_identity=("fe80::1", 5683))

        entries = self.state.get_responders(42)
        self.assertEqual(len(entries), 2)
        by_identity = {entry.responder_identity: entry for entry in entries}
        self.assertEqual(
            by_identity['endpoint:["fe80::1","5683"]'].locators,
            updated,
        )
        self.assertEqual(
            by_identity['endpoint:["fe80::2","5683"]'].locators,
            shared,
        )
        self.assertEqual(
            self.state.snapshot()["counters"]["responder_cache_refreshed"], 1)

    def test_responder_cache_evicts_oldest_per_objective_interface(self):
        state = RelayState(
            RelayConfig(
                ("a", "b"),
                max_responders_per_objective_interface=2,
            ),
            clock=lambda: self.now,
        )
        for address in ("fe80::1", "fe80::2"):
            state.remember_responder(
                42, ([106, f"coap://[{address}]", 17, 5683],), "b", 1000,
                responder_identity=(address, 5683),
            )
            self.now += 0.01
        # A different interface has its own independent capacity.
        state.remember_responder(
            42, ([106, "coap://[fe80::a]", 17, 5683],), "a", 1000,
            responder_identity=("fe80::a", 5683),
        )
        self.now += 0.01
        state.remember_responder(
            42, ([106, "coap://[fe80::3]", 17, 5683],), "b", 1000,
            responder_identity=("fe80::3", 5683),
        )

        entries = state.get_responders(42)
        identities = {entry.responder_identity for entry in entries}
        self.assertNotIn('endpoint:["fe80::1","5683"]', identities)
        self.assertIn('endpoint:["fe80::2","5683"]', identities)
        self.assertIn('endpoint:["fe80::3","5683"]', identities)
        self.assertIn('endpoint:["fe80::a","5683"]', identities)
        self.assertEqual(
            state.snapshot()["counters"]["responder_cache_evicted"], 1)
        # Configured interface order is the deterministic cache-hit preference.
        self.assertEqual([entry.learned_interface for entry in entries], ["a", "b", "b"])

    def test_bound_relay_state_serializes_worker_mutations_on_owner_loop(self):
        clock_threads = []

        def clock():
            clock_threads.append(threading.get_ident())
            return 10.0

        state = RelayState(
            RelayConfig(("a", "b"), discovery_hard_timeout_ms=1000),
            clock=clock,
        )
        self.assertFalse(hasattr(state, "_lock"))
        loop = asyncio.new_event_loop()
        ready = threading.Event()
        owner = {}

        def run_owner():
            asyncio.set_event_loop(loop)
            owner["thread_id"] = threading.get_ident()
            state.bind_owner_loop(loop)

            def heartbeat():
                if loop.is_running():
                    loop.call_later(0.01, heartbeat)

            loop.call_soon(heartbeat)
            ready.set()
            loop.run_forever()
            state.unbind_owner_loop()
            loop.close()

        owner_thread = threading.Thread(target=run_owner)
        owner_thread.start()
        self.assertTrue(ready.wait(timeout=1))

        def stop_owner():
            if loop.is_running():
                loop.call_soon_threadsafe(loop.stop)
            if owner_thread.is_alive():
                owner_thread.join(timeout=1)

        self.addCleanup(stop_owner)

        workers = [
            threading.Thread(target=lambda: [state.count("worker") for _ in range(5)])
            for _ in range(4)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())

        key = DiscoveryKey(INITIATOR, 99)
        state.create_discovery(
            key,
            incoming_interface="a",
            upstream_remote=None,
            upstream_token=b"up",
            upstream_request_context=None,
        )

        class Exchange:
            def __init__(self):
                self.close_thread = None

            def request_close(self):
                self.close_thread = threading.get_ident()

        exchange = Exchange()
        state.reserve_downstream(key, "b", exchange)
        state.close_discovery(key, reason="test")
        snapshot = state.snapshot()

        self.assertEqual(snapshot["counters"]["worker"], 20)
        self.assertTrue(snapshot["owner_bound"])
        self.assertGreaterEqual(snapshot["owner_dispatches"], 24)
        self.assertEqual(exchange.close_thread, owner["thread_id"])
        self.assertEqual(set(clock_threads), {owner["thread_id"]})

        stop_owner()
        self.assertFalse(owner_thread.is_alive())

    def test_bound_relay_state_never_falls_back_when_owner_loop_stops(self):
        state = RelayState(RelayConfig(("a", "b")))
        loop = asyncio.new_event_loop()
        state.bind_owner_loop(loop)

        def cleanup():
            if state._owner_loop is not None:
                state.unbind_owner_loop()
            if not loop.is_closed():
                loop.close()

        self.addCleanup(cleanup)
        errors = []

        worker = threading.Thread(
            target=lambda: self._capture_exception(errors, state.snapshot))
        worker.start()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertRegex(str(errors[0]), "owner loop is not running")
        cleanup()

    @staticmethod
    def _capture_exception(target, operation):
        try:
            operation()
        except Exception as exc:
            target.append(exc)

    def test_snapshot_reports_owned_state(self):
        key = DiscoveryKey(INITIATOR, 123)
        self.state.create_discovery(
            key, incoming_interface="a", upstream_remote="peer",
            upstream_token=b"up", upstream_request_context=None,
        )
        self.state.register_downstream(key, "b", b"down", object())
        snapshot = self.state.snapshot()
        self.assertEqual(snapshot["active_discovery_transactions"], 1)
        self.assertEqual(snapshot["active_downstream_branches"], 1)
        self.assertEqual(snapshot["response_digests"], 0)

    def test_repository_quiescence_reports_all_live_relay_state(self):
        key = DiscoveryKey(INITIATOR, 127)
        self.state.create_discovery(
            key, incoming_interface="a", upstream_remote="peer",
            upstream_token=b"up", upstream_request_context=None,
        )
        self.state.register_downstream(key, "b", b"down", object())
        with self.assertRaisesRegex(
                AssertionError, "active_discovery_transactions"):
            assert_quiescent(relay_state=self.state)
        self.state.close_discovery(key, reason="test")
        snapshot = assert_quiescent(relay_state=self.state)
        self.assertEqual(snapshot["relay"]["active_downstream_branches"], 0)

    def test_closing_transaction_requests_exchange_cleanup_once(self):
        class Exchange:
            def __init__(self):
                self.close_requests = 0

            def request_close(self):
                self.close_requests += 1

        key = DiscoveryKey(INITIATOR, 124)
        self.state.create_discovery(
            key, incoming_interface="a", upstream_remote="peer",
            upstream_token=b"up", upstream_request_context=None,
        )
        exchange = Exchange()
        branch = self.state.register_downstream(key, "b", b"down", exchange)
        self.assertIsNotNone(branch)
        self.assertTrue(self.state.close_discovery(key, reason="test"))
        self.assertFalse(self.state.close_discovery(key, reason="test-again"))
        self.assertEqual(exchange.close_requests, 1)
        self.assertEqual(branch.state, "CLOSED")

    def test_downstream_exchange_is_reserved_then_token_is_bound(self):
        key = DiscoveryKey(INITIATOR, 125)
        self.state.create_discovery(
            key, incoming_interface="a", upstream_remote="peer",
            upstream_token=b"up", upstream_request_context=None,
        )
        exchange = object()
        branch = self.state.reserve_downstream(key, "b", exchange)
        self.assertIsNotNone(branch)
        self.assertEqual(branch.token, b"")
        self.assertIs(
            self.state.bind_downstream_token(key, "b", b"assigned", exchange),
            branch,
        )
        self.assertEqual(branch.token, b"assigned")

    def test_downstream_token_bind_rejects_wrong_exchange(self):
        key = DiscoveryKey(INITIATOR, 126)
        self.state.create_discovery(
            key, incoming_interface="a", upstream_remote="peer",
            upstream_token=b"up", upstream_request_context=None,
        )
        self.state.reserve_downstream(key, "b", object())
        self.assertIsNone(
            self.state.bind_downstream_token(key, "b", b"assigned", object())
        )
        self.assertEqual(self.state.counters["downstream_token_bind_rejected"], 1)

    def test_objective_number_is_bounded_to_uint32(self):
        message = discovery()
        message[3][0] = 0x100000000
        with self.assertRaises(CodecError):
            encode_canonical(message)

    def test_relay_config_cli_overrides(self):
        parser = argparse.ArgumentParser()
        add_relay_arguments(parser)
        args = parser.parse_args([
            "--relay-interface", "eth0",
            "--relay-interface", "eth1",
            "--relay-hard-timeout-ms", "3000",
            "--relay-quiet-timeout-ms", "250",
            "--relay-rate", "5",
            "--relay-burst", "2",
        ])
        config = relay_config_from_args(args)
        self.assertEqual(config.enabled_interfaces, ("eth0", "eth1"))
        self.assertEqual(config.discovery_hard_timeout_ms, 3000)
        self.assertEqual(config.discovery_quiet_timeout_ms, 250)
        self.assertEqual(config.relay_rate_per_second, 5)
        self.assertEqual(config.relay_burst, 2)

    def test_relay_config_file_overrides(self):
        parser = argparse.ArgumentParser()
        add_relay_arguments(parser)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "relay.json"
            path.write_text('{"enabled_interfaces":["a","b"],"relay_burst":3}', encoding="utf-8")
            config = relay_config_from_args(parser.parse_args(["--relay-config", str(path)]))
        self.assertEqual(config.enabled_interfaces, ("a", "b"))
        self.assertEqual(config.relay_burst, 3)


class RateLimiterTests(unittest.TestCase):
    def test_bucket_refills(self):
        bucket = TokenBucket(2, 2, now=0)
        self.assertTrue(bucket.allow(0))
        self.assertTrue(bucket.allow(0))
        self.assertFalse(bucket.allow(0))
        self.assertTrue(bucket.allow(0.5))

    def test_interfaces_are_independent(self):
        state = RelayState(RelayConfig(("a", "b"), relay_rate_per_second=1, relay_burst=1),
                           clock=lambda: 0)
        self.assertTrue(state.allow("flood", "a"))
        self.assertFalse(state.allow("flood", "a"))
        self.assertTrue(state.allow("flood", "b"))


class FakeManager:
    def __init__(self):
        self.outgoing_requests = {}
        self.pipe = None
        self.counter = 0
        self.requests_sent = 0

    def request(self, pipe):
        self.requests_sent += 1
        self.counter += 1
        self.pipe = pipe
        pipe.request.token = bytes([self.counter])
        self.outgoing_requests[(pipe.request.token, None)] = pipe


class FakeContext:
    def __init__(self):
        self.manager = FakeManager()

    async def find_remote_and_interface(self, _request):
        return self.manager


class ExchangeTests(unittest.IsolatedAsyncioTestCase):
    def test_adapter_version_contract_is_explicit(self):
        self.assertEqual(aiocoap_adapter_version(), "0.4.17")
        self.assertEqual(assert_supported_aiocoap(), aiocoap_adapter_version())
        self.assertEqual(
            assert_aiocoap_private_contract(), aiocoap_adapter_version())
        with mock.patch(
                "cgrasp.coap_multicast_adapter.aiocoap_adapter_version",
                return_value="0.4.18"):
            with self.assertRaisesRegex(RuntimeError, "Unsupported aiocoap version 0.4.18"):
                assert_supported_aiocoap()
        from aiocoap import protocol
        with mock.patch.object(protocol.TokenManager, "request", None):
            with self.assertRaisesRegex(
                    RuntimeError, r"protocol\.TokenManager\.request"):
                assert_aiocoap_private_contract()

    async def test_collects_three_and_close_is_idempotent(self):
        import aiocoap
        request = aiocoap.Message(code=aiocoap.Code.FETCH, uri="coap://[ff02::fd%lo]/x")
        context = FakeContext()
        exchange = MulticastExchange(context, request, "lo", 1)
        await exchange.start()
        self.assertTrue(exchange.snapshot()["token_registered"])
        for index in range(3):
            message = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=bytes([index]))
            message.token = b"\x01"
            message.mid = index + 1
            context.manager.pipe.add_response(message, True)
        seen = []
        async for item in exchange:
            seen.append(item.payload)
            if len(seen) == 3:
                break
        self.assertEqual(seen, [b"\0", b"\1", b"\2"])
        await exchange.close()
        await exchange.close()
        self.assertNotIn((b"\x01", None), context.manager.outgoing_requests)
        snapshot = exchange.snapshot()
        self.assertTrue(snapshot["closed"])
        self.assertFalse(snapshot["token_registered"])
        self.assertEqual(snapshot["responses_received"], 3)

    async def test_same_endpoint_and_token_deliver_multiple_responses(self):
        import aiocoap

        request = aiocoap.Message(code=aiocoap.Code.FETCH, uri="coap://[ff02::fd%lo]/x")
        context = FakeContext()
        exchange = MulticastExchange(context, request, "r-upstream", 1)
        await exchange.start()
        remote = SimpleNamespace(sockaddr=("fd00::fe", 5683, 0, 1))
        for mid, payload in ((100, b"first"), (101, b"second")):
            message = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=payload)
            message.token = request.token
            message.mid = mid
            message.remote = remote
            context.manager.pipe.add_response(message, True)
        responses = []
        async for response in exchange:
            responses.append(response)
            if len(responses) == 2:
                break
        self.assertEqual([item.payload for item in responses], [b"first", b"second"])
        self.assertEqual({item.token for item in responses}, {request.token})
        self.assertEqual({item.remote.sockaddr[0] for item in responses}, {"fd00::fe"})
        self.assertEqual({item.interface for item in responses}, {"r-upstream"})
        await exchange.close()

    async def test_each_downstream_exchange_gets_a_fresh_token(self):
        import aiocoap
        context = FakeContext()
        first_request = aiocoap.Message(code=aiocoap.Code.FETCH, uri="coap://[ff02::fd%lo]/x")
        second_request = aiocoap.Message(code=aiocoap.Code.FETCH, uri="coap://[ff02::fd%lo]/x")
        first = MulticastExchange(context, first_request, "a", 1)
        second = MulticastExchange(context, second_request, "b", 1)
        await first.start()
        await second.start()
        self.assertNotEqual(first_request.token, second_request.token)
        await first.close()
        await second.close()

    async def test_collector_reports_branch_before_accepting_responses(self):
        context = FakeContext()
        client = CoapClient(_ctx=context)
        started = []

        await client.fetch_multicast_collect(
            ["coap://[ff02::fd%lo]/x"],
            b"request",
            hard_timeout=0.5,
            on_exchange_started=lambda interface, token, exchange: started.append(
                (interface, token, exchange.snapshot()["token_registered"])
            ),
        )

        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][0], "coap://[ff02::fd%lo]/x")
        self.assertTrue(started[0][1])
        self.assertTrue(started[0][2])

    async def test_collector_exposes_exchange_before_transport_send(self):
        context = FakeContext()
        client = CoapClient(_ctx=context)
        created = []
        started = []

        await client.fetch_multicast_collect(
            ["coap://[ff02::fd%lo]/x"],
            b"request",
            hard_timeout=0.5,
            on_exchange_created=lambda interface, exchange: created.append(
                (interface, context.manager.requests_sent, exchange)
            ),
            on_exchange_started=lambda interface, token, exchange: started.append(
                (interface, token, context.manager.requests_sent)
            ),
        )

        self.assertEqual(len(created), 1)
        self.assertEqual(created[0][1], 0)
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][2], 1)

    async def test_collector_reports_response_before_window_closes(self):
        import aiocoap
        context = FakeContext()
        client = CoapClient(_ctx=context)
        exchanges = []
        response_seen = asyncio.Event()
        streamed = []

        collector = asyncio.create_task(client.fetch_multicast_collect(
            ["coap://[ff02::fd%lo]/x"],
            b"request",
            hard_timeout=30,
            on_exchange_created=lambda _interface, exchange: exchanges.append(exchange),
            on_response=lambda response: (
                streamed.append(response.payload), response_seen.set()
            ),
        ))
        while context.manager.pipe is None:
            await asyncio.sleep(0)
        response = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=b"streamed")
        response.token = context.manager.pipe.request.token
        response.mid = 77
        response.remote = SimpleNamespace(sockaddr=("fd00::2", 5683, 0, 1))
        context.manager.pipe.add_response(response, True)

        await asyncio.wait_for(response_seen.wait(), timeout=3.0)
        self.assertEqual(streamed, [b"streamed"])
        self.assertFalse(collector.done(), "response callback must precede window close")
        exchanges[0].request_close()
        collected = await asyncio.wait_for(collector, timeout=3.0)
        self.assertEqual([item.payload for item in collected], [b"streamed"])

    async def test_multicast_pipe_handler_does_not_buffer_streamed_responses(self):
        emitted = asyncio.Event()
        release = asyncio.Event()

        async def handler(_request, pipe):
            pipe.add_response(b"first", is_last=False)
            emitted.set()
            await release.wait()

        class Pipe:
            request = SimpleNamespace(
                remote=SimpleNamespace(is_multicast_locally=True))

            def __init__(self):
                self.responses = []

            def add_response(self, response, is_last=False):
                self.responses.append((response, is_last))

        pipe = Pipe()
        task = asyncio.create_task(PipeHandlerResource(handler).render_to_pipe(pipe))
        await asyncio.wait_for(emitted.wait(), timeout=3.0)
        self.assertEqual(pipe.responses, [(b"first", False)])
        self.assertFalse(task.done())
        release.set()
        await task

    async def test_multicast_pipe_rejects_ambiguous_large_stream_response(self):
        async def handler(_request, pipe):
            pipe.add_response(
                b"X" * 1025,
                is_last=False,
            )

        class Pipe:
            request = SimpleNamespace(
                remote=SimpleNamespace(
                    is_multicast_locally=True,
                    maximum_payload_size=1124,
                    maximum_block_size_exp=6,
                )
            )

            def __init__(self):
                self.responses = []

            def add_response(self, response, is_last=False):
                self.responses.append((response, is_last))

        pipe = Pipe()
        with self.assertRaisesRegex(
                StreamingResponsePayloadTooLarge,
                "1025 bytes; single-message limit is 1024 bytes"):
            await PipeHandlerResource(handler).render_to_pipe(pipe)
        self.assertEqual(pipe.responses, [])

    async def test_multicast_pipe_accepts_stream_response_at_payload_limit(self):
        expected = b"X" * 1024

        async def handler(_request, pipe):
            pipe.add_response(expected, is_last=True)

        class Pipe:
            request = SimpleNamespace(
                remote=SimpleNamespace(
                    is_multicast_locally=True,
                    maximum_payload_size=1124,
                    maximum_block_size_exp=6,
                )
            )

            def __init__(self):
                self.responses = []

            def add_response(self, response, is_last=False):
                self.responses.append((response, is_last))

        pipe = Pipe()
        await PipeHandlerResource(handler).render_to_pipe(pipe)
        self.assertEqual(pipe.responses, [(expected, True)])

    async def test_collector_propagates_stream_callback_failure(self):
        import aiocoap
        context = FakeContext()
        client = CoapClient(_ctx=context)

        def fail(_response):
            raise RuntimeError("upstream pipe closed")

        collector = asyncio.create_task(client.fetch_multicast_collect(
            ["coap://[ff02::fd%lo]/x"], b"request", hard_timeout=1,
            on_response=fail,
        ))
        while context.manager.pipe is None:
            await asyncio.sleep(0)
        response = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=b"streamed")
        response.token = context.manager.pipe.request.token
        response.mid = 78
        response.remote = SimpleNamespace(sockaddr=("fd00::2", 5683, 0, 1))
        context.manager.pipe.add_response(response, True)

        with self.assertRaisesRegex(RuntimeError, "upstream pipe closed"):
            await asyncio.wait_for(collector, timeout=3.0)

    async def test_pre_send_close_prevents_transport_send(self):
        context = FakeContext()
        client = CoapClient(_ctx=context)
        started = []

        await client.fetch_multicast_collect(
            ["coap://[ff02::fd%lo]/x"],
            b"request",
            hard_timeout=0.5,
            on_exchange_created=lambda _interface, exchange: exchange.request_close(),
            on_exchange_started=lambda *args: started.append(args),
        )

        self.assertEqual(context.manager.requests_sent, 0)
        self.assertEqual(started, [])

    async def test_timeout_closes_exchange_and_late_response_is_ignored(self):
        import aiocoap
        context = FakeContext()
        request = aiocoap.Message(code=aiocoap.Code.FETCH, uri="coap://[ff02::fd%lo]/x")
        exchange = MulticastExchange(context, request, "lo", 0.01)
        seen = []
        async for item in exchange:
            seen.append(item.payload)
        self.assertEqual(seen, [])
        self.assertNotIn((request.token, None), context.manager.outgoing_requests)
        late = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=b"late")
        late.token = request.token
        late.mid = 99
        context.manager.pipe.add_response(late, True)
        self.assertTrue(exchange._queue.empty())

    async def test_threadsafe_close_request_is_idempotent(self):
        import aiocoap
        context = FakeContext()
        request = aiocoap.Message(code=aiocoap.Code.FETCH, uri="coap://[ff02::fd%lo]/x")
        exchange = MulticastExchange(context, request, "lo", 1)
        await exchange.start()
        exchange.request_close()
        exchange.request_close()
        await asyncio.sleep(0)
        self.assertTrue(exchange.snapshot()["closed"])
        self.assertNotIn((request.token, None), context.manager.outgoing_requests)
        snapshot = assert_quiescent(exchanges=(exchange,))
        self.assertFalse(snapshot["exchanges"][0]["token_registered"])

    async def test_close_wakes_an_exchange_waiting_for_a_response(self):
        import aiocoap
        context = FakeContext()
        request = aiocoap.Message(code=aiocoap.Code.FETCH, uri="coap://[ff02::fd%lo]/x")
        exchange = MulticastExchange(context, request, "lo", 30)
        await exchange.start()

        async def consume():
            return [item async for item in exchange]

        consumer = asyncio.create_task(consume())
        await asyncio.sleep(0)
        exchange.request_close()
        self.assertEqual(await asyncio.wait_for(consumer, timeout=3.0), [])


class RuntimeResponderCacheTests(unittest.TestCase):
    def test_standard_relay_owns_upstream_exchange_metadata(self):
        from cgrasp import cgrasp as cg

        class CapturingState(RelayState):
            closed_transaction = None

            def close_discovery(self, key, *, reason):
                self.closed_transaction = self.discovery.get(key)
                return super().close_discovery(key, reason=reason)

        state = CapturingState(RelayConfig(("a", "b")))
        previous = cg._coap_relay_state
        cg._coap_relay_state = state
        self.addCleanup(setattr, cg, "_coap_relay_state", previous)
        parsed = cg._parse_msg(discovery())
        upstream_remote = object()
        upstream_pipe = object()

        with mock.patch.object(cg, "_std_coap_mc_uris", return_value=[]), \
                mock.patch("cgrasp.coap_client.coap_fetch_multicast_collect_sync", return_value=[]):
            self.assertEqual(
                cg._std_coap_relay_discovery(
                    parsed, 0, upstream_remote=upstream_remote,
                    upstream_token=b"upstream-token",
                    upstream_request_context=upstream_pipe,
                ),
                [],
            )

        tx = state.closed_transaction
        self.assertIsNotNone(tx)
        self.assertIs(tx.upstream_remote, upstream_remote)
        self.assertEqual(tx.upstream_token, b"upstream-token")
        self.assertIs(tx.upstream_request_context, upstream_pipe)

    def test_cancelled_upstream_does_not_create_relay_transaction(self):
        from cgrasp import cgrasp as cg

        state = RelayState(RelayConfig(("a", "b")))
        previous = cg._coap_relay_state
        cg._coap_relay_state = state
        self.addCleanup(setattr, cg, "_coap_relay_state", previous)
        cancelled = threading.Event()
        cancelled.set()

        self.assertEqual(
            cg._std_coap_relay_discovery(
                cg._parse_msg(discovery()), 0, cancel_event=cancelled,
            ),
            [],
        )
        self.assertEqual(state.remaining_discovery_transactions(), 0)

    def test_cached_responder_builds_divert_response(self):
        from cgrasp import cgrasp as cg

        class Msg:
            id_value = 123
            id_source = INITIATOR

            class Obj:
                num = 42

            obj = Obj()

        old_state = cg._coap_relay_state
        old_dull = cg.DULL
        had_test_divert = hasattr(cg, "_test_divert")
        old_test_divert = getattr(cg, "_test_divert", False)
        try:
            state = RelayState(RelayConfig(("a", "b")), clock=lambda: 100.0)
            locator = [106, "coap://[fe80::2]:5683/.well-known/grasp-coap", 17, 5683]
            state.remember_responder(
                42, (locator,), "b", 1000,
                responder_identity=("fe80::2", 5683),
            )
            state.remember_responder(
                42, (locator,), "b", 1000,
                responder_identity=("fe80::3", 5683),
            )
            cg._coap_relay_state = state
            cg.DULL = False
            cg._test_divert = True
            raw = cg._std_coap_mc_build_discovery_response(Msg(), 1)[0]
            decoded = cbor2.loads(cg._decrypt_msg(raw))
        finally:
            cg._coap_relay_state = old_state
            cg.DULL = old_dull
            if had_test_divert:
                cg._test_divert = old_test_divert
            else:
                delattr(cg, "_test_divert")
        self.assertEqual(decoded[0], 2)
        self.assertEqual(decoded[1], 123)
        self.assertEqual(decoded[4][0], 100)
        self.assertEqual(decoded[4][1][0], 106)
        self.assertEqual(len(decoded[4]), 2, "duplicate advertised locators are collapsed")


if __name__ == "__main__":
    unittest.main()
