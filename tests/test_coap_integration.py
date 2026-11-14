# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import asyncio
import json
import os
import ast
import ipaddress
import re
import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import cbor2

from cgrasp.cgrasp_quiescence import assert_quiescent
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE = ROOT / "tests" / "interop_node.py"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_SRC = ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def parse_result(output: str) -> dict:
    for line in reversed(output.splitlines()):
        try:
            item = json.loads(line)
        except Exception:
            continue
        if item.get("event") == "result":
            return item
    raise AssertionError(f"no result record in output:\n{output}")


def assert_strict(result: dict, *, minimum_unicast=0, minimum_multicast=0) -> None:
    assert result["ok"], result
    audit = result["audit"]
    assert audit["coap_unicast_requests"] >= minimum_unicast
    assert audit["coap_multicast_requests"] >= minimum_multicast
    assert audit["tcp_connections"] == 0
    assert audit["legacy_udp_messages"] == 0
    assert audit["fallback_count"] == 0
    assert audit["errors"] == []


def run_pair(server_role: str, client_role: str, obj: int, *, extra_args=()) -> tuple[dict, dict]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    server = subprocess.Popen(
        [sys.executable, str(NODE), server_role, "--obj", str(obj), *extra_args],
        cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert server.stdout is not None
    startup = []
    deadline = time.time() + 10
    while time.time() < deadline:
        line = server.stdout.readline()
        if line:
            startup.append(line)
            try:
                if json.loads(line).get("event") == "ready":
                    break
            except Exception:
                pass
        elif server.poll() is not None:
            break
    else:
        server.kill()
        server.communicate()
        raise AssertionError("server did not become ready")

    client = subprocess.run(
        [sys.executable, str(NODE), client_role, "--obj", str(obj), *extra_args],
        cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )
    try:
        remaining, _ = server.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        remaining, _ = server.communicate()
    server_output = "".join(startup) + remaining
    assert client.returncode == 0, client.stdout
    assert server.returncode == 0, server_output
    return parse_result(client.stdout), parse_result(server_output)


def parse_std_audit(output: str, prefix: str) -> dict:
    match = re.search(rf"^\[{re.escape(prefix)}\] TEST_RESULT .*?audit=(\{{.*\}})$", output, re.MULTILINE)
    if not match:
        raise AssertionError(f"no {prefix} TEST_RESULT audit in output:\n{output}")
    return ast.literal_eval(match.group(1))


def run_std_asa_pair() -> tuple[str, str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    briggs = subprocess.Popen(
        [
            sys.executable, str(ROOT / "CoapBriggsStd.py"),
            "--listen-self", "--strict-coap", "--bind", "::", "--coap-port", "5683",
            "--flood-interval-s", "0.5",
        ],
        cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    assert briggs.stdout is not None
    startup = []
    deadline = time.time() + 15
    while time.time() < deadline:
        line = briggs.stdout.readline()
        if line:
            startup.append(line)
            if "Ready to negotiate EX3" in line:
                break
        elif briggs.poll() is not None:
            break
    else:
        briggs.kill()
        remaining, _ = briggs.communicate()
        raise AssertionError("CoapBriggsStd did not become ready:\n" + "".join(startup) + remaining)

    gray = subprocess.run(
        [
            sys.executable, str(ROOT / "CoapGrayStd.py"),
            "--listen-self", "--strict-coap", "--bind", "::", "--coap-port", "15683",
            "--test-iterations", "1", "--fixed-request", "50",
            "--timeout-ms", "5000", "--sleep-s", "0",
        ],
        cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    briggs.terminate()
    try:
        remaining, _ = briggs.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        briggs.kill()
        remaining, _ = briggs.communicate()
    briggs_output = "".join(startup) + remaining
    assert gray.returncode == 0, gray.stdout
    assert briggs.returncode == 0, briggs_output
    return gray.stdout, briggs_output


_WINDOWS_SKIP = {
    "test_fast_negotiation_over_strict_coap",
    "test_synchronization_over_strict_coap",
    "test_multiround_negotiation_over_strict_coap",
    "test_large_synchronization_uses_blockwise",
    "test_standard_single_link_discovery",
    "test_standard_single_link_flood",
    "test_std_gray_briggs_asa_pair",
}


class CoapIntegrationTests(unittest.TestCase):
    def setUp(self):
        # aiocoap's Windows fallback transport (simplesocketserver) cannot bind
        # the any-address and therefore cannot receive the locators used by
        # these end-to-end tests.  They run on Linux/macOS CI; skipping them
        # here keeps the Windows unit/loopback suite meaningful.
        if sys.platform == "win32" and self._testMethodName in _WINDOWS_SKIP:
            self.skipTest(
                "aiocoap Windows fallback cannot bind the any-address; "
                "run this end-to-end test on Linux")

    class _FakeCg:
        @staticmethod
        def _option(number):
            return SimpleNamespace(number=number, reason=None)

        @staticmethod
        def _ass_message(mtype, sid, _source, body):
            if mtype == 6 and body and hasattr(body[0], "reason"):
                body = [102, body[0].reason]
            return cbor2.dumps([mtype, sid, body])

        @staticmethod
        def _parse_msg(decoded):
            return SimpleNamespace(obj=decoded[2])

        @staticmethod
        def _coap_immediate_synchronize_response(_msg):
            return None

    @staticmethod
    def _request_from(peer):
        return SimpleNamespace(remote=SimpleNamespace(hostinfo=f"[{peer}]:5683"))

    def test_closed_server_socket_keeps_queued_response(self):
        from cgrasp.cgrasp_coap_transport import CoapServerSessionSocket

        sock = CoapServerSessionSocket(
            sid=123,
            peer_addr=ipaddress.IPv6Address("fd00::1"),
        )
        sock.sendall(b"final-response")
        sock.close()

        self.assertEqual(sock.pop_outbound(timeout_s=0), b"final-response")

    def test_server_socket_routes_concurrent_exchange_responses_independently(self):
        from cgrasp.cgrasp_coap_transport import CoapServerSessionSocket

        sock = CoapServerSessionSocket(
            sid=124,
            peer_addr=ipaddress.IPv6Address("fd00::1"),
        )
        first = sock.begin_exchange(token=b"first", inbound=b"request-1")
        second = sock.begin_exchange(token=b"second", inbound=b"request-2")

        self.assertEqual(sock.recvfrom(2048)[0], b"request-1")
        sock.sendall(b"response-1")
        self.assertEqual(sock.recvfrom(2048)[0], b"request-2")
        sock.sendall(b"response-2")

        # Deliberately collect in reverse order: each handler owns its queue.
        self.assertEqual(second.pop_response(timeout_s=0), b"response-2")
        self.assertEqual(first.pop_response(timeout_s=0), b"response-1")
        first.close()
        second.close()
        self.assertEqual(sock.exchange_snapshots(), ())
        sock.close()

    def test_server_socket_bounds_and_deduplicates_exchange_registry(self):
        from cgrasp.cgrasp_coap_transport import (
            BridgeExchangeCapacityError,
            BridgeExchangeConflictError,
            CoapServerSessionSocket,
        )

        sock = CoapServerSessionSocket(
            sid=125,
            peer_addr=ipaddress.IPv6Address("fd00::1"),
            max_pending_exchanges=1,
        )
        exchange = sock.begin_exchange(token=b"one")
        with self.assertRaises(BridgeExchangeConflictError):
            sock.begin_exchange(token=b"one")
        with self.assertRaises(BridgeExchangeCapacityError):
            sock.begin_exchange(token=b"two")
        exchange.close()
        replacement = sock.begin_exchange(token=b"two")
        replacement.close()
        sock.close()

    def test_bridge_snapshot_includes_exchange_identity_and_quiescence(self):
        from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge

        bridge = CgraspCoapApiBridge(cg=self._FakeCg())
        peer = ipaddress.IPv6Address("fd00::1")
        sock = bridge._get_or_create_session(126, peer)
        exchange = sock.begin_exchange(token=b"token", direction="inbound")
        snapshot = bridge.snapshot()
        self.assertEqual(snapshot["active_exchanges"], 1)
        self.assertEqual(
            snapshot["exchanges"][0],
            {
                "sid": 126,
                "peer": "fd00::1",
                "token": b"token".hex(),
                "direction": "inbound",
                "closed": False,
                "response_routed": False,
                "pending_responses": 0,
            },
        )
        with self.assertRaisesRegex(AssertionError, "active_exchanges"):
            assert_quiescent(bridge=bridge)
        exchange.close()
        sock.close()
        self.assertEqual(
            assert_quiescent(bridge=bridge)["bridge"]["active_exchanges"], 0)

    def test_terminal_response_stays_visible_until_exchange_consumes_it(self):
        from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge

        bridge = CgraspCoapApiBridge(cg=self._FakeCg())
        peer = ipaddress.IPv6Address("fd00::1")
        sock = bridge._get_or_create_session(128, peer)
        exchange = sock.begin_exchange(token=b"terminal")
        terminal = cbor2.dumps([6, 128, [101]])
        sock.sendall(terminal)

        snapshot = bridge.snapshot()
        self.assertEqual(snapshot["active_sessions"], 1)
        self.assertEqual(snapshot["active_exchanges"], 1)
        self.assertEqual(snapshot["exchanges"][0]["pending_responses"], 1)
        self.assertEqual(exchange.pop_response(timeout_s=0), terminal)
        exchange.close()
        assert_quiescent(bridge=bridge)

    def test_bridge_separates_same_session_id_by_peer(self):
        from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge

        bridge = CgraspCoapApiBridge(cg=self._FakeCg())
        first = bridge._get_or_create_session(123, ipaddress.IPv6Address("fd00::1"))
        second = bridge._get_or_create_session(123, ipaddress.IPv6Address("fd00::2"))
        self.assertIsNot(first, second)
        self.assertEqual(bridge.snapshot()["active_sessions"], 2)
        with self.assertRaisesRegex(AssertionError, "active_sessions"):
            assert_quiescent(bridge=bridge)
        first.close()
        second.close()
        self.assertEqual(
            assert_quiescent(bridge=bridge)["bridge"]["active_sessions"], 0)

    def test_missing_sync_listener_is_explicit_decline_without_session_leak(self):
        from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge

        bridge = CgraspCoapApiBridge(cg=self._FakeCg())
        request = self._request_from("fd00::1")
        payload = cbor2.dumps([4, 456, [42, 1, 1, None]])
        response = asyncio.run(bridge.handle_post(payload, request))
        decoded = cbor2.loads(response)
        self.assertEqual(decoded[0], 6)
        self.assertEqual(decoded[2][0], 102)
        self.assertIn("synchronization listener", decoded[2][1])
        self.assertEqual(
            assert_quiescent(bridge=bridge)["bridge"]["active_sessions"], 0)

    def test_terminal_inbound_closes_and_unregisters_session(self):
        from cgrasp.cgrasp_coap_transport import CgraspCoapApiBridge

        bridge = CgraspCoapApiBridge(cg=self._FakeCg())
        peer = ipaddress.IPv6Address("fd00::1")
        sock = bridge._get_or_create_session(789, peer)
        terminal = cbor2.dumps([6, 789, [101]])
        sock.push_inbound(terminal)
        self.assertEqual(sock.recvfrom(2048)[0], terminal)
        self.assertTrue(sock.closed)
        self.assertEqual(
            assert_quiescent(bridge=bridge)["bridge"]["active_sessions"], 0)

    def test_event_transport_missing_sync_handler_declines(self):
        from cgrasp.cgrasp_coap_transport import CgraspCoapTransport

        transport = CgraspCoapTransport(bind=("::", 0))
        raw = asyncio.run(transport._handle_sync(321, [4, 321, [42, 1, 1, None]]))
        decoded = cbor2.loads(raw)
        self.assertEqual(decoded, [6, 321, [102, "No synchronization handler for objective"]])

    def test_unicast_transport_retains_timeout_cause(self):
        from cgrasp.cgrasp_coap_transport import (
            CoapFailureCause, CoapTransportError, CoapUnicastSocket,
        )

        sock = CoapUnicastSocket("coap://[fd00::1]:5683", sid=12)
        with mock.patch(
            "cgrasp.cgrasp_coap_transport.coap_post_pooled_sync",
            side_effect=TimeoutError("deadline"),
        ):
            with self.assertRaises(CoapTransportError) as raised:
                sock.sendall(b"payload")
        self.assertEqual(raised.exception.cause, CoapFailureCause.TRANSPORT_TIMEOUT)
        self.assertEqual(sock.last_failure, CoapFailureCause.TRANSPORT_TIMEOUT)

    def test_unicast_success_code_is_centralized(self):
        import aiocoap
        from cgrasp.coap_server import CGRASP_CONTENT_FORMAT, CGRASP_UNICAST_SUCCESS_CODE

        self.assertEqual(CGRASP_UNICAST_SUCCESS_CODE, aiocoap.Code.CONTENT)
        self.assertEqual(CGRASP_CONTENT_FORMAT, 60)

    def test_baseline_profile_disables_wait(self):
        proc = subprocess.run(
            [sys.executable, str(NODE), "baseline-wait-disabled"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertTrue(parse_result(proc.stdout)["ok"])

    def test_synchronization_over_strict_coap(self):
        client, server = run_pair("sync-server", "sync-client", 47101)
        assert_strict(client, minimum_unicast=1)
        assert_strict(server)

    def test_fast_negotiation_over_strict_coap(self):
        client, server = run_pair("fast-server", "fast-client", 47102)
        assert_strict(client, minimum_unicast=1)
        assert_strict(server)

    def test_multiround_negotiation_over_strict_coap(self):
        client, server = run_pair("multiround-server", "multiround-client", 47103)
        assert_strict(client, minimum_unicast=2)
        assert_strict(server)

    def test_large_synchronization_uses_blockwise(self):
        client, server = run_pair("sync-server", "sync-client", 47106,
                                  extra_args=("--payload-size", "16384", "--timeout-ms", "8000"))
        assert_strict(client, minimum_unicast=1)
        assert_strict(server)

    def test_standard_single_link_discovery(self):
        proc = subprocess.run(
            [sys.executable, str(NODE), "discovery-self", "--obj", "47104"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
        )
        unavailable = ("Network is unreachable", "No multicast-capable interface", "Operation not permitted")
        if any(message in proc.stdout for message in unavailable):
            self.skipTest("environment has no usable IPv6 link-local multicast interface")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        assert_strict(parse_result(proc.stdout), minimum_multicast=1)

    def test_standard_single_link_flood(self):
        proc = subprocess.run(
            [sys.executable, str(NODE), "flood-self", "--obj", "47107", "--value", "flood-value"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
        )
        unavailable = ("Network is unreachable", "No multicast-capable interface", "Operation not permitted")
        if any(message in proc.stdout for message in unavailable):
            self.skipTest("environment has no usable IPv6 link-local multicast interface")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        assert_strict(parse_result(proc.stdout), minimum_multicast=1)

    def test_std_gray_briggs_asa_pair(self):
        gray_output, briggs_output = run_std_asa_pair()
        self.assertIn("[gray] Discovered locator:", gray_output)
        self.assertIn("[gray] Accepted offer", gray_output)
        self.assertIn("[briggs] New session", briggs_output)
        gray_audit = parse_std_audit(gray_output, "gray")
        briggs_audit = parse_std_audit(briggs_output, "briggs")
        for audit in (gray_audit, briggs_audit):
            self.assertEqual(audit["tcp_connections"], 0)
            self.assertEqual(audit["legacy_udp_messages"], 0)
            self.assertEqual(audit["fallback_count"], 0)
            self.assertEqual(audit["errors"], [])


if __name__ == "__main__":
    unittest.main()
