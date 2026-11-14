# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import unittest

from cgrasp.cgrasp_multicast import (
    CodecError,
    DiscoveryKey,
    RelayConfig,
    RelayState,
    decrement_loop_count,
    validate_discovery_response,
)


INITIATOR = bytes.fromhex("fd000001000000000000000000000010")
OTHER_INITIATOR = bytes.fromhex("fd000009000000000000000000000099")


def discovery(loop: int) -> list:
    return [1, 0x1234, INITIATOR, [42, 1, loop, None]]


def response(session: int = 0x1234, initiator: bytes = INITIATOR, locator_suffix: int = 20) -> list:
    locator = bytes.fromhex("fd0000030000000000000000000000") + bytes([locator_suffix])
    return [2, session, initiator, 10000, [103, locator, 17, 5683]]


class MultihopPlanProtocolTests(unittest.TestCase):
    def test_tc_mh_02_loop_count_boundaries(self):
        hop1 = decrement_loop_count(discovery(2))
        self.assertEqual(hop1[3][2], 1)
        hop2 = decrement_loop_count(hop1)
        self.assertEqual(hop2[3][2], 0)
        with self.assertRaises(CodecError):
            decrement_loop_count(hop2)
        original = discovery(3)
        changed = decrement_loop_count(original)
        self.assertEqual(original[3][2], 3)
        self.assertEqual(changed[3][2], 2)

    def test_tc_mh_04_duplicate_discovery_preserves_first_transaction(self):
        now = 100.0
        state = RelayState(RelayConfig(("r1-in", "r1-out"), discovery_hard_timeout_ms=3000),
                           clock=lambda: now)
        key = DiscoveryKey(INITIATOR, 0x1234)
        first = state.create_discovery(
            key,
            incoming_interface="r1-in",
            upstream_remote=("fd00:1::10", 5683),
            upstream_token=b"T0",
            upstream_request_context="first",
        )
        duplicate = state.create_discovery(
            key,
            incoming_interface="r1-alt",
            upstream_remote=("fd00:1::99", 5683),
            upstream_token=b"Tbad",
            upstream_request_context="second",
        )
        self.assertIsNotNone(first)
        self.assertIsNone(duplicate)
        self.assertEqual(state.discovery[key].incoming_interface, "r1-in")
        self.assertEqual(state.discovery[key].upstream_token, b"T0")
        self.assertEqual(state.discovery[key].upstream_request_context, "first")
        self.assertEqual(state.counters.get("discovery_duplicate_dropped"), 1)

    def test_tc_mh_05_response_semantic_deduplication(self):
        state = RelayState(RelayConfig(("r2-in", "r2-out")))
        key = DiscoveryKey(INITIATOR, 0x1234)
        tx = state.create_discovery(
            key,
            incoming_interface="r2-in",
            upstream_remote=None,
            upstream_token=b"T1",
            upstream_request_context=None,
        )
        self.assertIsNotNone(tx)
        first = state.validate_transaction_response(
            key,
            response(),
            expected_token=b"T2",
            received_token=b"T2",
        )
        self.assertTrue(first.accepted)
        duplicate = state.validate_transaction_response(
            key,
            response(),
            expected_token=b"T2",
            received_token=b"T2",
        )
        self.assertFalse(duplicate.accepted)
        self.assertEqual(duplicate.reason, "response_duplicate_dropped")
        self.assertEqual(tx.response_count, 1)
        self.assertEqual(len(tx.response_digests), 1)
        self.assertEqual(state.counters.get("accepted"), 1)
        self.assertEqual(state.counters.get("response_duplicate_dropped"), 1)

    def test_tc_mh_06_wrong_token_rejected(self):
        result = validate_discovery_response(
            response(),
            expected_key=DiscoveryKey(INITIATOR, 0x1234),
            expected_token=b"T2",
            received_token=b"Tbad",
        )
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "response_token_mismatch")

    def test_tc_mh_07_wrong_session_or_initiator_rejected(self):
        wrong_session = validate_discovery_response(
            response(session=0x9999),
            expected_key=DiscoveryKey(INITIATOR, 0x1234),
            expected_token=b"T2",
            received_token=b"T2",
        )
        self.assertFalse(wrong_session.accepted)
        self.assertEqual(wrong_session.reason, "response_session_mismatch")

        wrong_initiator = validate_discovery_response(
            response(initiator=OTHER_INITIATOR),
            expected_key=DiscoveryKey(INITIATOR, 0x1234),
            expected_token=b"T2",
            received_token=b"T2",
        )
        self.assertFalse(wrong_initiator.accepted)
        self.assertEqual(wrong_initiator.reason, "response_initiator_mismatch")

    def test_tc_mh_08_hard_timeout_cleans_transaction(self):
        now = 0.0

        def clock():
            return now

        state = RelayState(RelayConfig(("r2-in", "r2-out"), discovery_hard_timeout_ms=1000),
                           clock=clock)
        key = DiscoveryKey(INITIATOR, 0x1234)
        state.create_discovery(
            key,
            incoming_interface="r2-in",
            upstream_remote=None,
            upstream_token=b"T1",
            upstream_request_context=None,
        )
        self.assertIn(key, state.discovery)
        now = 1.5
        state.cleanup()
        self.assertNotIn(key, state.discovery)
        late = validate_discovery_response(
            response(),
            expected_key=key,
            expected_token=b"T2",
            received_token=b"T2",
        )
        self.assertTrue(late.accepted)
        self.assertNotIn(key, state.discovery)

    def test_tc_mh_10_cleared_transaction_rejects_late_response_without_recreate(self):
        state = RelayState(RelayConfig(("r2-in", "r2-out")))
        key = DiscoveryKey(INITIATOR, 0x1234)
        state.create_discovery(
            key,
            incoming_interface="r2-in",
            upstream_remote=None,
            upstream_token=b"T1",
            upstream_request_context=None,
        )
        self.assertEqual(state.clear_discovery_transactions(reason="test"), 1)
        late = state.validate_transaction_response(
            key,
            response(),
            expected_token=b"T2",
            received_token=b"T2",
        )
        self.assertFalse(late.accepted)
        self.assertEqual(late.reason, "response_unknown_transaction")
        self.assertEqual(state.counters.get("response_unknown_transaction"), 1)
        self.assertEqual(state.remaining_discovery_transactions(), 0)
        self.assertNotIn(key, state.discovery)

    def test_transaction_limits_are_enforced_by_single_validation_path(self):
        state = RelayState(RelayConfig(
            ("r2-in", "r2-out"), max_responses_per_transaction=1,
            max_response_digests=1,
        ))
        key = DiscoveryKey(INITIATOR, 0x1234)
        state.create_discovery(
            key, incoming_interface="r2-in", upstream_remote=None,
            upstream_token=b"T1", upstream_request_context=None,
        )
        first = state.validate_transaction_response(
            key, response(locator_suffix=20), expected_token=b"T2", received_token=b"T2")
        second = state.validate_transaction_response(
            key, response(locator_suffix=21), expected_token=b"T2", received_token=b"T2")
        self.assertTrue(first.accepted)
        self.assertFalse(second.accepted)
        self.assertEqual(second.reason, "response_limit_reached")

    def test_closed_transaction_is_terminal_and_close_is_idempotent(self):
        state = RelayState(RelayConfig(("r2-in", "r2-out")))
        key = DiscoveryKey(INITIATOR, 0x1234)
        tx = state.create_discovery(
            key, incoming_interface="r2-in", upstream_remote=None,
            upstream_token=b"T1", upstream_request_context=None,
        )
        self.assertIsNotNone(tx)
        self.assertTrue(state.close_discovery(key, reason="cancelled"))
        self.assertFalse(state.close_discovery(key, reason="again"))
        self.assertTrue(tx.closed)
        self.assertEqual(tx.close_reason, "cancelled")
        late = state.validate_transaction_response(
            key, response(), expected_token=b"T2", received_token=b"T2")
        self.assertFalse(late.accepted)
        self.assertEqual(late.reason, "response_unknown_transaction")


if __name__ == "__main__":
    unittest.main()
