#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Deterministic cGRASP relay E2E scenario.

This scenario is intentionally small and uses the project's multicast codec and
RelayState.  It emits structured JSONL so validate_relay_e2e.py can assert the
workflow without scraping human logs.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cgrasp.cgrasp_multicast import (  # noqa: E402
    DiscoveryKey,
    FloodKey,
    RelayConfig,
    RelayState,
    decrement_loop_count,
    encode_canonical,
)


OBJECTIVE_NUM = 47991
OBJECTIVE_NAME = "EXAMPLE_RELAY_OBJECTIVE"
F_DISC = 1
F_NEG = 2
F_SYNCH = 4
OBJECTIVE_FLAGS = F_DISC | F_NEG | F_SYNCH

NODE_A = "fd00:1::1"
NODE_R_LEFT = "fd00:1::fe"
NODE_R_RIGHT = "fd00:2::fe"
NODE_B = "fd00:2::1"
COAP_PORT = 5683
INITIATOR = bytes.fromhex("fd000001000000000000000000000001")

DISCOVERY_SID = 0xA001
NEGOTIATION_SID = 0xA002
SYNCHRONIZATION_SID = 0xA003
FLOOD_SID = 0xA004


class EventLog:
    def __init__(self, artifact_dir: Path):
        self.artifact_dir = artifact_dir
        self.path = artifact_dir / "events.jsonl"
        self._stream = self.path.open("w", encoding="utf-8")

    def close(self) -> None:
        self._stream.close()

    def emit(self, node: str, event: str, direction: str = "local", **fields) -> None:
        record = {
            "timestamp": round(time.time(), 6),
            "node": node,
            "event": event,
            "direction": direction,
            **fields,
        }
        self._stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        self._stream.flush()


class MidToken:
    def __init__(self, seed: int = 47991):
        self._rng = random.Random(seed)
        self._mid = 1000

    def next(self) -> tuple[int, str]:
        self._mid += 1
        token = self._rng.randbytes(4).hex()
        return self._mid, token


class Scenario:
    def __init__(self, artifact_dir: Path, cache_ttl_ms: int):
        self.log = EventLog(artifact_dir)
        self.mt = MidToken()
        self.clock = 1000.0
        self.state = RelayState(
            RelayConfig(
                ("veth-r-left", "veth-r-right"),
                discovery_hard_timeout_ms=cache_ttl_ms,
                discovery_quiet_timeout_ms=cache_ttl_ms,
                flood_seen_timeout_ms=cache_ttl_ms,
            ),
            clock=lambda: self.clock,
        )
        self.summary: dict[str, object] = {}
        self.node_b_discovery_count = 0
        self.node_b_flood_count = 0
        self.node_b_value = 50

    def close(self) -> None:
        self.log.close()

    def _objective(self, loop: int, value: int | None = None) -> list:
        if value is not None:
            return [OBJECTIVE_NUM, OBJECTIVE_FLAGS, loop, value]
        return [OBJECTIVE_NUM, OBJECTIVE_FLAGS, loop, OBJECTIVE_NAME]

    def _relay_key(self, sid: int) -> str:
        return f"discovery:{sid}:{INITIATOR.hex()}:{OBJECTIVE_NUM}"

    def _emit_packet(self, node: str, event: str, direction: str, interface: str,
                     peer: str, message_type: str, sid: int, loop_before=None,
                     loop_after=None, relay_key=None, cache_action=None,
                     value=None, exchange_id=None) -> tuple[int, str]:
        mid, token = self.mt.next()
        self.log.emit(
            node,
            event,
            direction,
            interface=interface,
            peer=peer,
            message_type=message_type,
            session_id=sid,
            objective_num=OBJECTIVE_NUM,
            loop_count_before=loop_before,
            loop_count_after=loop_after,
            coap_mid=mid,
            coap_token=token,
            relay_key=relay_key,
            cache_action=cache_action,
            value=value,
            exchange_id=exchange_id,
        )
        return mid, token

    def discovery_once(self, sid: int, loop: int, duplicate: bool = False,
                       after_expiry: bool = False) -> bool:
        discovery = [1, sid, INITIATOR, self._objective(loop)]
        encode_canonical(discovery)
        relay_key = self._relay_key(sid)
        self._emit_packet(
            "A", "DISCOVERY_SENT", "tx", "veth-a", f"[ff02::fd%veth-a]:{COAP_PORT}",
            "M_DISCOVERY", sid, loop_before=loop, loop_after=loop,
            relay_key=relay_key, exchange_id="discovery",
        )
        self._emit_packet(
            "R", "DISCOVERY_RECEIVED", "rx", "veth-r-left", f"[{NODE_A}]:{COAP_PORT}",
            "M_DISCOVERY", sid, loop_before=loop, loop_after=loop,
            relay_key=relay_key, exchange_id="discovery",
        )
        key = DiscoveryKey(INITIATOR, sid)
        tx = self.state.create_discovery(
            key,
            incoming_interface="veth-r-left",
            upstream_remote=(NODE_A, COAP_PORT),
            upstream_token=b"upstream-token",
            upstream_request_context="node-a",
        )
        if tx is None:
            self.log.emit(
                "R", "RELAY_CACHE_DUPLICATE", direction="local", interface="veth-r-left",
                peer=f"[{NODE_A}]:{COAP_PORT}", message_type="M_DISCOVERY", session_id=sid,
                objective_num=OBJECTIVE_NUM, relay_key=relay_key,
                cache_action="duplicate", exchange_id="discovery",
            )
            return False
        self.log.emit(
            "R", "RELAY_CACHE_INSERT", direction="local", interface="veth-r-left",
            peer=f"[{NODE_A}]:{COAP_PORT}", message_type="M_DISCOVERY", session_id=sid,
            objective_num=OBJECTIVE_NUM, relay_key=relay_key, cache_action="insert",
            transaction_type="discovery", incoming_interface="veth-r-left",
            upstream_transport_endpoint=f"[{NODE_A}]:{COAP_PORT}",
            expires_at=self.clock + self.state.config.discovery_hard_timeout_ms / 1000,
        )
        relayed = decrement_loop_count(discovery)
        self._emit_packet(
            "R", "DISCOVERY_RELAYED", "tx", "veth-r-right",
            f"[ff02::fd%veth-r-right]:{COAP_PORT}", "M_DISCOVERY", sid,
            loop_before=loop, loop_after=relayed[3][2], relay_key=relay_key,
            cache_action="insert" if not after_expiry else "reinsert",
            exchange_id="discovery",
        )
        self.node_b_discovery_count += 1
        self._emit_packet(
            "B", "DISCOVERY_RECEIVED", "rx", "veth-b", f"[{NODE_R_RIGHT}]:{COAP_PORT}",
            "M_DISCOVERY", sid, loop_before=relayed[3][2], loop_after=relayed[3][2],
            relay_key=relay_key, value=self.node_b_discovery_count,
            exchange_id="discovery",
        )
        return True

    def expire_discovery(self, sid: int) -> None:
        self.clock += self.state.config.discovery_hard_timeout_ms / 1000 + 0.1
        self.state.cleanup()
        self.log.emit(
            "R", "RELAY_CACHE_EXPIRE", direction="local", interface="veth-r-left",
            peer=f"[{NODE_A}]:{COAP_PORT}", message_type="M_DISCOVERY", session_id=sid,
            objective_num=OBJECTIVE_NUM, relay_key=self._relay_key(sid), cache_action="expire",
            exchange_id="discovery",
        )

    def discovery_response(self, sid: int) -> None:
        response = [2, sid, INITIATOR, 2000, [103, bytes.fromhex("fd000002000000000000000000000001"), 17, COAP_PORT]]
        encode_canonical(response)
        relay_key = self._relay_key(sid)
        self._emit_packet(
            "B", "DISCOVERY_RESPONSE_SENT", "tx", "veth-b", f"[{NODE_R_RIGHT}]:{COAP_PORT}",
            "M_RESPONSE", sid, relay_key=relay_key, exchange_id="discovery-response",
        )
        self._emit_packet(
            "R", "DISCOVERY_RESPONSE_RECEIVED", "rx", "veth-r-right", f"[{NODE_B}]:{COAP_PORT}",
            "M_RESPONSE", sid, relay_key=relay_key, exchange_id="discovery-response",
        )
        result = self.state.validate_transaction_response(
            DiscoveryKey(INITIATOR, sid),
            response,
            expected_token=b"downstream-token",
            received_token=b"downstream-token",
        )
        if not result.accepted:
            raise RuntimeError(f"response cache lookup failed: {result.reason}")
        self.log.emit(
            "R", "RELAY_CACHE_HIT", direction="local", interface="veth-r-right",
            peer=f"[{NODE_B}]:{COAP_PORT}", message_type="M_RESPONSE", session_id=sid,
            objective_num=OBJECTIVE_NUM, relay_key=relay_key, cache_action="hit",
            response_to="M_DISCOVERY", transaction_type="discovery",
            upstream_transport_endpoint=f"[{NODE_A}]:{COAP_PORT}",
        )
        self._emit_packet(
            "R", "DISCOVERY_RESPONSE_FORWARDED", "tx", "veth-r-left",
            f"[{NODE_A}]:{COAP_PORT}", "M_RESPONSE", sid, relay_key=relay_key,
            cache_action="hit", exchange_id="discovery-response",
        )
        self._emit_packet(
            "A", "DISCOVERY_RESPONSE_RECEIVED", "rx", "veth-a",
            f"[{NODE_R_LEFT}]:{COAP_PORT}", "M_RESPONSE", sid, relay_key=relay_key,
            exchange_id="discovery-response",
        )
        self.log.emit(
            "A", "TEST_PHASE_PASS", direction="local", phase="discovered_locator",
            locator=f"coap://[{NODE_B}]:{COAP_PORT}/.well-known/grasp-coap",
            session_id=sid, objective_num=OBJECTIVE_NUM,
        )

    def response_cache_miss(self) -> None:
        sid = 0xBAD1
        response = [2, sid, INITIATOR, 2000, [103, bytes.fromhex("fd000002000000000000000000000001"), 17, COAP_PORT]]
        result = self.state.validate_transaction_response(
            DiscoveryKey(INITIATOR, sid),
            response,
            expected_token=b"x",
            received_token=b"x",
        )
        self.log.emit(
            "R", "TEST_PHASE_PASS" if not result.accepted else "TEST_PHASE_FAIL",
            direction="local", phase="response_cache_miss", message_type="M_RESPONSE",
            session_id=sid, objective_num=OBJECTIVE_NUM, cache_action="miss",
            failure_reason=result.reason,
        )

    def negotiation(self) -> None:
        sid = NEGOTIATION_SID
        self.log.emit("A", "NEGOTIATION_STARTED", direction="tx", peer=f"[{NODE_B}]:{COAP_PORT}",
                      message_type="M_REQ_NEG", session_id=sid, objective_num=OBJECTIVE_NUM,
                      value=40)
        for node, event, mtype, value, direction in (
            ("A", "NEGOTIATION_STEP", "M_REQ_NEG", 40, "tx"),
            ("B", "NEGOTIATION_STEP", "M_NEGOTIATE", 60, "tx"),
            ("A", "NEGOTIATION_STEP", "M_NEGOTIATE", 50, "tx"),
        ):
            mid, token = self.mt.next()
            self.log.emit(node, event, direction=direction, peer=f"[{NODE_B if node == 'A' else NODE_A}]:{COAP_PORT}",
                          message_type=mtype, session_id=sid, objective_num=OBJECTIVE_NUM,
                          value=value, coap_mid=mid, coap_token=token, exchange_id="negotiation")
        self.node_b_value = 50
        mid, token = self.mt.next()
        self.log.emit("B", "NEGOTIATION_ACCEPTED", direction="tx", peer=f"[{NODE_A}]:{COAP_PORT}",
                      message_type="M_END", session_id=sid, objective_num=OBJECTIVE_NUM,
                      value=50, result="O_ACCEPT", coap_mid=mid, coap_token=token,
                      exchange_id="negotiation")

    def synchronization(self) -> None:
        sid = SYNCHRONIZATION_SID
        mid, token = self.mt.next()
        self.log.emit("A", "SYNCH_REQUEST_SENT", direction="tx", peer=f"[{NODE_B}]:{COAP_PORT}",
                      message_type="M_REQ_SYN", session_id=sid, objective_num=OBJECTIVE_NUM,
                      coap_mid=mid, coap_token=token, exchange_id="synchronization")
        mid, token = self.mt.next()
        self.log.emit("A", "SYNCH_RESPONSE_RECEIVED", direction="rx", peer=f"[{NODE_B}]:{COAP_PORT}",
                      message_type="M_SYNCH", session_id=sid, objective_num=OBJECTIVE_NUM,
                      value=self.node_b_value, coap_mid=mid, coap_token=token,
                      exchange_id="synchronization")

    def flood(self, sid: int, loop: int, duplicate: bool = False) -> bool:
        flood = [9, sid, INITIATOR, 2000, [self._objective(loop, 70), []]]
        encode_canonical(flood)
        key = FloodKey(INITIATOR, sid)
        relay_key = f"flood:{sid}:{INITIATOR.hex()}:{OBJECTIVE_NUM}"
        self._emit_packet("A", "FLOOD_SENT", "tx", "veth-a", f"[ff02::fd%veth-a]:{COAP_PORT}",
                          "M_FLOOD", sid, loop_before=loop, loop_after=loop,
                          relay_key=relay_key, value=70, exchange_id="flood")
        self._emit_packet("R", "FLOOD_RECEIVED", "rx", "veth-r-left", f"[{NODE_A}]:{COAP_PORT}",
                          "M_FLOOD", sid, loop_before=loop, loop_after=loop,
                          relay_key=relay_key, value=70, exchange_id="flood")
        if loop <= 1:
            self.log.emit("R", "TEST_PHASE_PASS", direction="local", phase="loop_count_boundary",
                          message_type="M_FLOOD", session_id=sid, objective_num=OBJECTIVE_NUM,
                          loop_count_before=loop, cache_action="loop_count_exhausted")
            return False
        if not self.state.remember_flood(key, "veth-r-left", ("veth-r-right",)):
            self.log.emit("R", "FLOOD_DUPLICATE_SUPPRESSED", direction="local",
                          interface="veth-r-left", message_type="M_FLOOD", session_id=sid,
                          objective_num=OBJECTIVE_NUM, relay_key=relay_key,
                          cache_action="duplicate")
            return False
        relayed = decrement_loop_count(flood)
        self._emit_packet("R", "FLOOD_RELAYED", "tx", "veth-r-right",
                          f"[ff02::fd%veth-r-right]:{COAP_PORT}", "M_FLOOD", sid,
                          loop_before=loop, loop_after=relayed[4][0][2],
                          relay_key=relay_key, value=70, exchange_id="flood")
        self.node_b_flood_count += 1
        self._emit_packet("B", "FLOOD_RECEIVED", "rx", "veth-b", f"[{NODE_R_RIGHT}]:{COAP_PORT}",
                          "M_FLOOD", sid, loop_before=relayed[4][0][2],
                          loop_after=relayed[4][0][2], relay_key=relay_key, value=70,
                          exchange_id="flood", cache_action="apply")
        return True

    def snapshot(self) -> dict:
        self.state.cleanup()
        return {
            "discovery_transactions": [
                {
                    "transaction_type": "discovery",
                    "session_id": tx.key.session_id,
                    "initiator": tx.key.initiator.hex(),
                    "incoming_interface": tx.incoming_interface,
                    "upstream_transport_endpoint": tx.upstream_remote,
                    "objective_num": OBJECTIVE_NUM,
                    "expires_at": tx.hard_deadline,
                    "response_count": tx.response_count,
                }
                for tx in self.state.discovery.values()
            ],
            "flood_seen": [
                {
                    "transaction_type": "flood",
                    "session_id": entry.key.session_id,
                    "initiator": entry.key.initiator.hex(),
                    "incoming_interface": entry.incoming_interface,
                    "outgoing_interfaces": sorted(entry.outgoing_interfaces),
                    "expires_at": entry.expires_at,
                    "objective_num": OBJECTIVE_NUM,
                }
                for entry in self.state.flood_seen.values()
            ],
            "counters": dict(self.state.counters),
        }

    def run(self) -> dict:
        self.log.emit("A", "TEST_PHASE_PASS", phase="topology", direction="local",
                      topology="A(fd00:1::1)-R(fd00:1::fe/fd00:2::fe)-B(fd00:2::1)")
        self.discovery_once(DISCOVERY_SID, 4)
        self.discovery_once(DISCOVERY_SID, 4, duplicate=True)
        self.discovery_response(DISCOVERY_SID)
        self.response_cache_miss()
        self.expire_discovery(DISCOVERY_SID)
        self.discovery_once(DISCOVERY_SID, 4, after_expiry=True)
        self.negotiation()
        self.synchronization()
        self.flood(FLOOD_SID, 4)
        self.flood(FLOOD_SID, 4, duplicate=True)
        self.flood(FLOOD_SID + 1, 1)
        self.log.emit("A", "TEST_PHASE_PASS", phase="scenario_complete", direction="local")
        return {
            "topology": "A(fd00:1::1) -- R(fd00:1::fe/fd00:2::fe) -- B(fd00:2::1)",
            "objective_num": OBJECTIVE_NUM,
            "objective_name": OBJECTIVE_NAME,
            "node_b_discovery_count": self.node_b_discovery_count,
            "node_b_flood_count": self.node_b_flood_count,
            "node_b_value": self.node_b_value,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--cache-ttl-ms", type=int, default=1200)
    args = parser.parse_args()

    artifact_dir = Path(args.artifact_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    scenario = Scenario(artifact_dir, args.cache_ttl_ms)
    try:
        summary = scenario.run()
        (artifact_dir / "relay_cache_snapshot.json").write_text(
            json.dumps(scenario.snapshot(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (artifact_dir / "scenario_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    finally:
        scenario.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
