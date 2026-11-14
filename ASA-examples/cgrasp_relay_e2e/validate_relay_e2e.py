#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate the cGRASP relay E2E JSONL trace."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PHASES = [
    "topology",
    "discovery_first_hop",
    "discovery_relay",
    "relay_cache_insert",
    "relay_cache_duplicate_suppression",
    "relay_cache_expiry",
    "response_cache_hit",
    "response_hop_by_hop_return",
    "discovered_locator",
    "negotiation",
    "synchronization",
    "flood_relay",
    "flood_duplicate_suppression",
    "loop_count_boundary",
    "session_token_mid_semantics",
]


class Failure(Exception):
    pass


def load_events(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise Failure(f"{path}:{line_no}: invalid JSON: {exc}") from exc
    if not events:
        raise Failure(f"{path}: no events")
    return events


def select(events: list[dict], name: str) -> list[dict]:
    return [event for event in events if event.get("event") == name]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def first(events: list[dict], name: str) -> dict:
    found = select(events, name)
    require(bool(found), f"missing event {name}")
    return found[0]


def token_mid_pairs(events: list[dict], exchange_id: str) -> list[tuple[int, str]]:
    pairs = []
    for event in events:
        if event.get("exchange_id") == exchange_id and event.get("coap_mid") is not None:
            pairs.append((int(event["coap_mid"]), str(event.get("coap_token", ""))))
    return pairs


def validate(events: list[dict]) -> dict[str, str]:
    results = {phase: "FAIL" for phase in PHASES}

    require(any(e.get("phase") == "topology" for e in select(events, "TEST_PHASE_PASS")),
            "topology phase did not pass")
    results["topology"] = "PASS"

    sent = first(events, "DISCOVERY_SENT")
    recv_r = first(events, "DISCOVERY_RECEIVED")
    require(sent["node"] == "A" and sent["interface"] == "veth-a", "Node A did not send on Link 1")
    require(recv_r["node"] == "R" and recv_r["interface"] == "veth-r-left", "Relay did not receive on Link 1")
    results["discovery_first_hop"] = "PASS"

    relayed = first(events, "DISCOVERY_RELAYED")
    recv_b = [e for e in select(events, "DISCOVERY_RECEIVED") if e.get("node") == "B"]
    require(relayed["interface"] == "veth-r-right", "Discovery was not relayed on Link 2")
    require(relayed["loop_count_before"] == 4 and relayed["loop_count_after"] == 3,
            "Discovery loop-count was not decremented 4 -> 3")
    require(len(recv_b) == 2, f"expected B to process first and post-expiry Discovery only, got {len(recv_b)}")
    results["discovery_relay"] = "PASS"

    insert = first(events, "RELAY_CACHE_INSERT")
    require(insert["cache_action"] == "insert" and insert["transaction_type"] == "discovery",
            "relay cache insert is missing normalized transaction metadata")
    results["relay_cache_insert"] = "PASS"

    dup = first(events, "RELAY_CACHE_DUPLICATE")
    require(dup["cache_action"] == "duplicate", "duplicate Discovery was not suppressed")
    require(len(select(events, "DISCOVERY_RELAYED")) == 2,
            "duplicate or post-expiry Discovery forwarding count is wrong")
    results["relay_cache_duplicate_suppression"] = "PASS"

    expire = first(events, "RELAY_CACHE_EXPIRE")
    require(expire["cache_action"] == "expire", "relay cache expiry was not observed")
    results["relay_cache_expiry"] = "PASS"

    hit = first(events, "RELAY_CACHE_HIT")
    require(hit["message_type"] == "M_RESPONSE" and hit["response_to"] == "M_DISCOVERY",
            "M_RESPONSE did not hit the Discovery transaction")
    results["response_cache_hit"] = "PASS"

    b_sent = first(events, "DISCOVERY_RESPONSE_SENT")
    r_fwd = first(events, "DISCOVERY_RESPONSE_FORWARDED")
    a_recv = [e for e in select(events, "DISCOVERY_RESPONSE_RECEIVED") if e.get("node") == "A"]
    require(b_sent["peer"].startswith("[fd00:2::fe]"), "B did not send M_RESPONSE to Relay R")
    require(r_fwd["peer"].startswith("[fd00:1::1]"), "R did not forward M_RESPONSE upstream to A")
    require(bool(a_recv), "A did not receive Discovery response")
    results["response_hop_by_hop_return"] = "PASS"

    require(any(e.get("phase") == "discovered_locator" and "fd00:2::1" in e.get("locator", "")
                for e in select(events, "TEST_PHASE_PASS")),
            "A did not record Node B locator")
    results["discovered_locator"] = "PASS"

    neg_values = [e.get("value") for e in select(events, "NEGOTIATION_STEP")]
    accepted = first(events, "NEGOTIATION_ACCEPTED")
    require(neg_values == [40, 60, 50] and accepted.get("value") == 50,
            f"unexpected negotiation sequence: {neg_values}, accepted={accepted.get('value')}")
    require(first(events, "NEGOTIATION_STARTED")["session_id"] != sent["session_id"],
            "negotiation reused discovery SID")
    results["negotiation"] = "PASS"

    synch = first(events, "SYNCH_RESPONSE_RECEIVED")
    require(synch["value"] == 50 and synch["message_type"] == "M_SYNCH",
            "synchronization did not return value 50")
    require(synch["session_id"] not in (sent["session_id"], accepted["session_id"]),
            "synchronization SID was reused")
    results["synchronization"] = "PASS"

    flood_relay = first(events, "FLOOD_RELAYED")
    flood_b = [e for e in select(events, "FLOOD_RECEIVED") if e.get("node") == "B"]
    require(flood_relay["loop_count_before"] == 4 and flood_relay["loop_count_after"] == 3,
            "Flood loop-count was not decremented 4 -> 3")
    require(len(flood_b) == 1 and flood_b[0].get("value") == 70, "Node B did not apply Flood exactly once")
    results["flood_relay"] = "PASS"

    flood_dup = first(events, "FLOOD_DUPLICATE_SUPPRESSED")
    require(flood_dup["cache_action"] == "duplicate", "duplicate Flood was not suppressed")
    results["flood_duplicate_suppression"] = "PASS"

    require(any(e.get("phase") == "loop_count_boundary" and e.get("cache_action") == "loop_count_exhausted"
                for e in select(events, "TEST_PHASE_PASS")),
            "loop-count boundary event missing")
    results["loop_count_boundary"] = "PASS"

    discovery_pairs = token_mid_pairs(events, "discovery")
    response_pairs = token_mid_pairs(events, "discovery-response")
    negotiation_pairs = token_mid_pairs(events, "negotiation")
    require(len(discovery_pairs) >= 4 and len(set(discovery_pairs)) == len(discovery_pairs),
            "Discovery hop CoAP MID/Token pairs were not fresh")
    require(len(response_pairs) >= 4 and len(set(response_pairs)) == len(response_pairs),
            "Response hop CoAP MID/Token pairs were not fresh")
    require(len(negotiation_pairs) >= 4 and len(set(negotiation_pairs)) == len(negotiation_pairs),
            "Negotiation CoAP MID/Token pairs were not fresh")
    session_ids = {
        "discovery": first(events, "DISCOVERY_SENT")["session_id"],
        "negotiation": first(events, "NEGOTIATION_STARTED")["session_id"],
        "synchronization": first(events, "SYNCH_REQUEST_SENT")["session_id"],
        "flood": first(events, "FLOOD_SENT")["session_id"],
    }
    require(len(set(session_ids.values())) == 4, f"expected distinct workflow SIDs, got {session_ids}")
    results["session_token_mid_semantics"] = "PASS"

    results["overall"] = "PASS"
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_dir")
    args = parser.parse_args()
    artifact_dir = Path(args.artifact_dir).resolve()
    events_path = artifact_dir / "events.jsonl"
    try:
        results = validate(load_events(events_path))
    except Failure as exc:
        results = {phase: "FAIL" for phase in PHASES}
        results["overall"] = "FAIL"
        results["failure"] = str(exc)
        results["events"] = str(events_path)
        print(json.dumps(results, indent=2, sort_keys=True))
        return 1
    (artifact_dir / "summary.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n",
                                               encoding="utf-8")
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
