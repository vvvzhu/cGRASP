#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Generate Mermaid topology and sequence diagrams for relay E2E artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DISPLAY_NODE = {
    "A": "Node A",
    "R": "Relay R",
    "B": "Node B",
    "C": "Node C",
    "D": "Node D",
}


EDGE_EVENTS = {
    "DISCOVERY_SENT",
    "DISCOVERY_RELAYED",
    "DISCOVERY_RESPONSE_SENT",
    "DISCOVERY_RESPONSE_FORWARDED",
    "NEGOTIATION_STARTED",
    "NEGOTIATION_STEP",
    "NEGOTIATION_ACCEPTED",
    "SYNCH_REQUEST_SENT",
    "SYNCH_RESPONSE_RECEIVED",
    "FLOOD_SENT",
    "FLOOD_RELAYED",
}


LOCAL_EVENTS = {
    "RELAY_CACHE_INSERT",
    "RELAY_CACHE_DUPLICATE",
    "RELAY_CACHE_EXPIRE",
    "RELAY_CACHE_HIT",
    "FLOOD_DUPLICATE_SUPPRESSED",
    "TEST_PHASE_PASS",
    "TEST_PHASE_FAIL",
}


def load_events(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                events.append(json.loads(line))
    return sorted(events, key=lambda item: item.get("timestamp", 0))


def topology_mermaid() -> str:
    return """flowchart LR
  A["Node A / Gray<br/>fd00:1::1<br/>veth-a"]
  R["Relay R<br/>fd00:1::fe / fd00:2::fe / fd00:3::fe / fd00:4::fe<br/>veth-r-left / veth-r-right / veth-r-c / veth-r-d"]
  B["Node B / Briggs<br/>fd00:2::1<br/>veth-b"]
  C["Node C<br/>fd00:3::1<br/>veth-c<br/>post-cache discovery"]
  D["Node D<br/>fd00:4::1<br/>veth-d<br/>loop-count boundary"]

  A <-->|"Link 1<br/>Discovery/Flood relay<br/>Unicast routed workflow"| R
  R <-->|"Link 2<br/>Objective responder"| B
  R <-->|"Link 3<br/>Node C discovers after relay cache"| C
  R <-->|"Link 4<br/>Node D low loop-count tests"| D
"""


def _target_for_event(event: dict) -> str:
    name = event.get("event")
    node = event.get("node")
    peer = str(event.get("peer") or "")
    direction = event.get("direction")

    if name in {"DISCOVERY_SENT", "FLOOD_SENT"}:
        return "R"
    if name in {"DISCOVERY_RELAYED", "FLOOD_RELAYED"}:
        return "B"
    if name == "DISCOVERY_RESPONSE_SENT":
        return "R"
    if name == "DISCOVERY_RESPONSE_FORWARDED":
        return "A"
    if name == "SYNCH_REQUEST_SENT":
        return "B"
    if name == "SYNCH_RESPONSE_RECEIVED":
        return "A"
    if name == "NEGOTIATION_STARTED":
        return "B"
    if name == "NEGOTIATION_ACCEPTED":
        return "A"
    if name == "NEGOTIATION_STEP":
        if node == "A":
            return "B"
        if node == "B":
            return "A"
    if direction == "rx":
        if "fd00:1::" in peer:
            return "A"
        if "fd00:2::" in peer:
            return "B"
    return node or "R"


def _label(event: dict) -> str:
    parts = [str(event.get("event"))]
    mtype = event.get("message_type")
    if mtype:
        parts.append(str(mtype))
    sid = event.get("session_id")
    if sid is not None:
        parts.append(f"sid={sid}")
    value = event.get("value")
    if value is not None:
        parts.append(f"value={value}")
    before = event.get("loop_count_before")
    after = event.get("loop_count_after")
    if before is not None and after is not None and before != after:
        parts.append(f"loop {before}->{after}")
    mid = event.get("coap_mid")
    token = event.get("coap_token")
    if mid is not None:
        parts.append(f"mid={mid}")
    if token:
        parts.append(f"tok={token}")
    action = event.get("cache_action")
    if action:
        parts.append(f"cache={action}")
    phase = event.get("phase")
    if phase:
        parts.append(f"phase={phase}")
    return "<br/>".join(parts).replace(":", "#58;")


def sequence_mermaid(events: list[dict]) -> str:
    lines = [
        "sequenceDiagram",
        "  participant A as Node A",
        "  participant R as Relay R",
        "  participant B as Node B",
        "  participant C as Node C",
        "  participant D as Node D",
        "",
    ]

    for event in events:
        name = event.get("event")
        node = event.get("node")
        if node not in DISPLAY_NODE:
            continue
        label = _label(event)
        if name in EDGE_EVENTS:
            target = _target_for_event(event)
            if target == node:
                lines.append(f"  Note over {node}: {label}")
            else:
                lines.append(f"  {node}->>{target}: {label}")
        elif name in LOCAL_EVENTS:
            lines.append(f"  Note over {node}: {label}")
    return "\n".join(lines) + "\n"


def timeline_markdown(events: list[dict]) -> str:
    lines = ["# cGRASP Relay E2E Timeline", "", "| # | Node | Event | Message | SID | Details |", "|---:|---|---|---|---:|---|"]
    for index, event in enumerate(events, 1):
        details = []
        for key in ("direction", "interface", "peer", "cache_action", "phase", "value"):
            value = event.get(key)
            if value is not None:
                details.append(f"{key}={value}")
        before = event.get("loop_count_before")
        after = event.get("loop_count_after")
        if before is not None or after is not None:
            details.append(f"loop={before}->{after}")
        if event.get("coap_mid") is not None:
            details.append(f"mid={event.get('coap_mid')}")
        if event.get("coap_token"):
            details.append(f"token={event.get('coap_token')}")
        lines.append(
            f"| {index} | {event.get('node', '')} | {event.get('event', '')} | "
            f"{event.get('message_type', '') or ''} | {event.get('session_id', '') or ''} | "
            f"{'<br/>'.join(details)} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("events_jsonl", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    events_path = args.events_jsonl.resolve()
    output_dir = (args.output_dir or events_path.parent).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    events = load_events(events_path)

    (output_dir / "topology.mmd").write_text(topology_mermaid(), encoding="utf-8")
    (output_dir / "sequence.mmd").write_text(sequence_mermaid(events), encoding="utf-8")
    (output_dir / "timeline.md").write_text(timeline_markdown(events), encoding="utf-8")
    print(f"Wrote {output_dir / 'topology.mmd'}")
    print(f"Wrote {output_dir / 'sequence.mmd'}")
    print(f"Wrote {output_dir / 'timeline.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
