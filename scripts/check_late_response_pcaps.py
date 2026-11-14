#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate that a response arriving after relay expiry is not forwarded."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from check_relay_pcaps import M_DISCOVERY, M_RESPONSE, read_pcap


def last_event(path: Path, event: str) -> dict:
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("event") == event:
            result = item
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--relay-log", type=Path, required=True)
    parser.add_argument("--initiator-log", type=Path, required=True)
    parser.add_argument("--min-late-delay-ms", type=float, required=True)
    parser.add_argument("--expected-relay-hard-timeout-ms", type=int, required=True)
    parser.add_argument("--expected-relay-quiet-timeout-ms", type=int, required=True)
    args = parser.parse_args()

    paths = {
        "upstream": args.capture_dir / "relay-left.pcap",
        "downstream": args.capture_dir / "relay-b.pcap",
    }
    missing = [str(path) for path in (*paths.values(), args.relay_log, args.initiator_log)
               if not path.is_file()]
    if missing:
        raise SystemExit("FAIL: missing evidence: " + ", ".join(missing))
    try:
        events = {name: read_pcap(path) for name, path in paths.items()}
    except FileNotFoundError:
        raise SystemExit("SKIP: tshark is required for late-response validation")

    errors: list[str] = []
    upstream_requests = [e for e in events["upstream"] if e.cgrasp[0] == M_DISCOVERY]
    upstream_responses = [e for e in events["upstream"] if e.cgrasp[0] == M_RESPONSE]
    downstream_requests = [e for e in events["downstream"] if e.cgrasp[0] == M_DISCOVERY]
    downstream_responses = [e for e in events["downstream"] if e.cgrasp[0] == M_RESPONSE]
    if len(upstream_requests) != 1:
        errors.append(f"expected one upstream Discovery, observed {len(upstream_requests)}")
    if upstream_responses:
        errors.append(f"late response was forwarded upstream {len(upstream_responses)} time(s)")
    if len(downstream_requests) != 1:
        errors.append(f"expected one downstream Discovery, observed {len(downstream_requests)}")
    if not downstream_responses:
        errors.append("no delayed downstream M_RESPONSE observed")

    delay_ms = None
    if downstream_requests and downstream_responses:
        delay_ms = (
            downstream_responses[0].packet.time_epoch -
            downstream_requests[0].packet.time_epoch
        ) * 1000
        if delay_ms < args.min_late_delay_ms:
            errors.append(
                f"downstream response delay {delay_ms:.3f} ms is below "
                f"{args.min_late_delay_ms:.3f} ms")
        if (upstream_requests and
                downstream_responses[0].session_id != upstream_requests[0].session_id):
            errors.append("late response session does not match upstream Discovery")

    relay_ready = last_event(args.relay_log, "ready")
    relay = last_event(args.relay_log, "result")
    initiator = last_event(args.initiator_log, "result")
    counters = relay.get("counters") or {}
    quiescence = relay.get("quiescence") or {}
    relay_audit = relay.get("audit") or {}
    initiator_audit = initiator.get("audit") or {}
    if relay.get("ok") is not True:
        errors.append("relay result is not ok")
    if relay_ready.get("relay_hard_timeout_ms") != args.expected_relay_hard_timeout_ms:
        errors.append(
            f"relay hard timeout={relay_ready.get('relay_hard_timeout_ms')}, expected "
            f"{args.expected_relay_hard_timeout_ms}")
    if relay_ready.get("relay_quiet_timeout_ms") != args.expected_relay_quiet_timeout_ms:
        errors.append(
            f"relay quiet timeout={relay_ready.get('relay_quiet_timeout_ms')}, expected "
            f"{args.expected_relay_quiet_timeout_ms}")
    if relay.get("remaining_transactions") != 0:
        errors.append(
            f"relay remaining_transactions={relay.get('remaining_transactions')}, expected 0")
    if counters.get("accepted", 0) != 0:
        errors.append(f"relay accepted={counters.get('accepted')}, expected 0")
    if counters.get("response_forwarded", 0) != 0:
        errors.append(
            f"relay response_forwarded={counters.get('response_forwarded')}, expected 0")
    for field in ("active_discovery_transactions", "active_downstream_branches", "response_digests"):
        if quiescence.get(field) != 0:
            errors.append(f"relay {field}={quiescence.get(field)}, expected 0")
    if initiator.get("ok") is not True or initiator.get("locators") != 0:
        errors.append(
            f"initiator result ok={initiator.get('ok')} locators={initiator.get('locators')}, "
            "expected true/0")
    for name, audit in (("relay", relay_audit), ("initiator", initiator_audit)):
        if audit.get("errors"):
            errors.append(f"{name} audit errors={audit.get('errors')}")
        for counter in ("fallback_count", "legacy_udp_messages", "tcp_connections"):
            if audit.get(counter, 0) != 0:
                errors.append(f"{name} {counter}={audit.get(counter)}, expected 0")

    lines = ["cGRASP E2E-06 late-response report", ""]
    lines.append(f"downstream_response_delay_ms={delay_ms:.3f}" if delay_ms is not None
                 else "downstream_response_delay_ms=missing")
    lines.append(f"upstream_responses={len(upstream_responses)}")
    lines.append(f"relay_counters={json.dumps(counters, sort_keys=True)}")
    lines.append(f"relay_ready={json.dumps(relay_ready, sort_keys=True)}")
    lines.append(f"relay_quiescence={json.dumps(quiescence, sort_keys=True)}")
    lines.append(f"relay_audit={json.dumps(relay_audit, sort_keys=True)}")
    lines.append(f"initiator_result={json.dumps(initiator, sort_keys=True)}")
    lines.extend(["", "PASS" if not errors else "FAIL"])
    lines.extend(f"- {error}" for error in errors)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if errors:
        raise SystemExit("FAIL: " + "; ".join(errors))
    print(f"PASS: late response was not forwarded or retained: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
