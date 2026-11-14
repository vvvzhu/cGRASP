#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Summarize multicast test-plan coverage with explicit evidence classes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PASS_CURRENT_E2E = "PASS_CURRENT_E2E"
PASS_UNIT = "PASS_UNIT"
PASS_REUSED_EVIDENCE = "PASS_REUSED_EVIDENCE"
PARTIAL = "PARTIAL"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
MISSING = "MISSING"


def run(command: list[str]) -> tuple[bool, str]:
    proc = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode == 0, proc.stdout.strip()


def exists(path: str) -> bool:
    return (ROOT / path).exists()


def last_line(text: str) -> list[str]:
    return text.splitlines()[-1:] if text else []


def case(name: str, status: str, *, unit=None, current_pcap=None, reused_pcap=None,
         namespace_run=None, missing=None, artifact=None) -> dict:
    return {
        "name": name,
        "status": status,
        "evidence": {
            "unit": unit or [],
            "current_pcap": current_pcap or [],
            "reused_pcap": reused_pcap or [],
            "namespace_run": namespace_run or [],
        },
        "missing": missing or [],
        "artifact": artifact,
    }


def main() -> int:
    python = sys.executable
    results: dict[str, dict] = {}

    ok_relay, out_relay = run([python, "scripts/check_relay_pcaps.py", "captures/multicast-relay"])
    ok_loss, out_loss = run([python, "scripts/check_relay_pcaps.py", "captures/multicast-loss"])
    ok_loop, out_loop = run([python, "scripts/check_relay_pcaps.py", "captures/multicast-loop"])
    ok_multi, out_multi = run([
        python, "scripts/check_relay_pcaps.py", "captures/multicast-multi",
        "--min-hops", "3", "--min-loop-decrements", "0",
    ])
    ok_divert, out_divert = run([
        python, "scripts/check_relay_pcaps.py", "captures/multicast-divert",
        "--require-divert",
    ])
    ok_flood_relay, out_flood_relay = run([
        python, "scripts/check_flood_pcaps.py", "captures/multicast-flood-relay",
    ])
    ok_flood_loop, out_flood_loop = run([
        python, "scripts/check_flood_pcaps.py", "captures/multicast-flood-loop",
    ])
    ok_unit, _out_unit = run([python, "-m", "unittest", "-v", "tests.test_multicast_plan_cases"])
    ok_retx_a, out_retx_a = run([
        python, "scripts/check_response_retransmit_pcaps.py",
        "captures/multicast-response-retransmit-drop-response", "--mode", "drop-response",
    ]) if exists("captures/multicast-response-retransmit-drop-response") else (False, "")
    ok_retx_b, out_retx_b = run([
        python, "scripts/check_response_retransmit_pcaps.py",
        "captures/multicast-response-retransmit-drop-ack", "--mode", "drop-ack",
    ]) if exists("captures/multicast-response-retransmit-drop-ack") else (False, "")

    results["TC-MH-01"] = case(
        "basic two-relay Discovery and reverse M_RESPONSE",
        PASS_REUSED_EVIDENCE if ok_relay else MISSING,
        reused_pcap=last_line(out_relay),
        missing=["P0 current namespace rerun metadata"] if ok_relay else ["relay pcap validation"],
        artifact="captures/multicast-relay/relay-report.txt" if exists("captures/multicast-relay/relay-report.txt") else None,
    )
    results["TC-MH-02"] = case(
        "loop-count boundary",
        PASS_UNIT if ok_unit else MISSING,
        unit=["tests.test_multicast_plan_cases.test_tc_mh_02_loop_count_boundaries"] if ok_unit else [],
    )
    results["TC-MH-03"] = case(
        "multiple responders",
        PASS_REUSED_EVIDENCE if ok_multi else MISSING,
        reused_pcap=last_line(out_multi),
        missing=["P0 current namespace rerun metadata"] if ok_multi else ["multi pcap validation"],
        artifact="captures/multicast-multi/relay-report.txt" if exists("captures/multicast-multi/relay-report.txt") else None,
    )
    results["TC-MH-04"] = case(
        "duplicate Discovery suppression",
        PASS_REUSED_EVIDENCE if ok_unit and ok_loop else MISSING,
        unit=["tests.test_multicast_plan_cases.test_tc_mh_04_duplicate_discovery_preserves_first_transaction"] if ok_unit else [],
        reused_pcap=last_line(out_loop),
        missing=["current namespace rerun"] if ok_unit and ok_loop else ["unit or loop pcap evidence"],
    )
    results["TC-MH-05"] = case(
        "response retransmission / semantic dedup",
        PASS_CURRENT_E2E if ok_retx_b and ok_unit else PARTIAL,
        unit=["tests.test_multicast_plan_cases.test_tc_mh_05_response_semantic_deduplication"] if ok_unit else [],
        current_pcap=last_line(out_retx_b) if ok_retx_b else [],
        missing=[] if ok_retx_b else [
            "deterministic ACK-loss namespace run",
            "CoAP retransmission pcap with same MID/token",
            "runtime proof response_forwarded == 1",
        ],
    )
    results["TC-MH-06"] = case(
        "wrong Token rejected",
        PASS_UNIT if ok_unit else MISSING,
        unit=["tests.test_multicast_plan_cases.test_tc_mh_06_wrong_token_rejected"] if ok_unit else [],
    )
    results["TC-MH-07"] = case(
        "wrong session-id or initiator rejected",
        PASS_UNIT if ok_unit else MISSING,
        unit=["tests.test_multicast_plan_cases.test_tc_mh_07_wrong_session_or_initiator_rejected"] if ok_unit else [],
    )
    results["TC-MH-08"] = case(
        "transaction timeout and late response",
        PASS_UNIT if ok_unit else MISSING,
        unit=["tests.test_multicast_plan_cases.test_tc_mh_08_hard_timeout_cleans_transaction"] if ok_unit else [],
        missing=["namespace proof that late response sends no upstream packet"],
    )
    results["TC-MH-09"] = case(
        "response path loss and CoAP retransmission",
        PASS_CURRENT_E2E if ok_retx_a else PARTIAL,
        current_pcap=last_line(out_retx_a) if ok_retx_a else [],
        reused_pcap=last_line(out_loss) if ok_loss else [],
        missing=[] if ok_retx_a else [
            "deterministic first-M_RESPONSE-drop namespace run",
            "proof first response absent at relay",
            "proof retransmitted response same MID/token arrives",
        ],
    )
    results["TC-MH-10"] = case(
        "intermediate relay loses state",
        PASS_UNIT if ok_unit else NOT_IMPLEMENTED,
        unit=[
            "tests.test_multicast_plan_cases.test_tc_mh_10_cleared_transaction_rejects_late_response_without_recreate"
        ] if ok_unit else [],
        missing=["relay-state-loss namespace pcap and runtime counters"],
    )
    results["TC-MH-11"] = case(
        "responder cache / O_DIVERT",
        PASS_REUSED_EVIDENCE if ok_divert else MISSING,
        reused_pcap=last_line(out_divert),
        missing=["P0 current namespace rerun metadata"] if ok_divert else ["divert pcap validation"],
        artifact="captures/multicast-divert/relay-report.txt" if exists("captures/multicast-divert/relay-report.txt") else None,
    )
    results["TC-MH-12"] = case(
        "branch topology multiple reverse responses",
        PARTIAL if ok_loop else NOT_IMPLEMENTED,
        reused_pcap=last_line(out_loop),
        missing=[
            "dedicated branch-multi-response topology",
            "R1 downstream exchange count == 2",
            "Initiator receives two distinct locators",
        ],
    )
    results["Flood relay"] = case(
        "additional Flood relay / loop validation",
        PASS_REUSED_EVIDENCE if ok_flood_relay and ok_flood_loop else MISSING,
        reused_pcap=last_line(out_flood_relay) + last_line(out_flood_loop),
        missing=["P0 current namespace rerun metadata"] if ok_flood_relay and ok_flood_loop else ["flood pcap validation"],
    )

    print(json.dumps(results, indent=2, sort_keys=True))
    allowed = {PASS_CURRENT_E2E, PASS_UNIT, PASS_REUSED_EVIDENCE, PARTIAL, NOT_IMPLEMENTED}
    return 0 if all(item["status"] in allowed for item in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
