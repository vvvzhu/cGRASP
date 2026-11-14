#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate E2E-07 peer isolation for two clients sharing one session ID."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from render_namespace_interactions import _loads_cgrasp, _parse_options_and_payload


M_REQ_NEG = 3
M_NEGOTIATE = 5
M_END = 6


def read_events(path: Path) -> list[dict]:
    proc = subprocess.run(
        [
            "tshark", "-r", str(path), "-Y", "udp && ipv6",
            "-T", "fields", "-E", "separator=|",
            "-e", "frame.number", "-e", "ipv6.src", "-e", "ipv6.dst",
            "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or f"tshark failed for {path}")
    events = []
    for line in proc.stdout.splitlines():
        fields = line.split("|", 5)
        if len(fields) != 6 or not fields[5]:
            continue
        try:
            _type, code, mid, token, _options, payload = _parse_options_and_payload(
                bytes.fromhex(fields[5].replace(":", "")))
            message = _loads_cgrasp(payload)
        except Exception:
            continue
        if not isinstance(message, list) or len(message) < 2:
            continue
        events.append({
            "frame": fields[0], "src": fields[1].lower(), "dst": fields[2].lower(),
            "sport": fields[3], "dport": fields[4], "code": code, "mid": mid,
            "token": token.hex(), "message": message,
        })
    return events


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


def objective_value(message: list) -> object:
    if message and message[0] in (M_REQ_NEG, M_NEGOTIATE) and len(message) > 2:
        objective = message[2]
        if isinstance(objective, list) and len(objective) > 3:
            return objective[3]
    return None


def clean_audit(name: str, audit: dict, errors: list[str]) -> None:
    if audit.get("errors"):
        errors.append(f"{name} audit errors={audit.get('errors')}")
    for field in ("fallback_count", "legacy_udp_messages", "tcp_connections"):
        if audit.get(field, 0) != 0:
            errors.append(f"{name} {field}={audit.get(field)}, expected 0")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--client-a-log", type=Path, required=True)
    parser.add_argument("--client-b-log", type=Path, required=True)
    parser.add_argument("--session-id", type=int, required=True)
    args = parser.parse_args()

    pcap_paths = {
        "alpha": args.capture_dir / "server-alpha.pcap",
        "bravo": args.capture_dir / "server-bravo.pcap",
    }
    required = [*pcap_paths.values(), args.server_log, args.client_a_log, args.client_b_log]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("FAIL: missing evidence: " + ", ".join(missing))
    try:
        pcaps = {name: read_events(path) for name, path in pcap_paths.items()}
    except FileNotFoundError:
        raise SystemExit("SKIP: tshark is required for session-collision validation")

    errors: list[str] = []
    for name, events in pcaps.items():
        messages = [event["message"] for event in events]
        sids = {message[1] for message in messages if len(message) > 1}
        types = [message[0] for message in messages]
        values = [objective_value(message) for message in messages]
        expected_values = {name, f"reply:{name}", f"final:{name}"}
        if sids != {args.session_id}:
            errors.append(f"{name} link session IDs={sorted(sids)}, expected {args.session_id}")
        for required_type in (M_REQ_NEG, M_NEGOTIATE, M_END):
            if required_type not in types:
                errors.append(f"{name} link lacks cGRASP message type {required_type}")
        if not expected_values.issubset(set(values)):
            errors.append(f"{name} link objective values={values}, expected {sorted(expected_values)}")
        foreign = {"alpha", "reply:alpha", "final:alpha", "bravo", "reply:bravo", "final:bravo"}
        foreign -= expected_values
        if foreign.intersection(values):
            errors.append(f"{name} link contains other peer's values: {values}")

    server = last_event(args.server_log, "result")
    clients = {
        "alpha": last_event(args.client_a_log, "result"),
        "bravo": last_event(args.client_b_log, "result"),
    }
    bridge = server.get("bridge") or {}
    counters = bridge.get("counters") or {}
    if server.get("ok") is not True:
        errors.append("server result is not ok")
    if server.get("workers_alive") != 0:
        errors.append(f"server workers_alive={server.get('workers_alive')}, expected 0")
    if bridge.get("active_sessions") != 0 or bridge.get("active_exchanges") != 0:
        errors.append(
            f"bridge active state sessions={bridge.get('active_sessions')} "
            f"exchanges={bridge.get('active_exchanges')}, expected 0/0")
    for field, expected in (("sessions_created", 2), ("sessions_closed", 2),
                            ("exchanges_created", 4), ("exchanges_closed", 4)):
        if counters.get(field) != expected:
            errors.append(f"bridge {field}={counters.get(field)}, expected {expected}")
    sessions = server.get("sessions") or []
    if len(sessions) != 2 or {item.get("session_id") for item in sessions} != {args.session_id}:
        errors.append(f"server sessions do not prove one shared SID: {sessions}")
    if len({item.get("peer") for item in sessions}) != 2:
        errors.append(f"server did not observe two distinct peers: {sessions}")

    for name, result in clients.items():
        if (result.get("ok") is not True or result.get("session_id") != args.session_id or
                result.get("sent") != name or result.get("received") != f"reply:{name}"):
            errors.append(f"{name} client result mismatch: {result}")
        clean_audit(name, result.get("audit") or {}, errors)
    clean_audit("server", server.get("audit") or {}, errors)

    lines = ["cGRASP E2E-07 session-ID collision report", ""]
    lines.append(f"session_id={args.session_id}")
    lines.append(f"alpha_frames={len(pcaps['alpha'])}")
    lines.append(f"bravo_frames={len(pcaps['bravo'])}")
    lines.append(f"server_sessions={json.dumps(sessions, sort_keys=True)}")
    lines.append(f"bridge={json.dumps(bridge, sort_keys=True)}")
    lines.append(f"alpha_result={json.dumps(clients['alpha'], sort_keys=True)}")
    lines.append(f"bravo_result={json.dumps(clients['bravo'], sort_keys=True)}")
    lines.extend(["", "PASS" if not errors else "FAIL"])
    lines.extend(f"- {error}" for error in errors)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if errors:
        raise SystemExit("FAIL: " + "; ".join(errors))
    print(f"PASS: same session ID remained isolated by peer: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
