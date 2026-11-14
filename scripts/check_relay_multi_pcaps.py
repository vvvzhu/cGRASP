#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate A--R--B or A--R--{B,C} relay Discovery evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

from check_relay_pcaps import COAP_CODE_CONTENT, M_DISCOVERY, M_RESPONSE, read_pcap


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-forward-delay-ms", type=float)
    parser.add_argument("--expected-responses", type=int)
    parser.add_argument("--downstream-pcap", action="append", dest="downstream_pcaps")
    args = parser.parse_args()

    downstream_pcaps = args.downstream_pcaps or ["relay-b.pcap", "relay-c.pcap"]
    expected_responses = (
        len(downstream_pcaps)
        if args.expected_responses is None else args.expected_responses
    )
    if expected_responses < 1:
        parser.error("--expected-responses must be positive")
    required = ("relay-left.pcap", *downstream_pcaps)
    paths = [args.capture_dir / name for name in required]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise SystemExit("FAIL: missing capture(s): " + ", ".join(missing))

    try:
        events = {path.name: read_pcap(path) for path in paths}
    except FileNotFoundError:
        raise SystemExit("SKIP: tshark is required for relay-multi validation")

    errors: list[str] = []
    upstream = events["relay-left.pcap"]
    requests = [event for event in upstream if event.cgrasp[0] == M_DISCOVERY]
    responses = [event for event in upstream if event.cgrasp[0] == M_RESPONSE]
    if len(requests) != 1:
        errors.append(f"expected one upstream Discovery, observed {len(requests)}")
    request = requests[0] if requests else None
    if request is not None:
        token = request.packet.token
        matching = [event for event in responses if event.packet.token == token]
        if len(matching) != expected_responses:
            errors.append(
                f"expected {expected_responses} upstream M_RESPONSE packet(s) "
                f"with token {token.hex()}, observed {len(matching)}")
        if len({event.packet.mid for event in matching}) != len(matching):
            errors.append("upstream M_RESPONSE packets do not have fresh MIDs")
        if any(event.packet.src != "fe80::102" for event in matching):
            errors.append("upstream M_RESPONSE source is not relay left endpoint fe80::102")
        if any(event.packet.code != COAP_CODE_CONTENT for event in matching):
            errors.append("upstream M_RESPONSE is not CoAP 2.05 Content")
        if len({event.packet.payload for event in matching}) != len(matching):
            errors.append("upstream M_RESPONSE payloads are not distinct")

        downstream_responses = [
            event
            for name in downstream_pcaps
            for event in events[name]
            if event.cgrasp[0] == M_RESPONSE
        ]
        forwarding_delays = []
        for upstream_event in matching:
            sources = [
                event for event in downstream_responses
                if event.packet.payload == upstream_event.packet.payload
            ]
            if len(sources) != 1:
                errors.append(
                    "could not correlate one downstream source for upstream "
                    f"MID {upstream_event.packet.mid}"
                )
                continue
            delay_ms = (
                upstream_event.packet.time_epoch - sources[0].packet.time_epoch
            ) * 1000
            forwarding_delays.append((upstream_event.packet.mid, delay_ms))
            if delay_ms < 0:
                errors.append(
                    f"upstream MID {upstream_event.packet.mid} predates its downstream response"
                )
            if (args.max_forward_delay_ms is not None and
                    delay_ms > args.max_forward_delay_ms):
                errors.append(
                    f"upstream MID {upstream_event.packet.mid} forwarding delay "
                    f"{delay_ms:.3f} ms exceeds {args.max_forward_delay_ms:.3f} ms"
                )
    else:
        forwarding_delays = []

    for name in downstream_pcaps:
        branch = events[name]
        if not any(event.cgrasp[0] == M_DISCOVERY for event in branch):
            errors.append(f"{name}: no downstream Discovery")
        if not any(event.cgrasp[0] == M_RESPONSE for event in branch):
            errors.append(f"{name}: no downstream M_RESPONSE")

    topology = "A--R--B" if len(downstream_pcaps) == 1 else "A--R--{" + ",".join(
        Path(name).stem.removeprefix("relay-").upper() for name in downstream_pcaps) + "}"
    lines = [f"cGRASP {topology} relay response report", ""]
    for name in required:
        for event in events[name]:
            if event.cgrasp[0] not in (M_DISCOVERY, M_RESPONSE):
                continue
            lines.append(
                f"{name} frame={event.packet.frame} time={event.packet.time_epoch:.6f} "
                f"src={event.packet.src} dst={event.packet.dst} "
                f"mid={event.packet.mid} token={event.token_hex} mtype={event.cgrasp[0]}"
            )
    lines.append("")
    lines.extend(
        f"forwarding-delay mid={mid} delay_ms={delay_ms:.3f}"
        for mid, delay_ms in forwarding_delays
    )
    lines.extend(["", "PASS" if not errors else "FAIL"])
    lines.extend(f"- {error}" for error in errors)
    args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if errors:
        raise SystemExit("FAIL: " + "; ".join(errors))
    print(
        f"PASS: validated {topology} relay response path with "
        f"{expected_responses} response(s): {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
