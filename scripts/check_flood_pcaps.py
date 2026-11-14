#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate cGRASP Flood multicast pcaps.

The Discovery relay checker validates request/response hops. Flood is
different: it must be a one-way NON multicast POST with No-Response=26, and
loop topologies should not produce Content responses.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cbor2

try:
    import quadsk
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:  # pragma: no cover
    quadsk = None
    Cipher = algorithms = modes = padding = default_backend = None


CGRASP_RESOURCE_PATH = [".well-known", "grasp-coap"]
CGRASP_MULTICAST_GROUP = "ff02::fd"
M_FLOOD = 9
COAP_TYPE_NON = 1
COAP_CODE_POST = 2
OPTION_URI_PATH = 11
OPTION_NO_RESPONSE = 258
FLOOD_NO_RESPONSE_VALUE = 26


@dataclass(frozen=True)
class FloodEvent:
    filename: str
    frame: str
    src: str
    dst: str
    src_port: str
    dst_port: str
    coap_type: int
    code: int
    mid: int
    token: bytes
    path: list[str]
    no_response: list[int]
    cgrasp: list[Any]

    @property
    def session_id(self) -> int:
        return self.cgrasp[1]

    @property
    def initiator(self) -> bytes:
        return self.cgrasp[2]

    @property
    def loop_counts(self) -> list[int]:
        loops = []
        for tagged in self.cgrasp[4:]:
            if isinstance(tagged, list) and tagged and isinstance(tagged[0], list) and len(tagged[0]) >= 3:
                loops.append(tagged[0][2])
        return loops


def _extended(nibble: int, data: bytes, offset: int) -> tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    if nibble == 13:
        return 13 + data[offset], offset + 1
    if nibble == 14:
        return 269 + int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    raise ValueError("reserved option nibble")


def _decrypt_quads(payload: bytes) -> bytes:
    if quadsk is None or Cipher is None or padding is None or default_backend is None:
        raise ValueError("QUADS unavailable")
    decryptor = Cipher(
        algorithms.AES(quadsk.key),
        modes.CBC(quadsk.iv),
        backend=default_backend(),
    ).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decryptor.update(payload) + decryptor.finalize()) + unpadder.finalize()


def _loads_payload(payload: bytes) -> list[Any]:
    for raw in (payload, None):
        try:
            decoded = cbor2.loads(payload if raw is not None else _decrypt_quads(payload))
            if isinstance(decoded, list) and len(decoded) >= 5 and decoded[0] == M_FLOOD:
                return decoded
        except Exception:
            continue
    raise ValueError("not a cGRASP Flood payload")


def parse_udp_payload(filename: str, fields: list[str]) -> FloodEvent | None:
    raw = bytes.fromhex(fields[5].replace(":", ""))
    if len(raw) < 4 or raw[0] >> 6 != 1:
        return None
    token_length = raw[0] & 0x0F
    coap_type = (raw[0] >> 4) & 0x03
    code = raw[1]
    mid = int.from_bytes(raw[2:4], "big")
    token = raw[4:4 + token_length]
    offset = 4 + token_length
    option_number = 0
    options = []
    while offset < len(raw) and raw[offset] != 0xFF:
        head = raw[offset]
        offset += 1
        delta, offset = _extended(head >> 4, raw, offset)
        length, offset = _extended(head & 0x0F, raw, offset)
        option_number += delta
        options.append((option_number, raw[offset:offset + length]))
        offset += length
    payload = b""
    if offset < len(raw) and raw[offset] == 0xFF:
        payload = raw[offset + 1:]
    try:
        cgrasp = _loads_payload(payload)
    except Exception:
        return None
    return FloodEvent(
        filename=filename,
        frame=fields[0],
        src=fields[1],
        dst=fields[2].lower(),
        src_port=fields[3],
        dst_port=fields[4],
        coap_type=coap_type,
        code=code,
        mid=mid,
        token=token,
        path=[value.decode("utf-8", "replace") for number, value in options if number == OPTION_URI_PATH],
        no_response=[int.from_bytes(value, "big") for number, value in options if number == OPTION_NO_RESPONSE],
        cgrasp=cgrasp,
    )


def read_pcaps(capture_dir: Path) -> list[FloodEvent]:
    events: list[FloodEvent] = []
    for pcap in sorted(capture_dir.glob("*.pcap")):
        proc = subprocess.run(
            [
                "tshark", "-r", str(pcap), "-Y", "udp && ipv6",
                "-T", "fields", "-E", "separator=|",
                "-e", "frame.number", "-e", "ipv6.src", "-e", "ipv6.dst",
                "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode:
            raise RuntimeError(proc.stderr.strip() or f"tshark failed for {pcap}")
        for line in proc.stdout.splitlines():
            fields = line.split("|", 5)
            if len(fields) != 6 or not fields[5]:
                continue
            event = parse_udp_payload(pcap.name, fields)
            if event is not None:
                events.append(event)
    return events


def validate(events: list[FloodEvent], *, min_hops: int) -> list[str]:
    errors: list[str] = []
    if len(events) < min_hops:
        errors.append(f"only {len(events)} Flood frame(s), expected at least {min_hops}")
    sessions = {event.session_id for event in events}
    initiators = {event.initiator for event in events}
    if len(sessions) != 1:
        errors.append(f"expected one Flood session-id, observed {sorted(sessions)}")
    if len(initiators) != 1:
        errors.append(f"expected one Flood initiator, observed {len(initiators)}")
    all_loops = sorted({loop for event in events for loop in event.loop_counts}, reverse=True)
    if len(all_loops) < min(2, min_hops):
        errors.append(f"insufficient loop-count diversity: {all_loops}")
    for event in events:
        if event.coap_type != COAP_TYPE_NON:
            errors.append(f"{event.filename} frame {event.frame}: Flood is not NON")
        if event.code != COAP_CODE_POST:
            errors.append(f"{event.filename} frame {event.frame}: Flood code is {event.code}, expected POST")
        if event.dst != CGRASP_MULTICAST_GROUP:
            errors.append(f"{event.filename} frame {event.frame}: Flood dst is {event.dst}")
        if event.path != CGRASP_RESOURCE_PATH:
            errors.append(f"{event.filename} frame {event.frame}: Flood path is /{'/'.join(event.path)}")
        if event.no_response != [FLOOD_NO_RESPONSE_VALUE]:
            errors.append(
                f"{event.filename} frame {event.frame}: Flood No-Response is {event.no_response}, "
                f"expected [{FLOOD_NO_RESPONSE_VALUE}]"
            )
    return errors


def report(events: list[FloodEvent], errors: list[str]) -> str:
    lines = ["cGRASP multicast Flood pcap report", ""]
    for event in sorted(events, key=lambda item: (item.filename, int(item.frame or 0))):
        loops = ",".join(str(loop) for loop in event.loop_counts)
        lines.append(
            f"{event.filename} frame={event.frame} {event.src}%:{event.src_port} -> "
            f"{event.dst}%:{event.dst_port} type={event.coap_type} code={event.code} "
            f"mid={event.mid} token={event.token.hex() or '-'} M_FLOOD "
            f"sid={event.session_id} initiator={event.initiator.hex()} loops={loops} "
            f"no_response={event.no_response}"
        )
    lines.append("")
    if errors:
        lines.append("FAIL")
        lines.extend(f"- {err}" for err in errors)
    else:
        lines.append("PASS")
        lines.append("- Flood relay mapping validated")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture_dir", type=Path)
    ap.add_argument("--min-hops", type=int, default=3)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()

    try:
        events = read_pcaps(args.capture_dir)
    except FileNotFoundError:
        print("SKIP: tshark is required for Flood pcap validation", file=sys.stderr)
        return 77
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    errors = validate(events, min_hops=args.min_hops)
    output = report(events, errors)
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    if errors:
        print("FAIL: Flood pcap validation failed; " + "; ".join(errors), file=sys.stderr)
        return 1
    print(
        f"PASS: Flood pcap validation: {len(events)} cGRASP Flood frame(s), "
        f"report: {args.report if args.report else '(not written)'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
