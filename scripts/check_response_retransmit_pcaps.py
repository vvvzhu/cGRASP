#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate deterministic M_RESPONSE retransmission pcaps for TC-MH-05/09.

Mode A (drop first M_RESPONSE before the relay):
  - responder sends the same CON 2.05 M_RESPONSE at least twice;
  - retransmissions use the same MID and Token;
  - relay/upstream eventually sees exactly one semantic result.

Mode B (drop first ACK from relay to responder):
  - relay receives the same CON 2.05 M_RESPONSE at least twice;
  - retransmissions use the same MID and Token;
  - relay forwards the semantic response upstream exactly once.
"""

from __future__ import annotations

import argparse
import json
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


M_RESPONSE = 2
COAP_TYPE_CON = 0
COAP_TYPE_ACK = 2
COAP_CODE_CONTENT = 69
SAME_PACKET_WINDOW_SECONDS = 0.05


@dataclass(frozen=True)
class PacketEvent:
    pcap: str
    frame: int
    time_epoch: float
    src: str
    dst: str
    src_port: int
    dst_port: int
    coap_type: int
    code: int
    mid: int
    token: bytes
    payload: bytes
    cgrasp: list[Any] | None

    @property
    def token_hex(self) -> str:
        return self.token.hex() or "-"

    @property
    def response_key(self) -> tuple[int, bytes, bytes]:
        return (self.mid, self.token, self.payload)

    @property
    def hop_retransmit_key(self) -> tuple[str, str, int, int, int, int, int, bytes, bytes]:
        return (
            self.src, self.dst, self.src_port, self.dst_port,
            self.coap_type, self.code, self.mid, self.token, self.payload,
        )

    @property
    def semantic_key(self) -> bytes:
        return cbor2.dumps(self.cgrasp, canonical=True) if self.cgrasp is not None else self.payload


def _extended(nibble: int, data: bytes, offset: int) -> tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    if nibble == 13:
        if offset >= len(data):
            raise ValueError("truncated option")
        return 13 + data[offset], offset + 1
    if nibble == 14:
        if offset + 2 > len(data):
            raise ValueError("truncated option")
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


def _loads_cgrasp(payload: bytes) -> list[Any] | None:
    if not payload:
        return None
    for raw in (payload, None):
        try:
            decoded = cbor2.loads(payload if raw is not None else _decrypt_quads(payload))
        except Exception:
            continue
        if isinstance(decoded, list) and len(decoded) >= 3 and decoded[0] == M_RESPONSE:
            return decoded
    return None


def parse_coap(raw: bytes) -> tuple[int, int, int, bytes, bytes]:
    if len(raw) < 4 or raw[0] >> 6 != 1:
        raise ValueError("not CoAP")
    token_len = raw[0] & 0x0F
    if token_len > 8 or 4 + token_len > len(raw):
        raise ValueError("bad token")
    coap_type = (raw[0] >> 4) & 0x03
    code = raw[1]
    mid = int.from_bytes(raw[2:4], "big")
    token = raw[4:4 + token_len]
    offset = 4 + token_len
    option_number = 0
    while offset < len(raw) and raw[offset] != 0xFF:
        head = raw[offset]
        offset += 1
        delta, offset = _extended(head >> 4, raw, offset)
        length, offset = _extended(head & 0x0F, raw, offset)
        option_number += delta
        if offset + length > len(raw):
            raise ValueError("truncated option")
        offset += length
    payload = b""
    if offset < len(raw) and raw[offset] == 0xFF:
        payload = raw[offset + 1:]
    return coap_type, code, mid, token, payload


def read_events(capture_dir: Path) -> list[PacketEvent]:
    events: list[PacketEvent] = []
    for pcap in sorted(capture_dir.glob("*.pcap")):
        proc = subprocess.run(
            [
                "tshark", "-r", str(pcap), "-Y", "udp && ipv6",
                "-T", "fields", "-E", "separator=|",
                "-e", "frame.number", "-e", "frame.time_epoch",
                "-e", "ipv6.src", "-e", "ipv6.dst",
                "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode:
            raise RuntimeError(proc.stderr.strip() or f"tshark failed for {pcap}")
        for line in proc.stdout.splitlines():
            fields = line.split("|", 6)
            if len(fields) != 7 or not fields[6]:
                continue
            try:
                coap_type, code, mid, token, payload = parse_coap(bytes.fromhex(fields[6].replace(":", "")))
            except Exception:
                continue
            events.append(PacketEvent(
                pcap=pcap.name,
                frame=int(fields[0] or 0),
                time_epoch=float(fields[1] or 0),
                src=fields[2].lower(),
                dst=fields[3].lower(),
                src_port=int(fields[4]),
                dst_port=int(fields[5]),
                coap_type=coap_type,
                code=code,
                mid=mid,
                token=token,
                payload=payload,
                cgrasp=_loads_cgrasp(payload),
            ))
    return sorted(events, key=lambda item: (item.time_epoch, item.pcap, item.frame))


def _responses(events: list[PacketEvent]) -> list[PacketEvent]:
    return [
        event for event in events
        if event.coap_type == COAP_TYPE_CON and event.code == COAP_CODE_CONTENT and
        event.cgrasp is not None and event.cgrasp[0] == M_RESPONSE
    ]


def _acks(events: list[PacketEvent]) -> list[PacketEvent]:
    return [event for event in events if event.coap_type == COAP_TYPE_ACK]


def _time_clusters(items: list[PacketEvent]) -> list[list[PacketEvent]]:
    clusters: list[list[PacketEvent]] = []
    for item in sorted(items, key=lambda event: event.time_epoch):
        if not clusters or item.time_epoch - clusters[-1][-1].time_epoch > SAME_PACKET_WINDOW_SECONDS:
            clusters.append([item])
        else:
            clusters[-1].append(item)
    return clusters


def validate_mode_a(events: list[PacketEvent]) -> tuple[list[str], list[str]]:
    evidence: list[str] = []
    errors: list[str] = []
    responses = _responses(events)
    grouped: dict[tuple[str, str, int, int, int, int, int, bytes, bytes], list[PacketEvent]] = {}
    for event in responses:
        grouped.setdefault(event.hop_retransmit_key, []).append(event)
    retransmitted = [items for items in grouped.values() if len(_time_clusters(items)) >= 2]
    if not retransmitted:
        errors.append("no repeated CON 2.05 M_RESPONSE with same MID/Token/payload")
    else:
        chosen = sorted(retransmitted, key=lambda items: len(items), reverse=True)[0]
        first = chosen[0]
        clusters = _time_clusters(chosen)
        evidence.append(
            f"same_hop_mid_token_payload_retransmit mid={first.mid} token={first.token_hex} "
            f"clusters={len(clusters)} src={first.src}:{first.src_port} dst={first.dst}:{first.dst_port}"
        )
    semantic_results = {event.semantic_key for event in responses}
    if not semantic_results:
        errors.append("no decoded M_RESPONSE result reached capture set")
    else:
        evidence.append(f"semantic_results={len(semantic_results)}")
    return errors, evidence


def validate_mode_b(events: list[PacketEvent]) -> tuple[list[str], list[str]]:
    evidence: list[str] = []
    errors: list[str] = []
    responses = _responses(events)
    grouped: dict[tuple[str, str, int, int, int, int, int, bytes, bytes], list[PacketEvent]] = {}
    for event in responses:
        grouped.setdefault(event.hop_retransmit_key, []).append(event)
    duplicates = [items for items in grouped.values() if len(_time_clusters(items)) >= 2]
    if not duplicates:
        errors.append("response_received < 2 for same MID/Token/payload")
    else:
        chosen = sorted(duplicates, key=len, reverse=True)[0]
        first = chosen[0]
        clusters = _time_clusters(chosen)
        evidence.append(
            f"response_received_clusters={len(clusters)} same_mid={first.mid} "
            f"same_token={first.token_hex} src={first.src}:{first.src_port} dst={first.dst}:{first.dst_port}"
        )
    duplicate_semantics = 0
    for items in grouped.values():
        clusters = _time_clusters(items)
        if len(clusters) > 1:
            duplicate_semantics += len(clusters) - 1
    if duplicate_semantics < 1:
        errors.append("response_duplicate_dropped cannot be inferred: no duplicate semantic response")
    else:
        evidence.append(f"semantic_duplicate_candidates={duplicate_semantics}")
    ack_mids = {event.mid for event in _acks(events)}
    response_mids = {event.mid for event in responses}
    matching_ack_mids = ack_mids & response_mids
    if not matching_ack_mids:
        errors.append("no ACK found for retransmitted CON response MID")
    else:
        evidence.append(f"ack_matches_response_mid={sorted(matching_ack_mids)}")
    return errors, evidence


def report(mode: str, errors: list[str], evidence: list[str]) -> str:
    lines = [f"cGRASP response retransmission pcap report mode={mode}", ""]
    lines.extend(f"- {item}" for item in evidence)
    lines.append("")
    if errors:
        lines.append("FAIL")
        lines.extend(f"- {item}" for item in errors)
    else:
        lines.append("PASS")
    return "\n".join(lines) + "\n"


def _last_result(path: Path | None) -> dict:
    if path is None:
        return {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return {}
    result = {}
    for line in lines:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("event") == "result":
            result = obj
    return result


def validate_logs(mode: str, r2_log: Path | None, initiator_log: Path | None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    evidence: list[str] = []
    r2 = _last_result(r2_log)
    initiator = _last_result(initiator_log)
    if r2_log is not None:
        counters = r2.get("counters") or {}
        audit = r2.get("audit") or {}
        remaining = r2.get("remaining_transactions")
        if mode == "drop-response":
            if audit.get("coap_test_receive_fault_drop-first-response", 0) < 1:
                errors.append("R2 log missing coap_test_receive_fault_drop-first-response")
            if counters.get("response_received", 0) != 1:
                errors.append(f"R2 response_received is {counters.get('response_received')}, expected 1")
            if counters.get("response_forwarded", 0) != 1:
                errors.append(f"R2 response_forwarded is {counters.get('response_forwarded')}, expected 1")
        else:
            received = counters.get("response_received", 0)
            accepted = counters.get("accepted", 0)
            duplicates = counters.get("response_duplicate_dropped", 0)
            if received < 1:
                errors.append(f"R2 response_received is {received}, expected >= 1")
            if accepted != 1:
                errors.append(f"R2 accepted is {accepted}, expected 1")
            if counters.get("response_forwarded", 0) != 1:
                errors.append(f"R2 response_forwarded is {counters.get('response_forwarded')}, expected 1")
            if received == 1:
                evidence.append("duplicate_suppressed_below_cgrasp=true")
            elif duplicates < received - 1:
                errors.append(
                    f"R2 received {received} responses but dropped only {duplicates} duplicate(s)")
        if remaining not in (0, None):
            errors.append(f"R2 remaining_transactions is {remaining}, expected 0")
        evidence.append(f"r2_counters={counters} r2_audit={audit} remaining_transactions={remaining}")
    if initiator_log is not None:
        locators = initiator.get("locators")
        ok = initiator.get("ok")
        if ok is not True:
            errors.append("initiator result is not ok")
        if locators != 1:
            errors.append(f"initiator locators is {locators}, expected 1")
        evidence.append(f"initiator_ok={ok} initiator_unique_results={locators}")
    return errors, evidence


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture_dir", type=Path)
    ap.add_argument("--mode", choices=["drop-response", "drop-ack"], required=True)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--r2-log", type=Path)
    ap.add_argument("--initiator-log", type=Path)
    args = ap.parse_args()

    try:
        events = read_events(args.capture_dir)
    except FileNotFoundError:
        print("SKIP: tshark is required for response retransmit pcap validation", file=sys.stderr)
        return 77
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if args.mode == "drop-response":
        errors, evidence = validate_mode_a(events)
    else:
        errors, evidence = validate_mode_b(events)
    log_errors, log_evidence = validate_logs(args.mode, args.r2_log, args.initiator_log)
    errors.extend(log_errors)
    evidence.extend(log_evidence)
    output = report(args.mode, errors, evidence)
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    if errors:
        print("FAIL: response retransmit pcap validation failed; " + "; ".join(errors), file=sys.stderr)
        return 1
    print(
        f"PASS: response retransmit pcap validation mode={args.mode}; "
        f"report: {args.report if args.report else '(not written)'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
