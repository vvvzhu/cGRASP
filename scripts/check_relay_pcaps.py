#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate and summarize hop-by-hop cGRASP Discovery relay pcaps.

This checker is intentionally independent of tshark's CoAP option-name fields:
it asks tshark only for UDP payload bytes, then parses CoAP and CBOR locally.
It proves the properties that the base coap-integration report cannot show:

* multicast Discovery is FETCH/NON on every observed relay hop;
* Discovery does not carry No-Response;
* M_RESPONSE is a 2.05 Content response, not a new POST request;
* each hop's response uses the same Token as that hop's request;
* relay creates fresh request Tokens on downstream hops;
* cGRASP initiator/session stay unchanged and loop-count decreases.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cbor2
from types import SimpleNamespace
try:
    import json
    import os
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    _quads_key_file = os.environ.get("CGRASP_QUADS_KEY_FILE", "").strip()
    if _quads_key_file:
        with open(_quads_key_file, "r", encoding="utf-8") as _kf:
            _qk = json.load(_kf)
        quadsk = SimpleNamespace(key=bytes.fromhex(_qk["key"]),
                                 iv=bytes.fromhex(_qk["iv"]))
    else:
        quadsk = None
except Exception:  # pragma: no cover - exercised only when optional crypto is absent
    quadsk = None
    Cipher = algorithms = modes = padding = default_backend = None


CGRASP_RESOURCE_PATH = [".well-known", "grasp-coap"]
CGRASP_MULTICAST_GROUP = "ff02::fd"
M_DISCOVERY = 1
M_RESPONSE = 2
COAP_TYPE_CON = 0
COAP_TYPE_NON = 1
COAP_CODE_POST = 2
COAP_CODE_FETCH = 5
COAP_CODE_CONTENT = 69
OPTION_URI_PATH = 11
OPTION_NO_RESPONSE = 258


@dataclass(frozen=True)
class CoapPacket:
    filename: str
    frame: str
    time_epoch: float
    src: str
    dst: str
    src_port: str
    dst_port: str
    msg_type: int
    code: int
    mid: int
    token: bytes
    options: tuple[tuple[int, bytes], ...]
    payload: bytes

    @property
    def path(self) -> list[str]:
        return [
            value.decode("utf-8", "replace")
            for number, value in self.options
            if number == OPTION_URI_PATH
        ]

    @property
    def no_response(self) -> list[int]:
        return [
            int.from_bytes(value, "big")
            for number, value in self.options
            if number == OPTION_NO_RESPONSE
        ]


@dataclass(frozen=True)
class CGraspEvent:
    packet: CoapPacket
    cgrasp: list[Any]
    session_id: int
    initiator: bytes
    loop_count: int | None

    @property
    def token_hex(self) -> str:
        return self.packet.token.hex() or "-"

    @property
    def initiator_hex(self) -> str:
        return self.initiator.hex()


def _extended(nibble: int, data: bytes, offset: int) -> tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    if nibble == 13:
        if offset >= len(data):
            raise ValueError("truncated extended CoAP option")
        return 13 + data[offset], offset + 1
    if nibble == 14:
        if offset + 2 > len(data):
            raise ValueError("truncated extended CoAP option")
        return 269 + int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    raise ValueError("reserved CoAP option nibble")


def parse_coap(raw: bytes, *, filename: str, fields: list[str]) -> CoapPacket:
    if len(raw) < 4:
        raise ValueError("short CoAP packet")
    if raw[0] >> 6 != 1:
        raise ValueError("unsupported CoAP version")
    token_length = raw[0] & 0x0F
    if token_length > 8:
        raise ValueError("invalid CoAP token length")
    if 4 + token_length > len(raw):
        raise ValueError("truncated CoAP token")
    msg_type = (raw[0] >> 4) & 0x03
    code = raw[1]
    mid = int.from_bytes(raw[2:4], "big")
    token = raw[4:4 + token_length]
    offset = 4 + token_length
    option_number = 0
    options: list[tuple[int, bytes]] = []
    while offset < len(raw) and raw[offset] != 0xFF:
        head = raw[offset]
        offset += 1
        delta, offset = _extended(head >> 4, raw, offset)
        length, offset = _extended(head & 0x0F, raw, offset)
        option_number += delta
        if offset + length > len(raw):
            raise ValueError("truncated CoAP option")
        options.append((option_number, raw[offset:offset + length]))
        offset += length
    payload = b""
    if offset < len(raw):
        if raw[offset] != 0xFF:
            raise ValueError("invalid CoAP payload marker")
        payload = raw[offset + 1:]
    return CoapPacket(
        filename=filename,
        frame=fields[0],
        time_epoch=float(fields[1]),
        src=fields[2],
        dst=fields[3].lower(),
        src_port=fields[4],
        dst_port=fields[5],
        msg_type=msg_type,
        code=code,
        mid=mid,
        token=token,
        options=tuple(options),
        payload=payload,
    )


def _loop_count(msg: list[Any]) -> int | None:
    if not msg or msg[0] != M_DISCOVERY or len(msg) < 4:
        return None
    obj = msg[3]
    if isinstance(obj, list) and len(obj) >= 3 and isinstance(obj[2], int):
        return obj[2]
    return None


def parse_cgrasp(packet: CoapPacket) -> CGraspEvent | None:
    if not packet.payload:
        return None
    decoded = _loads_cgrasp_payload(packet.payload)
    if not isinstance(decoded, list) or len(decoded) < 3:
        return None
    if decoded[0] not in (M_DISCOVERY, M_RESPONSE):
        return None
    session_id = decoded[1]
    initiator = decoded[2]
    if not isinstance(session_id, int) or not isinstance(initiator, bytes):
        return None
    return CGraspEvent(packet, decoded, session_id, initiator, _loop_count(decoded))


def _decrypt_quads(payload: bytes) -> bytes:
    if quadsk is None or Cipher is None or padding is None or default_backend is None:
        raise ValueError("QUADS decryption unavailable")
    decryptor = Cipher(
        algorithms.AES(quadsk.key),
        modes.CBC(quadsk.iv),
        backend=default_backend(),
    ).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decryptor.update(payload) + decryptor.finalize()) + unpadder.finalize()


def _loads_cgrasp_payload(payload: bytes) -> Any:
    try:
        decoded = cbor2.loads(payload)
        if _looks_like_cgrasp(decoded):
            return decoded
    except Exception:
        pass
    decoded = cbor2.loads(_decrypt_quads(payload))
    if not _looks_like_cgrasp(decoded):
        raise ValueError("payload is not a cGRASP message")
    return decoded


def _looks_like_cgrasp(decoded: Any) -> bool:
    return (
        isinstance(decoded, list)
        and len(decoded) >= 3
        and decoded[0] in (M_DISCOVERY, M_RESPONSE)
        and isinstance(decoded[1], int)
        and isinstance(decoded[2], bytes)
    )


def read_pcap(path: Path) -> list[CGraspEvent]:
    proc = subprocess.run(
        [
            "tshark", "-r", str(path), "-Y", "udp && ipv6",
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
        raise RuntimeError(proc.stderr.strip() or f"tshark failed for {path}")
    events: list[CGraspEvent] = []
    for line in proc.stdout.splitlines():
        fields = line.split("|", 6)
        if len(fields) != 7 or not fields[6]:
            continue
        try:
            packet = parse_coap(
                bytes.fromhex(fields[6].replace(":", "")),
                filename=path.name,
                fields=fields,
            )
            event = parse_cgrasp(packet)
        except Exception:
            continue
        if event is not None:
            events.append(event)
    return events


def validate(events: list[CGraspEvent], min_hops: int, min_loop_decrements: int | None = None,
             require_single_identity: bool = True) -> list[str]:
    errors: list[str] = []
    discoveries = [ev for ev in events if ev.cgrasp[0] == M_DISCOVERY]
    responses = [ev for ev in events if ev.cgrasp[0] == M_RESPONSE]

    if len({ev.token_hex for ev in discoveries}) < min_hops:
        errors.append(
            f"only {len({ev.token_hex for ev in discoveries})} distinct Discovery request token(s), "
            f"expected at least {min_hops}"
        )
    if len({ev.token_hex for ev in responses}) < min_hops:
        errors.append(
            f"only {len({ev.token_hex for ev in responses})} distinct response token(s), "
            f"expected at least {min_hops}"
        )

    sessions = {ev.session_id for ev in discoveries + responses}
    initiators = {ev.initiator for ev in discoveries + responses}
    if require_single_identity and len(sessions) != 1:
        errors.append(f"expected one cGRASP session-id, observed {sorted(sessions)}")
    if require_single_identity and len(initiators) != 1:
        errors.append(f"expected one cGRASP initiator, observed {len(initiators)}")

    request_by_file_token: dict[tuple[str, bytes], CGraspEvent] = {}
    for ev in discoveries:
        pkt = ev.packet
        if pkt.msg_type != COAP_TYPE_NON:
            errors.append(f"{pkt.filename} frame {pkt.frame}: Discovery is not NON")
        if pkt.code != COAP_CODE_FETCH:
            errors.append(f"{pkt.filename} frame {pkt.frame}: Discovery code is {pkt.code}, expected FETCH")
        if pkt.dst != CGRASP_MULTICAST_GROUP:
            errors.append(f"{pkt.filename} frame {pkt.frame}: Discovery dst is {pkt.dst}")
        if pkt.path != CGRASP_RESOURCE_PATH:
            errors.append(f"{pkt.filename} frame {pkt.frame}: Discovery path is /{'/'.join(pkt.path)}")
        if pkt.no_response:
            errors.append(f"{pkt.filename} frame {pkt.frame}: Discovery has No-Response={pkt.no_response}")
        request_by_file_token.setdefault((pkt.filename, pkt.token), ev)

    matched_response_tokens: set[bytes] = set()
    for ev in responses:
        pkt = ev.packet
        if pkt.code == COAP_CODE_POST:
            errors.append(f"{pkt.filename} frame {pkt.frame}: M_RESPONSE was sent as POST")
        if pkt.code != COAP_CODE_CONTENT:
            errors.append(f"{pkt.filename} frame {pkt.frame}: M_RESPONSE code is {pkt.code}, expected 2.05 Content")
        if pkt.msg_type != COAP_TYPE_CON:
            errors.append(f"{pkt.filename} frame {pkt.frame}: M_RESPONSE is not CON")
        request = request_by_file_token.get((pkt.filename, pkt.token))
        if request is None:
            errors.append(f"{pkt.filename} frame {pkt.frame}: response token {pkt.token.hex()} has no request on same pcap")
        else:
            matched_response_tokens.add(pkt.token)
            if request.packet.mid == pkt.mid:
                errors.append(f"{pkt.filename} frame {pkt.frame}: response MID reused request MID {pkt.mid}")

    if len(matched_response_tokens) < min_hops:
        errors.append(
            f"only {len(matched_response_tokens)} hop token(s) have matched request/response, "
            f"expected at least {min_hops}"
        )

    if min_loop_decrements is None:
        min_loop_decrements = min_hops - 1
    loop_counts = sorted({ev.loop_count for ev in discoveries if ev.loop_count is not None}, reverse=True)
    if min_loop_decrements > 0 and (
            len(loop_counts) < min_loop_decrements + 1 or
            (loop_counts[0] - loop_counts[-1]) < min_loop_decrements):
        errors.append(f"loop-count did not show at least {min_loop_decrements} relay decrements: {loop_counts}")

    return errors


def has_divert_response(events: list[CGraspEvent]) -> bool:
    for ev in events:
        if ev.cgrasp[0] == M_RESPONSE:
            for option in ev.cgrasp[4:]:
                if isinstance(option, list) and option and option[0] == 100:
                    return True
    return False


def response_path_delays(
        events_by_name: dict[str, list[CGraspEvent]], path_names: list[str],
        max_forward_delay_ms: float | None,
        max_end_to_end_ms: float | None) -> tuple[list[str], list[str]]:
    """Validate one response streamed from downstream to upstream captures."""
    errors: list[str] = []
    selected: list[CGraspEvent] = []
    for name in path_names:
        responses = [
            event for event in events_by_name.get(name, ())
            if event.cgrasp[0] == M_RESPONSE
        ]
        if len(responses) != 1:
            errors.append(
                f"{name}: expected one response on latency path, observed {len(responses)}")
            continue
        selected.append(responses[0])
    if len(selected) != len(path_names):
        return [], errors
    if len({event.packet.payload for event in selected}) != 1:
        errors.append("latency-path responses do not carry the same payload")

    lines: list[str] = []
    for source, forwarded in zip(selected, selected[1:]):
        delay_ms = (forwarded.packet.time_epoch - source.packet.time_epoch) * 1000
        lines.append(
            f"forwarding-delay {source.packet.filename}->{forwarded.packet.filename} "
            f"delay_ms={delay_ms:.3f}")
        if delay_ms < 0:
            errors.append(
                f"{forwarded.packet.filename} response predates {source.packet.filename}")
        if max_forward_delay_ms is not None and delay_ms > max_forward_delay_ms:
            errors.append(
                f"{source.packet.filename}->{forwarded.packet.filename} forwarding delay "
                f"{delay_ms:.3f} ms exceeds {max_forward_delay_ms:.3f} ms")
    end_to_end_ms = (
        selected[-1].packet.time_epoch - selected[0].packet.time_epoch
    ) * 1000
    lines.append(f"end-to-end-forwarding-delay delay_ms={end_to_end_ms:.3f}")
    if max_end_to_end_ms is not None and end_to_end_ms > max_end_to_end_ms:
        errors.append(
            f"end-to-end forwarding delay {end_to_end_ms:.3f} ms exceeds "
            f"{max_end_to_end_ms:.3f} ms")
    return lines, errors


def report(events: list[CGraspEvent], errors: list[str],
           latency_lines: list[str] | None = None) -> str:
    lines = ["cGRASP multicast relay pcap report", ""]
    for ev in sorted(events, key=lambda item: (item.packet.filename, int(item.packet.frame or 0))):
        pkt = ev.packet
        if ev.cgrasp[0] == M_DISCOVERY:
            kind = "M_DISCOVERY"
            detail = f"loop={ev.loop_count}"
        else:
            kind = "M_RESPONSE"
            has_divert = any(isinstance(option, list) and option and option[0] == 100
                             for option in ev.cgrasp[4:])
            detail = "divert-response" if has_divert else "content-response"
        lines.append(
            f"{pkt.filename} frame={pkt.frame} {pkt.src}%:{pkt.src_port} -> {pkt.dst}%:{pkt.dst_port} "
            f"type={pkt.msg_type} code={pkt.code} mid={pkt.mid} token={ev.token_hex} "
            f"{kind} sid={ev.session_id} initiator={ev.initiator_hex} {detail}"
        )
    lines.append("")
    if latency_lines:
        lines.extend(latency_lines)
        lines.append("")
    if errors:
        lines.append("FAIL")
        lines.extend(f"- {err}" for err in errors)
    else:
        lines.append("PASS")
        lines.append("- hop-by-hop Discovery relay and reverse Content responses validated")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture_dir", type=Path)
    ap.add_argument("--min-hops", type=int, default=3)
    ap.add_argument("--min-loop-decrements", type=int)
    ap.add_argument("--require-divert", action="store_true")
    ap.add_argument("--response-path-pcap", action="append", default=[])
    ap.add_argument("--max-forward-delay-ms", type=float)
    ap.add_argument("--max-end-to-end-ms", type=float)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()

    pcaps = sorted(args.capture_dir.glob("*.pcap"))
    if not pcaps:
        print(f"FAIL: no pcap files found in {args.capture_dir}", file=sys.stderr)
        return 1

    events: list[CGraspEvent] = []
    events_by_name: dict[str, list[CGraspEvent]] = {}
    try:
        for pcap in pcaps:
            parsed = read_pcap(pcap)
            events_by_name[pcap.name] = parsed
            events.extend(parsed)
    except FileNotFoundError:
        print("SKIP: tshark is required for relay pcap validation", file=sys.stderr)
        return 77
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    errors = validate(events, args.min_hops, args.min_loop_decrements,
                      require_single_identity=not args.require_divert)
    latency_lines: list[str] = []
    if args.response_path_pcap:
        missing_path = [
            name for name in args.response_path_pcap if name not in events_by_name
        ]
        if missing_path:
            errors.append("missing latency-path capture(s): " + ", ".join(missing_path))
        else:
            latency_lines, latency_errors = response_path_delays(
                events_by_name, args.response_path_pcap,
                args.max_forward_delay_ms, args.max_end_to_end_ms)
            errors.extend(latency_errors)
    if args.require_divert and not has_divert_response(events):
        errors.append("no O_DIVERT M_RESPONSE found")
    output = report(events, errors, latency_lines)
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    if errors:
        print("FAIL: relay pcap validation failed; " + "; ".join(errors), file=sys.stderr)
        return 1
    print(
        f"PASS: relay pcap validation: {len(events)} cGRASP Discovery/Response frame(s), "
        f"report: {args.report if args.report else '(not written)'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
