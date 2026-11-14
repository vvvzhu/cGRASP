#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Render one pcap/pcapng as res1-style CoAP/cGRASP text.

This is a single-file offline formatter. It does not start any cGRASP node and
does not require namespace capture file names. It asks tshark only for UDP
payload bytes, then parses CoAP and cGRASP/CBOR locally.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
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


OPTION_URI_PATH = 11
OPTION_URI_QUERY = 15
OPTION_CONTENT_FORMAT = 12
OPTION_NO_RESPONSE = 258

M_NOOP = 0
M_DISCOVERY = 1
M_RESPONSE = 2
M_REQ_NEG = 3
M_REQ_SYN = 4
M_NEGOTIATE = 5
M_END = 6
M_WAIT = 7
M_SYNCH = 8
M_FLOOD = 9
M_INVALID = 99

TYPE_NAMES = {
    0: "Confirmable",
    1: "Non-Confirmable",
    2: "Acknowledgement",
    3: "Reset",
}

CODE_NAMES = {
    0: "Empty Message",
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
    5: "FETCH",
    69: "2.05 Content",
}

MTYPE_NAMES = {
    M_NOOP: "M_NOOP",
    M_DISCOVERY: "M_DISCOVERY",
    M_RESPONSE: "M_RESPONSE",
    M_REQ_NEG: "M_REQ_NEG",
    M_REQ_SYN: "M_REQ_SYN",
    M_NEGOTIATE: "M_NEGOTIATE",
    M_END: "M_END",
    M_WAIT: "M_WAIT",
    M_SYNCH: "M_SYNCH",
    M_FLOOD: "M_FLOOD",
    M_INVALID: "M_INVALID",
}


def _extended(nibble: int, data: bytes, offset: int) -> tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    if nibble == 13:
        if offset >= len(data):
            raise ValueError("truncated extended option")
        return 13 + data[offset], offset + 1
    if nibble == 14:
        if offset + 2 > len(data):
            raise ValueError("truncated extended option")
        return 269 + int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    raise ValueError("reserved option nibble")


def _parse_coap(raw: bytes) -> tuple[int, int, int, bytes, list[tuple[int, bytes]], bytes]:
    if len(raw) < 4:
        raise ValueError("short CoAP packet")
    if raw[0] >> 6 != 1:
        raise ValueError("unsupported CoAP version")
    token_len = raw[0] & 0x0F
    if token_len > 8 or 4 + token_len > len(raw):
        raise ValueError("invalid CoAP token length")
    coap_type = (raw[0] >> 4) & 0x03
    code = raw[1]
    mid = int.from_bytes(raw[2:4], "big")
    token = raw[4:4 + token_len]
    offset = 4 + token_len
    option_number = 0
    options: list[tuple[int, bytes]] = []
    while offset < len(raw) and raw[offset] != 0xFF:
        head = raw[offset]
        offset += 1
        delta, offset = _extended(head >> 4, raw, offset)
        length, offset = _extended(head & 0x0F, raw, offset)
        option_number += delta
        if offset + length > len(raw):
            raise ValueError("truncated option")
        options.append((option_number, raw[offset:offset + length]))
        offset += length
    payload = b""
    if offset < len(raw):
        if raw[offset] != 0xFF:
            raise ValueError("invalid payload marker")
        payload = raw[offset + 1:]
    return coap_type, code, mid, token, options, payload


def _path(options: list[tuple[int, bytes]]) -> str:
    parts = [
        value.decode("utf-8", "replace")
        for number, value in options
        if number == OPTION_URI_PATH
    ]
    return "/" + "/".join(parts) if parts else "-"


def _queries(options: list[tuple[int, bytes]]) -> list[str]:
    return [
        value.decode("utf-8", "replace")
        for number, value in options
        if number == OPTION_URI_QUERY
    ]


def _no_response(options: list[tuple[int, bytes]]) -> list[int]:
    return [
        int.from_bytes(value, "big")
        for number, value in options
        if number == OPTION_NO_RESPONSE
    ]


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


def _loads_cgrasp(payload: bytes) -> Any | None:
    if not payload:
        return None
    for candidate in (payload, None):
        try:
            raw = payload if candidate is not None else _decrypt_quads(payload)
            decoded = cbor2.loads(raw)
        except Exception:
            continue
        if isinstance(decoded, list) and decoded and decoded[0] in MTYPE_NAMES:
            return decoded
    return None


def _decode_objective(obj: Any) -> dict[str, Any] | None:
    if isinstance(obj, list) and len(obj) >= 3:
        out: dict[str, Any] = {}
        if isinstance(obj[0], int):
            out["objective_num"] = obj[0]
        if isinstance(obj[1], int):
            out["flags"] = obj[1]
        if isinstance(obj[2], int):
            out["loop_count"] = obj[2]
        if len(obj) >= 4:
            out["value"] = obj[3]
        return out
    return None


def _json_friendly(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": bytes(value).hex()}
    if isinstance(value, list):
        return [_json_friendly(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_friendly(item) for key, item in value.items()}
    return value


def _cgrasp_lines(cgrasp: Any) -> list[str]:
    if not isinstance(cgrasp, list) or not cgrasp:
        return ["  cGRASP: (no CBOR decode found)"]
    mtype = cgrasp[0]
    mtype_name = MTYPE_NAMES.get(mtype, f"M_{mtype}")
    sid = cgrasp[1] if len(cgrasp) > 1 else "-"
    lines = [f"  cGRASP: {mtype_name} sid={sid}"]

    if len(cgrasp) > 2:
        initiator = cgrasp[2]
        if isinstance(initiator, (bytes, bytearray)):
            lines.append(f"    initiator={bytes(initiator).hex()}")

    if mtype == M_DISCOVERY and len(cgrasp) > 3:
        lines.append(f"    objective={_decode_objective(cgrasp[3])!r}")
    elif mtype == M_RESPONSE:
        # Keep the original res1 style compact; locators are visible in CBOR(raw).
        pass
    elif mtype in (M_REQ_NEG, M_REQ_SYN, M_NEGOTIATE, M_SYNCH) and len(cgrasp) > 2:
        lines.append(f"    objective={_decode_objective(cgrasp[2])!r}")
    elif mtype == M_END and len(cgrasp) > 2:
        lines.append(f"    end={_json_friendly(cgrasp[2])!r}")
    elif mtype == M_WAIT and len(cgrasp) > 2:
        lines.append(f"    wait_ms={cgrasp[2]}")
    elif mtype == M_FLOOD:
        for item in cgrasp[4:]:
            if isinstance(item, list) and item and isinstance(item[0], list):
                lines.append(f"    objective={_decode_objective(item[0])!r}")
    elif mtype == M_INVALID and len(cgrasp) > 2:
        lines.append(f"    invalid={_json_friendly(cgrasp[2])!r}")

    lines.append(f"  CBOR(raw)={_json_friendly(cgrasp)!r}")
    return lines


def _read_udp_rows(pcap: Path, ports: set[int]) -> list[list[str]]:
    display_filter = "udp"
    if ports:
        port_expr = " || ".join(f"udp.port == {port}" for port in sorted(ports))
        display_filter = f"udp && ({port_expr})"
    proc = subprocess.run(
        [
            "tshark", "-r", str(pcap), "-Y", display_filter,
            "-T", "fields", "-E", "separator=|",
            "-e", "frame.number", "-e", "frame.time_epoch",
            "-e", "ipv6.src", "-e", "ipv6.dst",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.payload",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or f"tshark failed for {pcap}")
    rows = []
    for line in proc.stdout.splitlines():
        fields = line.split("|", 8)
        if len(fields) == 9 and fields[8]:
            rows.append(fields)
    return rows


def render(pcap: Path, *, ports: set[int], keep_parse_errors: bool = False) -> str:
    rows = _read_udp_rows(pcap, ports)
    blocks: list[tuple[float, int, str]] = []
    for fields in rows:
        frame, t_epoch, ipv6_src, ipv6_dst, ip_src, ip_dst, sport, dport, payload_hex = fields
        src = ipv6_src or ip_src
        dst = ipv6_dst or ip_dst
        try:
            coap_type, code, mid, token, options, payload = _parse_coap(
                bytes.fromhex(payload_hex.replace(":", ""))
            )
            cgrasp = _loads_cgrasp(payload)
        except Exception as exc:
            if not keep_parse_errors:
                continue
            block = (
                f"Frame {frame}: {src}% -> {dst}%  udp {sport}->{dport}\n"
                f"  parse_error={exc}"
            )
            blocks.append((float(t_epoch or 0), int(frame or 0), block))
            continue

        type_name = TYPE_NAMES.get(coap_type, str(coap_type))
        code_name = CODE_NAMES.get(code, str(code))
        block_lines = [
            f"Frame {frame}: {src}% -> {dst}%  udp {sport}->{dport}",
            f"  CoAP: type={type_name} code={code_name} mid={mid}",
        ]

        path = _path(options)
        if path != "-":
            block_lines.append(f"  Uri-Path: {path}")
        queries = _queries(options)
        if queries:
            block_lines.append(f"  Uri-Query: {', '.join(queries)}")
        no_response = _no_response(options)
        if no_response:
            block_lines.append(f"  No-Response: {no_response}")

        if cgrasp is not None:
            block_lines.extend(_cgrasp_lines(cgrasp))
        elif not payload:
            block_lines.append("  cGRASP: (no payload)")
        else:
            block_lines.append("  cGRASP: (no CBOR decode found)")

        blocks.append((float(t_epoch or 0), int(frame or 0), "\n".join(block_lines)))

    ordered = [block for _ts, _frame, block in sorted(blocks, key=lambda item: (item[0], item[1]))]
    return "\n\n".join(ordered).rstrip() + ("\n" if ordered else "")


def _parse_ports(raw: str) -> set[int]:
    ports: set[int] = set()
    for item in str(raw or "").split(","):
        item = item.strip()
        if item:
            ports.add(int(item))
    return ports


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap", type=Path, help="Input .pcap or .pcapng file")
    ap.add_argument(
        "--ports",
        default="5683,5686",
        help="Comma-separated UDP ports to inspect; empty means all UDP (default: 5683,5686)",
    )
    ap.add_argument("--output", "-o", type=Path, help="Output text file; default stdout")
    ap.add_argument("--keep-parse-errors", action="store_true", help="Include UDP packets that look non-CoAP")
    args = ap.parse_args()

    try:
        output = render(args.pcap, ports=_parse_ports(args.ports), keep_parse_errors=args.keep_parse_errors)
    except FileNotFoundError:
        print("SKIP: tshark is required for pcap rendering", file=sys.stderr)
        return 77
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        print(f"REPORT: res1-style CoAP/cGRASP interactions: {args.output}")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
