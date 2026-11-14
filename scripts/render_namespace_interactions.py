#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Render all CoAP/cGRASP namespace interactions across captured links."""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass, field
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
OPTION_NO_RESPONSE = 258
M_DISCOVERY = 1
M_RESPONSE = 2
M_REQ_NEG = 3
M_REQ_SYN = 4
M_NEGOTIATE = 5
M_END = 6
M_WAIT = 7
M_SYNCH = 8
M_FLOOD = 9

TYPE_NAMES = {
    0: "Confirmable",
    1: "Non-Confirmable",
    2: "Acknowledgement",
    3: "Reset",
}
CODE_NAMES = {
    0: "Empty Message",
    2: "POST",
    5: "FETCH",
    69: "2.05 Content",
}
MTYPE_NAMES = {
    M_DISCOVERY: "M_DISCOVERY",
    M_RESPONSE: "M_RESPONSE",
    M_REQ_NEG: "M_REQ_NEG",
    M_REQ_SYN: "M_REQ_SYN",
    M_NEGOTIATE: "M_NEGOTIATE",
    M_END: "M_END",
    M_WAIT: "M_WAIT",
    M_SYNCH: "M_SYNCH",
    M_FLOOD: "M_FLOOD",
}
DUPLICATE_WINDOW_SECONDS = 0.05


@dataclass
class Interaction:
    time_epoch: float
    frame: str
    pcap_name: str
    src: str
    dst: str
    sport: str
    dport: str
    payload_hex: str
    src_node: str
    dst_node: str
    block: str
    decoded_cgrasp: bool
    observed_on: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (self.src.lower(), self.dst.lower(), self.sport, self.dport, self.payload_hex)


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
        if isinstance(decoded, list) and len(decoded) >= 2 and decoded[0] in MTYPE_NAMES:
            return decoded
    return None


def _parse_options_and_payload(raw: bytes) -> tuple[int, int, int, bytes, list[tuple[int, bytes]], bytes]:
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


def _cgrasp_summary(msg: Any) -> str:
    if not isinstance(msg, list) or not msg:
        return "cGRASP=unparsed"
    mtype = msg[0]
    name = MTYPE_NAMES.get(mtype, f"M_{mtype}")
    sid = msg[1] if len(msg) > 1 else "-"
    parts = [f"cGRASP={name}", f"sid={sid}"]
    if len(msg) > 2:
        initiator = msg[2]
        if isinstance(initiator, (bytes, bytearray)):
            parts.append(f"initiator={bytes(initiator).hex()}")
        else:
            parts.append(f"initiator={initiator!r}")
    if mtype == M_DISCOVERY and len(msg) > 3:
        parts.append(f"objective={_decode_objective(msg[3])!r}")
    elif mtype == M_RESPONSE:
        if len(msg) > 3:
            parts.append(f"ttl={msg[3]}")
        if len(msg) > 4:
            parts.append(f"response={msg[4:]!r}")
    elif mtype == M_FLOOD:
        objective_parts = []
        for item in msg[4:]:
            if isinstance(item, list) and item and isinstance(item[0], list):
                objective_parts.append(f"objective={_decode_objective(item[0])!r}")
        if objective_parts:
            parts.append("; ".join(objective_parts))
    elif mtype in (M_REQ_NEG, M_REQ_SYN, M_NEGOTIATE, M_SYNCH) and len(msg) > 2:
        parts.append(f"objective={_decode_objective(msg[2])!r}")
    elif mtype == M_END and len(msg) > 2:
        parts.append(f"end={_json_friendly(msg[2])!r}")
    return " ".join(parts)


def _link_maps(mode: str) -> dict[str, dict[str, str]]:
    common = {
        "cgrasp-r1-vr10.pcap": {"fe80::101": "initiator", "fe80::102": "r1", "ff02::fd": "all-cGRASP-neighbors"},
        "cgrasp-r1-vr11.pcap": {"fe80::201": "r1", "fe80::202": "r2", "ff02::fd": "all-cGRASP-neighbors"},
        "cgrasp-r2-vr20.pcap": {"fe80::201": "r1", "fe80::202": "r2", "ff02::fd": "all-cGRASP-neighbors"},
        "cgrasp-r2-vr21.pcap": {"fe80::301": "r2", "fe80::302": "responder", "ff02::fd": "all-cGRASP-neighbors"},
    }
    if mode in {"loop", "flood-loop"}:
        common.update({
            "cgrasp-r3-vr30.pcap": {"fe80::401": "initiator", "fe80::402": "r3", "ff02::fd": "all-cGRASP-neighbors"},
            "cgrasp-r3-vr31.pcap": {"fe80::501": "r3", "fe80::502": "r2", "ff02::fd": "all-cGRASP-neighbors"},
            "cgrasp-r2-vr22.pcap": {"fe80::501": "r3", "fe80::502": "r2", "ff02::fd": "all-cGRASP-neighbors"},
        })
    if mode == "multi":
        return {
            "cgrasp-init-vi0.pcap": {"fe80::101": "initiator", "fe80::111": "responder1", "ff02::fd": "all-cGRASP-neighbors"},
            "cgrasp-init-vi1.pcap": {"fe80::102": "initiator", "fe80::112": "responder2", "ff02::fd": "all-cGRASP-neighbors"},
            "cgrasp-init-vi2.pcap": {"fe80::103": "initiator", "fe80::113": "responder3", "ff02::fd": "all-cGRASP-neighbors"},
        }
    if mode == "relay-multi":
        return {
            "relay-left.pcap": {
                "fe80::101": "initiator-a",
                "fe80::102": "relay-r-left",
                "ff02::fd": "all-cGRASP-neighbors",
            },
            "relay-b.pcap": {
                "fe80::201": "relay-r-b",
                "fe80::202": "responder-b",
                "ff02::fd": "all-cGRASP-neighbors",
            },
            "relay-c.pcap": {
                "fe80::301": "relay-r-c",
                "fe80::302": "responder-c",
                "ff02::fd": "all-cGRASP-neighbors",
            },
        }
    return common


def _node_name(filename: str, addr: str, maps: dict[str, dict[str, str]]) -> str:
    lowered = addr.lower()
    return maps.get(filename, {}).get(lowered, lowered)


def _read_udp_rows(pcap: Path) -> list[list[str]]:
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
    rows = []
    for line in proc.stdout.splitlines():
        fields = line.split("|", 6)
        if len(fields) == 7 and fields[6]:
            rows.append(fields)
    return rows


def _format_interaction(
    *,
    pcap: Path,
    fields: list[str],
    maps: dict[str, dict[str, str]],
) -> Interaction:
    frame, t_epoch, src, dst, sport, dport, payload_hex = fields
    src_node = _node_name(pcap.name, src, maps)
    dst_node = _node_name(pcap.name, dst, maps)
    try:
        coap_type, code, mid, token, options, payload = _parse_options_and_payload(
            bytes.fromhex(payload_hex.replace(":", ""))
        )
        cgrasp = _loads_cgrasp(payload)
    except Exception as exc:
        block = (
            f"Frame {frame}: {src}% -> {dst}%  udp {sport}->{dport}\n"
            f"  parse_error={exc}"
        )
        return Interaction(
            time_epoch=float(t_epoch),
            frame=frame,
            pcap_name=pcap.name,
            src=src,
            dst=dst,
            sport=sport,
            dport=dport,
            payload_hex=payload_hex,
            src_node=src_node,
            dst_node=dst_node,
            block=block,
            decoded_cgrasp=False,
            observed_on=[f"{pcap.name}#frame{frame}"],
        )

    type_name = TYPE_NAMES.get(coap_type, str(coap_type))
    code_name = CODE_NAMES.get(code, str(code))
    token_text = token.hex() if token else "-"
    block_lines = [
        f"Frame {frame}: {src}% -> {dst}%  udp {sport}->{dport}",
        f"  CoAP: type={type_name} code={code_name} mid={mid} token={token_text}",
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
        mtype = cgrasp[0] if isinstance(cgrasp, list) and cgrasp else None
        mtype_name = MTYPE_NAMES.get(mtype, f"M_{mtype}")
        sid = cgrasp[1] if isinstance(cgrasp, list) and len(cgrasp) > 1 else "-"
        block_lines.append(f"  cGRASP: {mtype_name} sid={sid}")
        if isinstance(cgrasp, list) and len(cgrasp) > 2:
            initiator = cgrasp[2]
            if isinstance(initiator, (bytes, bytearray)):
                block_lines.append(f"    initiator={bytes(initiator).hex()}")
        if mtype == M_DISCOVERY and isinstance(cgrasp, list) and len(cgrasp) > 3:
            block_lines.append(f"    objective={_decode_objective(cgrasp[3])!r}")
        elif mtype in (M_REQ_NEG, M_REQ_SYN, M_NEGOTIATE, M_SYNCH) and isinstance(cgrasp, list) and len(cgrasp) > 2:
            block_lines.append(f"    objective={_decode_objective(cgrasp[2])!r}")
        elif mtype == M_END and isinstance(cgrasp, list) and len(cgrasp) > 2:
            block_lines.append(f"    end={_json_friendly(cgrasp[2])!r}")
        elif mtype == M_FLOOD and isinstance(cgrasp, list):
            for item in cgrasp[4:]:
                if isinstance(item, list) and item and isinstance(item[0], list):
                    block_lines.append(f"    objective={_decode_objective(item[0])!r}")
        block_lines.append(f"  CBOR(raw)={_json_friendly(cgrasp)!r}")
    elif payload:
        block_lines.append("  cGRASP: (no CBOR decode found)")
    else:
        block_lines.append("  cGRASP: (no CBOR decode found)")
    block = "\n".join(block_lines)
    return Interaction(
        time_epoch=float(t_epoch),
        frame=frame,
        pcap_name=pcap.name,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        payload_hex=payload_hex,
        src_node=src_node,
        dst_node=dst_node,
        block=block,
        decoded_cgrasp=cgrasp is not None,
        observed_on=[f"{pcap.name}#frame{frame}"],
    )


def _renumber_block(block: str, number: int, observed_on: list[str]) -> str:
    lines = block.splitlines()
    if not lines:
        return block
    first = lines[0]
    if first.startswith("Frame "):
        _, sep, rest = first.partition(": ")
        if sep:
            lines[0] = f"Frame {number}: {rest}"
        else:
            lines[0] = f"Frame {number}: {first}"
    else:
        lines.insert(0, f"Frame {number}:")
    lines.append(f"  Observed-On: {', '.join(observed_on)}")
    return "\n".join(lines)


def _logical_timeline(events: list[Interaction]) -> list[Interaction]:
    timeline: list[Interaction] = []
    for event in sorted(events, key=lambda item: (item.time_epoch, item.pcap_name, int(item.frame or 0))):
        duplicate = None
        for existing in reversed(timeline):
            if event.time_epoch - existing.time_epoch > DUPLICATE_WINDOW_SECONDS:
                break
            if existing.key == event.key:
                duplicate = existing
                break
        if duplicate is not None:
            duplicate.observed_on.extend(event.observed_on)
            duplicate.time_epoch = min(duplicate.time_epoch, event.time_epoch)
            continue
        timeline.append(event)
    return timeline


def render(capture_dir: Path, mode: str) -> str:
    maps = _link_maps(mode)
    pcaps = sorted(capture_dir.glob("*.pcap"))
    lines: list[str] = []
    if not pcaps:
        return ""

    raw_events: list[Interaction] = []
    for pcap in pcaps:
        try:
            rows = _read_udp_rows(pcap)
        except FileNotFoundError:
            raise
        except Exception as exc:
            lines.append(f"ERROR reading {pcap.name}: {exc}")
            continue
        for fields in rows:
            raw_events.append(_format_interaction(pcap=pcap, fields=fields, maps=maps))

    timeline = _logical_timeline(raw_events)
    if timeline:
        for index, event in enumerate(timeline, 1):
            lines.append(_renumber_block(event.block, index, event.observed_on))
            lines.append("")
    return "\n".join(lines).rstrip() + ("\n" if lines else "")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture_dir", type=Path)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    try:
        output = render(args.capture_dir, args.mode)
    except FileNotFoundError:
        print("SKIP: tshark is required for namespace interaction rendering", file=sys.stderr)
        return 77
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    if "cGRASP: M_" not in output:
        print(f"FAIL: no cGRASP frames decoded in {args.output}", file=sys.stderr)
        return 1
    print(f"REPORT: full all-node CoAP/cGRASP interactions: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
