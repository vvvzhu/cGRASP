#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""Parse tshark -V text output for CoAP+cGRASP frames.

This script is meant for situations where you *already* ran something like:
  tshark -r capture.pcap -V > res.txt
and now want to extract the CoAP metadata and the decoded CBOR (cGRASP) message.

It reconstructs a Python list structure from the "Concise Binary Object Representation"
section and then prints a compact cGRASP interpretation.

Usage:
  python3 parse_tshark_v_coap_cgrasp.py res.txt -o res1.txt

Notes:
- This does not need the original pcap.
- It relies on tshark's CBOR pretty-print structure, not payload hex.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# cGRASP message type constants (subset)
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


_MTYPE_NAME = {
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


@dataclass
class CoapFrame:
    frame_no: Optional[int] = None
    ipv6_src: Optional[str] = None
    ipv6_dst: Optional[str] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None

    coap_type: Optional[str] = None
    coap_code: Optional[str] = None
    coap_mid: Optional[int] = None

    uri_path: Optional[str] = None
    uri_query: List[str] = None  # type: ignore[assignment]

    cbor: Any = None
    cgrasp: Optional[Dict[str, Any]] = None


def _int_or_none(s: str) -> Optional[int]:
    try:
        return int(s)
    except Exception:
        return None


def _split_frames(text: str) -> List[str]:
    # tshark uses "Frame N:" at column 0.
    parts = re.split(r"(?m)^Frame \d+: ", text)
    if not parts:
        return []
    # first part is preamble (before first Frame)
    out = []
    for i in range(1, len(parts)):
        out.append("Frame " + parts[i])
    return out


def _parse_coap_header(block: str, fr: CoapFrame) -> None:
    m = re.search(r"(?m)^\s*Frame Number:\s*(\d+)\s*$", block)
    if m:
        fr.frame_no = _int_or_none(m.group(1))

    m = re.search(r"(?m)^Internet Protocol Version 6, Src:\s*([^,]+), Dst:\s*(.+?)\s*$", block)
    if m:
        fr.ipv6_src = m.group(1).strip()
        fr.ipv6_dst = m.group(2).strip()

    m = re.search(r"(?m)^User Datagram Protocol, Src Port:\s*(\d+), Dst Port:\s*(\d+)\s*$", block)
    if m:
        fr.udp_src = _int_or_none(m.group(1))
        fr.udp_dst = _int_or_none(m.group(2))

    # Example: "Constrained Application Protocol, Non-Confirmable, FETCH, MID:54462"
    m = re.search(
        r"(?m)^Constrained Application Protocol,\s*([^,]+),\s*([^,]+),\s*MID:(\d+)\s*$",
        block,
    )
    if m:
        fr.coap_type = m.group(1).strip()
        fr.coap_code = m.group(2).strip()
        fr.coap_mid = _int_or_none(m.group(3))

    # Collect Uri-Path segments and Uri-Query values (from option printout)
    path_segs: List[str] = []
    queries: List[str] = []
    for line in block.splitlines():
        line = line.strip()
        if line.startswith("Uri-Path:"):
            seg = line.split(":", 1)[1].strip()
            if seg:
                path_segs.append(seg)
        elif line.startswith("Uri-Query:"):
            q = line.split(":", 1)[1].strip()
            if q:
                queries.append(q)

    if path_segs:
        fr.uri_path = "/" + "/".join(path_segs)
    fr.uri_query = queries


_VALUE_PATTERNS: List[Tuple[re.Pattern[str], Any]] = [
    (re.compile(r"^Unsigned Integer:\s*(\d+)\s*$"), lambda m: int(m.group(1))),
    (re.compile(r"^Negative Integer:\s*(-\d+)\s*$"), lambda m: int(m.group(1))),
    (re.compile(r"^Text String:\s*(.*)$"), lambda m: m.group(1)),
    (re.compile(r"^Byte String:\s*([0-9A-Fa-f]+)\s*$"), lambda m: bytes.fromhex(m.group(1))),
    (re.compile(r"^(true|false)\s*$", re.IGNORECASE), lambda m: m.group(1).lower() == "true"),
    (re.compile(r"^Null\s*$", re.IGNORECASE), lambda m: None),
]


def _parse_cbor_tree(block: str) -> Any:
    """Reconstruct CBOR structure from tshark's CBOR pretty print.

    We only depend on:
      - "Array: (N elements)"
      - leaf lines containing "Unsigned Integer:", "Text String:", "Byte String:" etc.

    Returns root object (usually a list) or None.
    """

    # Find CBOR section start
    lines = block.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == "Concise Binary Object Representation")
    except StopIteration:
        return None

    cbor_lines = lines[start + 1 :]

    stack: List[Tuple[int, List[Any]]] = []  # (indent, list)
    root: Any = None

    for raw in cbor_lines:
        # Stop if the next frame begins (defensive)
        if raw.startswith("Frame "):
            break

        indent = len(raw) - len(raw.lstrip(" "))
        s = raw.strip()
        if not s:
            continue

        if s.startswith("Array:"):
            # Create new list; decide nesting based on indentation.
            while stack and indent <= stack[-1][0]:
                stack.pop()
            new_list: List[Any] = []
            if stack:
                stack[-1][1].append(new_list)
            else:
                root = new_list
            stack.append((indent, new_list))
            continue

        # Leaf value lines sometimes have bitfield prefix like "...0 0001 = Unsigned Integer: 1"
        if "= " in s:
            s2 = s.split("= ", 1)[1].strip()
        else:
            s2 = s

        val = None
        for pat, conv in _VALUE_PATTERNS:
            m = pat.match(s2)
            if m:
                val = conv(m)
                break
        if val is None and s2 != "None":
            # Not a supported value line.
            continue

        if not stack:
            continue
        stack[-1][1].append(val)

    return root


def _decode_objective(obj: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(obj, list) or not obj:
        return None
    out: Dict[str, Any] = {}
    if len(obj) >= 1 and isinstance(obj[0], int):
        out["objective_num"] = obj[0]
    if len(obj) >= 2 and isinstance(obj[1], int):
        out["flags"] = obj[1]
    if len(obj) >= 3 and isinstance(obj[2], int):
        out["loop_count"] = obj[2]
    if len(obj) >= 4:
        out["value"] = obj[3]
    return out or None


def _decode_cgrasp(msg: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(msg, list) or len(msg) < 2:
        return None
    if not isinstance(msg[0], int):
        return None

    mtype = msg[0]
    out: Dict[str, Any] = {
        "mtype": mtype,
        "mtype_name": _MTYPE_NAME.get(mtype, f"M_{mtype}"),
        "session_id": msg[1] if isinstance(msg[1], int) else msg[1],
    }

    # Discovery/Response/Flood include initiator as element 2
    if mtype in (M_DISCOVERY, M_RESPONSE, M_FLOOD) and len(msg) >= 3:
        ini = msg[2]
        if isinstance(ini, (bytes, bytearray)):
            out["initiator_hex"] = bytes(ini).hex()
        else:
            out["initiator"] = ini

    # Objective positions
    if mtype in (M_DISCOVERY, M_REQ_NEG, M_REQ_SYN, M_NEGOTIATE, M_SYNCH):
        # Discovery: [type,sid,ini,obj]
        # Others: [type,sid,obj]
        obj = msg[3] if mtype == M_DISCOVERY and len(msg) >= 4 else (msg[2] if len(msg) >= 3 else None)
        out["objective"] = _decode_objective(obj)

    # END often has reason option list
    if mtype == M_END and len(msg) >= 3:
        out["end"] = msg[2]

    # WAIT: ttl ms
    if mtype == M_WAIT and len(msg) >= 3:
        out["wait_ms"] = msg[2]

    # RESPONSE: ttl and locator/options are complex; keep raw tail
    if mtype == M_RESPONSE and len(msg) >= 4:
        ttl = msg[3] if (len(msg) >= 4 and isinstance(msg[3], int)) else None
        if ttl is not None:
            out["ttl_ms"] = ttl

        # Common encodings we see in this codebase:
        #   [2, sid, ini, ttl, [106, "coap://...", 17, 5683]]
        # or ttl followed by a list of such locator option arrays.
        loc_part = msg[4] if len(msg) >= 5 else None

        def _decode_locator_opt(opt: Any) -> Optional[Dict[str, Any]]:
            if not isinstance(opt, list) or len(opt) < 2:
                return None
            otype = opt[0] if isinstance(opt[0], int) else None
            if otype is None:
                return None
            d: Dict[str, Any] = {"otype": otype}
            # O_URI_LOCATOR = 106
            if otype == 106:
                if len(opt) >= 2 and isinstance(opt[1], str):
                    d["uri"] = opt[1]
                if len(opt) >= 3 and isinstance(opt[2], int):
                    d["protocol"] = opt[2]
                if len(opt) >= 4 and isinstance(opt[3], int):
                    d["port"] = opt[3]
                return d
            # Fallback: preserve raw
            d["raw"] = opt[1:]
            return d

        locs: List[Dict[str, Any]] = []
        if isinstance(loc_part, list) and loc_part and isinstance(loc_part[0], int):
            one = _decode_locator_opt(loc_part)
            if one:
                locs.append(one)
        elif isinstance(loc_part, list):
            for it in loc_part:
                one = _decode_locator_opt(it)
                if one:
                    locs.append(one)
        if locs:
            out["locators"] = locs

        out["response_tail"] = msg[3:]

    return out


def _json_friendly(x: Any) -> Any:
    if isinstance(x, (bytes, bytearray)):
        return {"__bytes__": bytes(x).hex()}
    if isinstance(x, list):
        return [_json_friendly(i) for i in x]
    if isinstance(x, dict):
        return {k: _json_friendly(v) for k, v in x.items()}
    return x


def parse_tshark_v_text(text: str) -> List[CoapFrame]:
    frames: List[CoapFrame] = []
    for block in _split_frames(text):
        # tshark may decode udp/5684 as DTLS, or leave a non-standard CoAP port
        # as generic UDP, unless decode-as is supplied. In that case the CoAP
        # section won't exist. We still accept blocks that have a CBOR section.
        if ("Constrained Application Protocol" not in block) and (
            "Concise Binary Object Representation" not in block
        ):
            continue
        fr = CoapFrame(uri_query=[])
        _parse_coap_header(block, fr)
        fr.cbor = _parse_cbor_tree(block)
        fr.cgrasp = _decode_cgrasp(fr.cbor)
        frames.append(fr)
    return frames


def format_frames(frames: List[CoapFrame], *, as_jsonl: bool) -> str:
    if as_jsonl:
        lines = []
        for fr in frames:
            d = asdict(fr)
            d["cbor"] = _json_friendly(d.get("cbor"))
            lines.append(json.dumps(d, ensure_ascii=False, sort_keys=True))
        return "\n".join(lines) + ("\n" if lines else "")

    out_lines: List[str] = []
    for fr in frames:
        out_lines.append(f"Frame {fr.frame_no}: {fr.ipv6_src}% -> {fr.ipv6_dst}%  udp {fr.udp_src}->{fr.udp_dst}")
        out_lines.append(f"  CoAP: type={fr.coap_type} code={fr.coap_code} mid={fr.coap_mid}")
        if fr.uri_path:
            out_lines.append(f"  Uri-Path: {fr.uri_path}")
        if fr.uri_query:
            out_lines.append(f"  Uri-Query: {', '.join(fr.uri_query)}")
        if fr.cgrasp:
            out_lines.append(f"  cGRASP: {fr.cgrasp.get('mtype_name')} sid={fr.cgrasp.get('session_id')}")
            if fr.cgrasp.get("initiator_hex"):
                out_lines.append(f"    initiator={fr.cgrasp.get('initiator_hex')}")
            if fr.cgrasp.get("objective"):
                out_lines.append(f"    objective={fr.cgrasp.get('objective')}")
            if fr.cgrasp.get("end") is not None:
                out_lines.append(f"    end={_json_friendly(fr.cgrasp.get('end'))}")
            if fr.cgrasp.get("wait_ms") is not None:
                out_lines.append(f"    wait_ms={fr.cgrasp.get('wait_ms')}")
        else:
            out_lines.append("  cGRASP: (no CBOR decode found)")

        # Include a compact raw view when available
        if fr.cbor is not None:
            out_lines.append(f"  CBOR(raw)={_json_friendly(fr.cbor)}")
        out_lines.append("")

    return "\n".join(out_lines).rstrip() + ("\n" if out_lines else "")


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse tshark -V text output for CoAP+cGRASP")
    ap.add_argument("input", help="Input file produced by tshark -V (e.g., res.txt)")
    ap.add_argument("-o", "--output", default="res1.txt", help="Output file path")
    ap.add_argument("--jsonl", action="store_true", help="Write JSONL instead of human-readable text")
    args = ap.parse_args()

    inp = Path(args.input)
    outp = Path(args.output)
    text = inp.read_text(encoding="utf-8", errors="replace")

    frames = parse_tshark_v_text(text)
    if not frames:
        hint = (
            "[hint] No CoAP/CBOR frames found. For a non-standard plaintext CoAP port,\n"
            "       recreate the input with tshark decode-as, for example:\n"
            "         tshark -d udp.port==15683,coap -r capture.pcap -V > res.txt\n"
        )
        try:
            print(hint)
        except Exception:
            pass
    rendered = format_frames(frames, as_jsonl=bool(args.jsonl))
    outp.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
