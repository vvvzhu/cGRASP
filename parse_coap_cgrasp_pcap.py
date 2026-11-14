#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""Parse CoAP-based cGRASP messages from a packet capture (pcap/pcapng).

This script extracts UDP packets that carry CoAP (default port 5683), decodes
CoAP (RFC7252) header + options (Uri-Path etc), then tries to decode the payload
as a cGRASP/GRASP CBOR message.

It is designed for the CoAP transport used in this repo:
- Standard CoAP multicast: ff02::fd:5683, resource /.well-known/grasp-coap
- Unicast CoAP endpoint: /.well-known/grasp-coap (default)

Typical capture:
  sudo tcpdump -i any -nn -s 0 -w /tmp/cgrasp-coap.pcap udp port 5683

Examples:
  python3 parse_coap_cgrasp_pcap.py /tmp/cgrasp-coap.pcap
  python3 parse_coap_cgrasp_pcap.py /tmp/cgrasp-coap.pcap --only-path .well-known/grasp-coap
  python3 parse_coap_cgrasp_pcap.py /tmp/cgrasp-coap.pcap --ports 5683,5684 --json

Notes:
- If QUADS encryption is enabled, this script will *try* to import cgrasp2 and
  decrypt payloads using cgrasp2._decrypt_msg(). If that fails, it falls back
  to raw CBOR decode.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

import cbor2 as cbor
import dpkt

try:
    from pcapng import FileScanner  # type: ignore
except Exception:
    FileScanner = None  # type: ignore


# ---- Optional integration with local cgrasp2 parser (lazy import) ----

def _load_cgrasp2():
    """Best-effort import of the local cGRASP engine.

    Important: cgrasp.cgrasp prints a tkinter-related warning at import-time on
    headless systems; keeping this lazy avoids polluting JSON output.
    """

    try:
        from cgrasp import cgrasp as _cg  # type: ignore

        return _cg
    except Exception:
        return None


# ---- CoAP parsing ----

_COAP_PAYLOAD_MARKER = 0xFF
_COAP_OPT_URI_PATH = 11


@dataclass
class CoapMessage:
    ver: int
    mtype: int
    tkl: int
    code: int
    mid: int
    token: bytes
    options: List[Tuple[int, bytes]]  # (option_number, raw_value)
    payload: bytes

    @property
    def code_str(self) -> str:
        # Code is class.detail (8-bit): class = code >> 5, detail = code & 0x1F
        c = (self.code >> 5) & 0x07
        d = self.code & 0x1F
        return f"{c}.{d:02d}"

    def uri_path(self) -> str:
        parts: List[str] = []
        for onum, oval in self.options:
            if onum == _COAP_OPT_URI_PATH:
                try:
                    parts.append(oval.decode("utf-8", "replace"))
                except Exception:
                    parts.append(oval.hex())
        return "/".join([p for p in parts if p])


def _read_u16(raw: bytes, offset: int) -> Tuple[int, int]:
    if offset + 2 > len(raw):
        raise ValueError("Truncated u16")
    return (raw[offset] << 8) | raw[offset + 1], offset + 2


def _parse_extended(nibble: int, raw: bytes, offset: int) -> Tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    if nibble == 13:
        if offset + 1 > len(raw):
            raise ValueError("Truncated option extended (13)")
        return 13 + raw[offset], offset + 1
    if nibble == 14:
        v, offset2 = _read_u16(raw, offset)
        return 269 + v, offset2
    raise ValueError("Illegal option nibble 15")


def parse_coap(raw: bytes) -> CoapMessage:
    if len(raw) < 4:
        raise ValueError("Truncated CoAP header")

    b0 = raw[0]
    ver = (b0 >> 6) & 0x03
    mtype = (b0 >> 4) & 0x03
    tkl = b0 & 0x0F
    code = raw[1]
    mid = (raw[2] << 8) | raw[3]

    if ver != 1:
        raise ValueError(f"Unsupported CoAP version {ver}")
    if tkl > 8:
        raise ValueError("Invalid token length")

    offset = 4
    if offset + tkl > len(raw):
        raise ValueError("Truncated token")
    token = raw[offset : offset + tkl]
    offset += tkl

    options: List[Tuple[int, bytes]] = []
    current_opt = 0

    # Options until payload marker (0xFF) or end
    while offset < len(raw):
        if raw[offset] == _COAP_PAYLOAD_MARKER:
            offset += 1
            break

        byte = raw[offset]
        offset += 1
        delta_n = (byte >> 4) & 0x0F
        len_n = byte & 0x0F

        delta, offset = _parse_extended(delta_n, raw, offset)
        length, offset = _parse_extended(len_n, raw, offset)

        current_opt += delta
        if offset + length > len(raw):
            raise ValueError("Truncated option value")
        oval = raw[offset : offset + length]
        offset += length
        options.append((current_opt, oval))

    payload = raw[offset:] if offset <= len(raw) else b""
    return CoapMessage(ver, mtype, tkl, code, mid, token, options, payload)


# ---- PCAP reading ----


def _iter_packets_pcap(fileobj) -> Iterator[Tuple[float, bytes]]:
    """Yield (ts, packet_bytes) from a classic pcap."""
    reader = dpkt.pcap.Reader(fileobj)
    for ts, buf in reader:
        yield float(ts), bytes(buf)


def _iter_packets_pcapng(fileobj) -> Iterator[Tuple[float, bytes]]:
    """Yield (ts, packet_bytes) from a pcapng (via python-pcapng)."""
    if FileScanner is None:
        raise RuntimeError("pcapng requires python-pcapng (module 'pcapng')")

    scanner = FileScanner(fileobj)
    for block in scanner:
        # EnhancedPacket blocks have packet_data and timestamp fields.
        pkt = getattr(block, "packet_data", None)
        if not pkt:
            continue
        ts = getattr(block, "timestamp", None)
        if ts is None:
            # Fallback: no timestamp, just use 0.
            tsf = 0.0
        else:
            # python-pcapng timestamp is typically in seconds already.
            try:
                tsf = float(ts)
            except Exception:
                tsf = 0.0
        yield tsf, bytes(pkt)


def _decode_l2_to_l3(pkt: bytes):
    """Return the IP packet (dpkt.ip.IP or dpkt.ip6.IP6) from various L2 formats."""
    # tcpdump -i any usually uses Linux cooked capture (SLL)
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
        return eth.data
    except Exception:
        pass

    try:
        sll = dpkt.sll.SLL(pkt)
        return sll.data
    except Exception:
        pass

    # Newer tcpdump versions can emit Linux cooked capture v2 (SLL2)
    try:
        sll2 = dpkt.sll2.SLL2(pkt)
        return sll2.data
    except Exception:
        pass

    # Loopback captures (DLT_NULL/DLT_LOOP)
    try:
        loop = dpkt.loopback.Loopback(pkt)
        return loop.data
    except Exception:
        pass

    # Some traces may contain raw IP
    try:
        return dpkt.ip6.IP6(pkt)
    except Exception:
        pass

    try:
        return dpkt.ip.IP(pkt)
    except Exception:
        pass

    return None


def _fmt_ts(ts: float) -> str:
    try:
        return _dt.datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")
    except Exception:
        return f"{ts:.6f}"


def _ip_str(addr_bytes: bytes, *, v6: bool) -> str:
    import ipaddress

    if v6:
        return str(ipaddress.IPv6Address(addr_bytes))
    return str(ipaddress.IPv4Address(addr_bytes))


def _maybe_decrypt(payload: bytes, *, cg_mod) -> bytes:
    if cg_mod is not None and hasattr(cg_mod, "_decrypt_msg"):
        try:
            return cg_mod._decrypt_msg(payload)  # type: ignore[attr-defined]
        except Exception:
            return payload
    return payload


def _try_decode_cgrasp(
    payload: bytes,
    *,
    cg_mod,
    try_decrypt: bool,
    try_parse: bool,
) -> Tuple[Optional[list], Optional[object], Optional[str]]:
    """Return (decoded_list, parsed_msg_obj, error_str)."""

    plain = _maybe_decrypt(payload, cg_mod=cg_mod) if try_decrypt else payload
    try:
        decoded = cbor.loads(plain)
        if not isinstance(decoded, list):
            return decoded, None, None  # type: ignore[return-value]
    except Exception as ex:
        return None, None, f"CBOR decode failed: {ex}"

    if try_parse and cg_mod is not None and hasattr(cg_mod, "_parse_msg"):
        try:
            msg = cg_mod._parse_msg(decoded)  # type: ignore[attr-defined]
            return decoded, msg, None
        except Exception as ex:
            return decoded, None, f"cgrasp _parse_msg failed: {ex}"

    return decoded, None, None


def _mtype_name(mtype: int) -> str:
    # Best-effort mapping (matches cgrasp2 constants)
    names = {
        0: "M_NOOP",
        1: "M_DISCOVERY",
        2: "M_RESPONSE",
        3: "M_REQ_NEG",
        4: "M_REQ_SYN",
        5: "M_NEGOTIATE",
        6: "M_END",
        7: "M_WAIT",
        8: "M_SYNCH",
        9: "M_FLOOD",
        99: "M_INVALID",
    }
    return names.get(int(mtype), str(int(mtype)))


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Parse CoAP-based cGRASP messages from pcap/pcapng")
    ap.add_argument("pcap", help="Input capture file (.pcap or .pcapng)")
    ap.add_argument(
        "--ports",
        default="5683",
        help="Comma-separated UDP ports to include (default: 5683)",
    )
    ap.add_argument(
        "--only-path",
        default="",
        help="Only print CoAP messages whose Uri-Path equals this (e.g., .well-known/grasp-coap or .well-known/grasp-coap)",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Output JSON lines (one record per packet)",
    )
    ap.add_argument(
        "--with-cgrasp2",
        action="store_true",
        help="Lazily import cgrasp.cgrasp to enable decrypt/parse helpers (avoids tkinter warning by default)",
    )
    ap.add_argument(
        "--try-decrypt",
        action="store_true",
        help="Try to decrypt payload using cgrasp2._decrypt_msg() (requires --with-cgrasp2)",
    )
    ap.add_argument(
        "--try-parse",
        action="store_true",
        help="Try to parse decoded CBOR using cgrasp2._parse_msg() (requires --with-cgrasp2)",
    )
    ap.add_argument(
        "--max",
        type=int,
        default=0,
        help="Stop after N printed messages (0 = no limit)",
    )
    ap.add_argument(
        "--show-payload-hex",
        action="store_true",
        help="Include CoAP payload hex (can be large)",
    )
    ap.add_argument(
        "--stats",
        action="store_true",
        help="Print a parse summary to stderr (useful when output is empty)",
    )

    args = ap.parse_args(argv)

    cg_mod = _load_cgrasp2() if args.with_cgrasp2 else None
    if (args.try_decrypt or args.try_parse) and cg_mod is None:
        sys.stderr.write("Note: --try-decrypt/--try-parse requested but cgrasp2 not available; continuing without it.\n")

    want_ports = set()
    for p in str(args.ports).split(","):
        p = p.strip()
        if not p:
            continue
        want_ports.add(int(p))

    only_path = str(args.only_path).strip("/")

    printed = 0
    counters: Dict[str, int] = {
        "pkts": 0,
        "l3": 0,
        "udp": 0,
        "port_match": 0,
        "coap_ok": 0,
        "path_match": 0,
        "printed": 0,
    }

    with open(args.pcap, "rb") as f:
        if args.pcap.lower().endswith(".pcapng"):
            pkt_iter = _iter_packets_pcapng(f)
        else:
            pkt_iter = _iter_packets_pcap(f)

        for ts, buf in pkt_iter:
            counters["pkts"] += 1
            ip = _decode_l2_to_l3(buf)
            if ip is None:
                continue
            counters["l3"] += 1

            # IPv6
            if isinstance(ip, dpkt.ip6.IP6):
                src = _ip_str(ip.src, v6=True)
                dst = _ip_str(ip.dst, v6=True)
                l4 = ip.data
            # IPv4
            elif isinstance(ip, dpkt.ip.IP):
                src = _ip_str(ip.src, v6=False)
                dst = _ip_str(ip.dst, v6=False)
                l4 = ip.data
            else:
                continue

            if not isinstance(l4, dpkt.udp.UDP):
                continue
            counters["udp"] += 1

            sport = int(l4.sport)
            dport = int(l4.dport)
            if sport not in want_ports and dport not in want_ports:
                continue
            counters["port_match"] += 1

            udp_payload = bytes(l4.data or b"")
            if not udp_payload:
                continue

            try:
                coap = parse_coap(udp_payload)
            except Exception:
                continue
            counters["coap_ok"] += 1

            upath = coap.uri_path()
            if only_path and upath != only_path:
                continue
            counters["path_match"] += 1

            decoded_list, parsed_msg, dec_err = _try_decode_cgrasp(
                coap.payload,
                cg_mod=cg_mod,
                try_decrypt=bool(args.try_decrypt),
                try_parse=bool(args.try_parse),
            )

            record: Dict[str, object] = {
                "ts": float(ts),
                "time": _fmt_ts(ts),
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "coap": {
                    "type": int(coap.mtype),
                    "code": int(coap.code),
                    "code_str": coap.code_str,
                    "mid": int(coap.mid),
                    "token": coap.token.hex(),
                    "uri_path": upath,
                    "payload_len": len(coap.payload),
                },
            }

            # Extract mtype/sid if decoded as list
            if isinstance(decoded_list, list) and len(decoded_list) >= 2:
                try:
                    mtype = int(decoded_list[0])
                    sid = int(decoded_list[1])
                    record["cgrasp"] = {
                        "mtype": mtype,
                        "mtype_name": _mtype_name(mtype),
                        "sid": sid,
                    }
                except Exception:
                    pass

            if parsed_msg is not None:
                # parsed_msg is a cgrasp2 internal message object; extract common attrs.
                try:
                    record.setdefault("cgrasp", {})
                    cgr = record["cgrasp"]
                    if isinstance(cgr, dict):
                        cgr["parsed"] = {
                            "mtype": int(getattr(parsed_msg, "mtype", -1)),
                            "id_value": int(getattr(parsed_msg, "id_value", -1)),
                            "ttl": int(getattr(parsed_msg, "ttl", 0) or 0),
                        }
                except Exception:
                    pass

            if dec_err:
                record["decode_error"] = dec_err

            if args.show_payload_hex:
                record["coap"]["payload_hex"] = coap.payload.hex()  # type: ignore[index]

            if args.json:
                sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
            else:
                line = (
                    f"{record['time']} {src}%{sport} -> {dst}%{dport} "
                    f"CoAP {coap.code_str} mid={coap.mid} tok={coap.token.hex() or '-'} "
                    f"path=/{upath} payload={len(coap.payload)}B"
                )
                if isinstance(decoded_list, list) and len(decoded_list) >= 2:
                    try:
                        line += f" cGRASP={_mtype_name(int(decoded_list[0]))} sid={int(decoded_list[1])}"
                    except Exception:
                        pass
                if dec_err:
                    line += f" [decode: {dec_err}]"
                sys.stdout.write(line + "\n")

            printed += 1
            counters["printed"] = printed
            if args.max and printed >= int(args.max):
                break

    if args.stats:
        sys.stderr.write(
            "stats: "
            + ", ".join([f"{k}={v}" for k, v in counters.items()])
            + "\n"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
