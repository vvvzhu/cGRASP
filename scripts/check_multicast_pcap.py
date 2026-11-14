#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Validate cGRASP multicast CoAP mapping without tshark option-name support."""

from __future__ import annotations

import subprocess
import sys


def _extended(nibble: int, data: bytes, offset: int) -> tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    if nibble == 13:
        return 13 + data[offset], offset + 1
    if nibble == 14:
        return 269 + int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    raise ValueError("reserved CoAP option nibble")


def parse_coap(data: bytes) -> tuple[int, list[tuple[int, bytes]]]:
    if len(data) < 4 or data[0] >> 6 != 1:
        raise ValueError("invalid CoAP header")
    token_length = data[0] & 0x0F
    code = data[1]
    offset = 4 + token_length
    option_number = 0
    options = []
    while offset < len(data) and data[offset] != 0xFF:
        head = data[offset]
        offset += 1
        delta, offset = _extended(head >> 4, data, offset)
        length, offset = _extended(head & 0x0F, data, offset)
        option_number += delta
        if offset + length > len(data):
            raise ValueError("truncated CoAP option")
        options.append((option_number, data[offset:offset + length]))
        offset += length
    return code, options


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} CAPTURE", file=sys.stderr)
        return 2
    proc = subprocess.run(
        ["tshark", "-r", sys.argv[1], "-Y", "udp && ipv6",
         "-T", "fields", "-E", "separator=|",
         "-e", "frame.number", "-e", "ipv6.dst", "-e", "udp.payload"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode:
        print(proc.stderr, file=sys.stderr)
        return proc.returncode
    discoveries = floods = 0
    errors = []
    for line in proc.stdout.splitlines():
        fields = line.split("|", 2)
        if len(fields) != 3 or fields[1].lower() != "ff02::fd" or not fields[2]:
            continue
        frame, _destination, payload_hex = fields
        try:
            code, options = parse_coap(bytes.fromhex(payload_hex.replace(":", "")))
        except Exception as exc:
            errors.append(f"frame {frame}: {exc}")
            continue
        paths = [value.decode("utf-8", "replace") for number, value in options if number == 11]
        if paths != [".well-known", "grasp-coap"]:
            continue
        no_response = [int.from_bytes(value, "big") for number, value in options if number == 258]
        if code == 5:  # FETCH
            discoveries += 1
            if no_response:
                errors.append(f"frame {frame}: Discovery FETCH has No-Response={no_response}")
        elif code == 2:  # POST / Flood
            floods += 1
            if no_response != [26]:
                errors.append(f"frame {frame}: Flood No-Response is {no_response}, expected [26]")
    if discoveries == 0:
        errors.append("no standard multicast Discovery FETCH found")
    if floods == 0:
        errors.append("no standard multicast Flood POST found")
    if errors:
        print("FAIL: " + "; ".join(errors), file=sys.stderr)
        return 1
    print(f"PASS: multicast mapping: {discoveries} Discovery FETCH, {floods} Flood POST")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
