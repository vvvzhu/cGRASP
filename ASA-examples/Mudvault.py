#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Mudvault: add a PEM certificate to a local MUD trust store.

Ported from graspy's ``ASA-examples/Mudvault.py``, replacing the interactive
tkinter file dialog with explicit command-line arguments.  This is a local
helper, not a cGRASP ASA.

Example:

    python ASA-examples/Mudvault.py --pem ca.pem --vault ./mud-certs.pem

The certificate is appended to the vault file (created with mode 0600).  This
is demonstration code; it does not validate certificate chains or policies.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Mudvault: append a PEM certificate to a MUD trust store")
    ap.add_argument("--pem", required=True, help="PEM certificate file to add")
    ap.add_argument("--vault", default="./mud-certs.pem",
                    help="vault file to append to (default ./mud-certs.pem)")
    args = ap.parse_args(argv)

    pem_path = Path(args.pem)
    try:
        pem = pem_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"[Mudvault] cannot read {pem_path}: {exc}", file=sys.stderr)
        return 1
    if "BEGIN CERTIFICATE" not in pem or "END CERTIFICATE" not in pem:
        print(f"[Mudvault] {pem_path} does not look like a PEM certificate", file=sys.stderr)
        return 1

    vault = Path(args.vault)
    try:
        with vault.open("a", encoding="utf-8") as handle:
            if vault.stat().st_size:
                handle.write("\n")
            handle.write(pem.rstrip() + "\n")
        os.chmod(vault, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        print(f"[Mudvault] cannot write {vault}: {exc}", file=sys.stderr)
        return 1

    print(f"[Mudvault] certificate added to {vault}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
