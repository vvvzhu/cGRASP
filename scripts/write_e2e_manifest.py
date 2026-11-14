#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Write reproducibility metadata for a namespace E2E evidence directory."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--topology", required=True)
    parser.add_argument("--result", choices=("RUNNING", "PASS", "FAIL"), default="RUNNING")
    parser.add_argument("--parameter", action="append", default=[])
    args = parser.parse_args()

    try:
        aiocoap_version = version("aiocoap")
    except PackageNotFoundError:
        aiocoap_version = None
    parameters = dict(item.split("=", 1) for item in args.parameter)
    now = datetime.now(timezone.utc).isoformat()
    existing = {}
    if args.output.is_file() and args.output.stat().st_size:
        try:
            existing = json.loads(args.output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
    manifest = {
        "schema": 1,
        "run_id": args.run_id,
        "scenario": args.scenario,
        "topology": args.topology,
        "result": args.result,
        "created_at": existing.get("created_at", now),
        "updated_at": now,
        "git_commit": git("rev-parse", "HEAD"),
        "git_dirty": bool(git("status", "--short")),
        "python": platform.python_version(),
        "aiocoap": aiocoap_version,
        "parameters": parameters,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
