# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Real BRSKI flood E2E over Linux network namespaces.

Topology: Reggie (R) -- Procksy (P) -- Pledji (L).
The script creates three namespaces and two veth links, then verifies that
Procksy sees the registrar flood and Pledji discovers the proxy flood.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "test_brski_namespaces.sh"


def _skip_reason():
    if not sys.platform.startswith("linux"):
        return "Linux network namespaces are required"
    if os.geteuid() != 0:
        return "root is required for ip netns and veth"
    for tool in ("bash", "ip"):
        if shutil.which(tool) is None:
            return f"{tool} is not installed"
    for name in ("Reggie.py", "Procksy.py", "Pledji.py"):
        if not (ROOT / "ASA-examples" / name).is_file():
            return f"ASA-examples/{name} is missing"
    return None


@pytest.mark.relay
def test_brski_flood_e2e_real(tmp_path):
    reason = _skip_reason()
    if reason:
        pytest.skip(reason)

    capture_dir = tmp_path / "brski-e2e"
    env = os.environ.copy()
    env["PYTHON_BIN"] = env.get("PYTHON_BIN", sys.executable)
    env["CAPTURE_DIR"] = str(capture_dir)

    completed = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout

    report = (capture_dir / "report.txt").read_text(encoding="utf-8")
    assert "PASS" in report
    assert "registrar=" in (capture_dir / "procksy.log").read_text(encoding="utf-8")
    assert "flooded proxy" in (capture_dir / "procksy.log").read_text(encoding="utf-8")
    assert "discovered join proxy" in (capture_dir / "pledji.log").read_text(encoding="utf-8")
