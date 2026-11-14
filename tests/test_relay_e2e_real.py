# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "test_relay_multi_namespaces.sh"


def _skip_reason():
    if not sys.platform.startswith("linux"):
        return "Linux network namespaces are required"
    if os.geteuid() != 0:
        return "root is required for ip netns, veth and tcpdump"
    for tool in ("bash", "ip", "tcpdump"):
        if shutil.which(tool) is None:
            return f"{tool} is not installed"
    if importlib.util.find_spec("dpkt") is None:
        return "dpkt is required to validate the captures"
    return None


@pytest.mark.relay
def test_relay_multi_e2e_real(tmp_path):
    """Run the A--R--B relay scenario over real veth links and validate pcaps.

    Unlike ``relay_e2e_simulation.py``, this test creates Linux network
    namespaces, runs three ``cgrasp.cgrasp`` processes, captures UDP/5683 traffic on
    the relay interfaces, and makes ``check_relay_multi_pcaps.py`` assert the
    hop-by-hop Discovery/response path.  It is skipped unless the host provides
    Linux, root, ``ip``, ``tcpdump`` and ``dpkt``.
    """
    reason = _skip_reason()
    if reason:
        pytest.skip(reason)

    capture_dir = tmp_path / "relay-multi"
    env = os.environ.copy()
    env["PYTHON_BIN"] = env.get("PYTHON_BIN", sys.executable)
    env["CAPTURE_DIR"] = str(capture_dir)
    env["RESPONDER_COUNT"] = "1"

    completed = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout

    report = (capture_dir / "relay-multi-report.txt").read_text(encoding="utf-8")
    assert "PASS" in report
    assert (capture_dir / "relay-left.pcap").exists()
    assert (capture_dir / "relay-b.pcap").exists()
