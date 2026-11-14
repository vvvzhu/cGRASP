#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Verify the packaged wheel and the ``src/`` layout.

Checks:
- a wheel can be built locally without network access;
- the wheel contains the ``cgrasp`` package, the legacy GRASP API modules and
  the ``cgraspi`` wrapper, and does not contain flat-layout shims, tests,
  scripts or captured artifacts;
- the wheel installs into a clean target directory and the package imports;
- the cGRASP engine is available as ``cgrasp.cgrasp`` (imported with ``--with-deps``).

Run from the repository root:

    python scripts/verify_package.py
    python scripts/verify_package.py --with-deps
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_VERSION_SOURCE = (ROOT / "src" / "cgrasp" / "__init__.py").read_text(encoding="utf-8")
_project_version = re.search(r'^version = "([^"]+)"',
                             (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
                             re.MULTILINE)
VERSION = re.search(r'__version__ = "([^"]+)"', _VERSION_SOURCE).group(1)
if not _project_version or _project_version.group(1) != VERSION:
    raise SystemExit("FAIL: pyproject.toml and cgrasp.__version__ disagree")

REQUIRED = {
    "cgrasp/__init__.py",
    "cgrasp/cgrasp.py",
    "cgrasp/cgrasp_engine.py",
    "cgrasp/coap_client.py",
    "cgraspi.py",
    "grasp.py",
    "acp.py",
    "graspi.py",
}

FORBIDDEN = {
    "cgrasp2.py",
    "cgrasp_coap_transport.py",
    "cgrasp_engine.py",
    "cgrasp_multicast.py",
    "cgrasp_quiescence.py",
    "coap_client.py",
    "coap_server.py",
    "coap_multicast_adapter.py",
}


def _clean_build() -> None:
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    for egg in ROOT.glob("*.egg-info"):
        shutil.rmtree(egg, ignore_errors=True)


def build_wheel(outdir: Path) -> Path:
    _clean_build()
    outdir.mkdir(parents=True, exist_ok=True)
    previous = Path.cwd()
    os.chdir(ROOT)
    try:
        try:
            import setuptools.build_meta as build_meta

            name = build_meta.build_wheel(str(outdir))
        except Exception:
            subprocess.run(
                [sys.executable, "-m", "pip", "wheel", ".",
                 "--no-deps", "--no-build-isolation", "-w", str(outdir)],
                check=True, timeout=240,
            )
            name = next(outdir.glob("*.whl")).name
    finally:
        os.chdir(previous)
    wheel = outdir / name
    if not wheel.is_file():
        raise SystemExit(f"FAIL: wheel not found in {outdir}")
    return wheel


def inspect_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        missing = sorted(REQUIRED - names)
        forbidden = sorted(
            name for name in names
            if name in FORBIDDEN or name.startswith(
                ("tests/", "scripts/", "captures/", "artifacts/", "build/"))
        )
        metadata_name = next(
            (name for name in names if name.endswith(".dist-info/METADATA")), None)
        if metadata_name is None:
            raise SystemExit("FAIL: wheel has no METADATA")
        metadata = archive.read(metadata_name).decode("utf-8")

    problems = []
    if missing:
        problems.append("missing files: " + ", ".join(missing))
    if forbidden:
        problems.append("unexpected files: " + ", ".join(forbidden[:8]))
    if "Name: cgrasp" not in metadata:
        problems.append("metadata name is not cgrasp")
    if f"Version: {VERSION}" not in metadata:
        problems.append("unexpected version")
    if "License-File: LICENSE" not in metadata and "License: BSD-3-Clause" not in metadata:
        problems.append("license metadata missing")
    if problems:
        raise SystemExit("FAIL: " + "; ".join(problems))

    print(f"OK wheel contents: {len(names)} files, package + legacy API present",
          flush=True)


def verify_install(wheel: Path, *, with_deps: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="cgrasp-wheel-") as tmp:
        target = Path(tmp) / "site"
        command = [
            sys.executable, "-m", "pip", "install", "--no-input",
            "--target", str(target),
        ]
        if with_deps:
            command.append(str(wheel))
        else:
            command.extend(["--no-deps", "--no-index", str(wheel)])
        subprocess.run(command, check=True, timeout=180)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(target)
        subprocess.run(
            [sys.executable, "-c",
             "import cgrasp, importlib.util; "
             f"assert cgrasp.__version__ == {VERSION!r}; "
             "assert importlib.util.find_spec('cgrasp.cgrasp') is not None; "
             "assert importlib.util.find_spec('cgraspi') is not None; "
             "assert importlib.util.find_spec('cgrasp2') is None; "
             "assert importlib.util.find_spec('coap_client') is None"],
            check=True, timeout=60, env=env,
        )
        print("OK clean-target import: cgrasp package + legacy API shims",
              flush=True)

        if with_deps:
            subprocess.run(
                [sys.executable, "-c",
                 "import cgrasp.cgrasp as cg; print('OK package engine ->', cg.__name__)"],
                check=True, timeout=120, env=env,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-deps", action="store_true",
                        help="install runtime deps and import the cgrasp.cgrasp engine")
    parser.add_argument("--outdir", type=Path, default=ROOT / "dist",
                        help="wheel output directory (default: ./dist)")
    args = parser.parse_args()

    wheel = build_wheel(args.outdir.resolve())
    print(f"OK built wheel: {wheel.name} ({wheel.stat().st_size} bytes)",
          flush=True)
    inspect_wheel(wheel)
    verify_install(wheel, with_deps=args.with_deps)
    print("PASS: packaging verification", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
