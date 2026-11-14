# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Compatibility shim for the pre-``src/`` layout.

New code should import ``cgrasp.acp``; this top-level module is kept so
existing ASAs, tests and scripts keep working.
"""
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cgrasp import acp as _impl

sys.modules[__name__] = _impl
