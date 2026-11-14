#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Node A placeholder for the relay E2E scenario.

The executable workflow is orchestrated by relay_e2e_simulation.py so the JSONL
trace remains deterministic and centrally validated.
"""

from relay_e2e_simulation import main


if __name__ == "__main__":
    raise SystemExit(main())
