# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""Engine boundary for cGRASP.

``CgraspEngine`` owns the relay state, registries, caches, locks, clock and the
multicast response leisure policy.  ``cgrasp`` keeps its historical module
globals as aliases to the default engine's containers, so existing functions
continue to work while the engine boundary is introduced incrementally.

The next step (tracked in the remediation log) is to pass an engine instance
into the functions instead of relying on the module aliases, which will allow
multiple engines to coexist in one process.
"""

from __future__ import annotations

import random
import threading
import time
from typing import Callable, Optional

from .cgrasp_multicast import RelayConfig, RelayState

DEFAULT_LEISURE_MIN_MS = 50
DEFAULT_LEISURE_MAX_MS = 250

# Module-global name -> engine attribute.  cgrasp keeps the historical
# globals as aliases so existing functions do not need to change in one step.
_REGISTRY_GLOBALS = {
    "_asa_registry": "asa_registry",
    "_obj_registry": "obj_registry",
    "_discovery_cache": "discovery_cache",
    "_session_id_cache": "session_id_cache",
    "_flood_cache": "flood_cache",
    "_asa_lock": "asa_lock",
    "_obj_lock": "obj_lock",
    "_disc_lock": "disc_lock",
    "_sess_lock": "sess_lock",
    "_flood_lock": "flood_lock",
}


class CgraspEngine:
    """Own relay state, registries, caches, locks and the leisure policy."""

    def __init__(
        self,
        relay_config: Optional[RelayConfig] = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.clock = clock
        self.relay_config = relay_config
        self.relay_state = (
            RelayState(relay_config, clock=clock) if relay_config is not None else None
        )

        # Registries and caches.  The lists are deliberately kept as plain
        # lists: existing cgrasp code mutates them in place, so aliasing them
        # from the module globals is safe.
        self.asa_registry = []
        self.obj_registry = []
        self.discovery_cache = []
        self.session_id_cache = []
        self.flood_cache = []

        # Locks are re-entrant: several legacy helpers acquire a lock and call
        # another helper that takes the same lock.
        self.asa_lock = threading.RLock()
        self.obj_lock = threading.RLock()
        self.disc_lock = threading.RLock()
        self.sess_lock = threading.RLock()
        self.flood_lock = threading.RLock()

    def attach(self) -> "CgraspEngine":
        """Bind this engine's containers to the cgrasp compatibility globals."""
        from . import cgrasp
        for global_name, attribute in _REGISTRY_GLOBALS.items():
            setattr(cgrasp, global_name, getattr(self, attribute))
        return self

    def responder_leisure_seconds(self, rng: Callable[[float, float], float] = random.uniform) -> float:
        """Return a response delay within the configured leisure range."""
        if self.relay_config is None:
            low, high = DEFAULT_LEISURE_MIN_MS, DEFAULT_LEISURE_MAX_MS
        else:
            low = int(self.relay_config.responder_leisure_min_ms)
            high = int(self.relay_config.responder_leisure_max_ms)
        if high < low:
            low, high = high, low
        if high == low:
            return low / 1000.0
        return rng(low, high) / 1000.0

    def snapshot(self) -> dict:
        """Return diagnostics without exposing mutable objects."""
        return {
            "relay_state": (
                self.relay_state.snapshot() if self.relay_state is not None else None
            ),
            "registries": {
                "asa": len(self.asa_registry),
                "objectives": len(self.obj_registry),
                "discovery_cache": len(self.discovery_cache),
                "sessions": len(self.session_id_cache),
                "flood_cache": len(self.flood_cache),
            },
        }

    def install(self, *, attach_registries: bool = False) -> "CgraspEngine":
        """Install relay state (and optionally registries) into cgrasp.

        Relay configuration is created later than the engine's registry state,
        so the relay engine normally only installs ``relay_state``; the default
        engine owns the registries.
        """
        from . import cgrasp
        cgrasp._coap_relay_state = self.relay_state
        if attach_registries:
            self.attach()
        return self
