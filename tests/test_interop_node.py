# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import unittest
from types import SimpleNamespace

from tests.interop_node import _OneShotPrng, relay_config_or_none


def args(**overrides):
    values = {
        "relay_config": None,
        "relay_interfaces": None,
        "relay_hard_timeout_ms": None,
        "relay_quiet_timeout_ms": None,
        "relay_rate": None,
        "relay_burst": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class RelayArgumentTests(unittest.TestCase):
    def test_no_relay_overrides_uses_automatic_interfaces(self):
        self.assertIsNone(relay_config_or_none(args()))

    def test_timeout_without_interface_is_rejected_instead_of_ignored(self):
        with self.assertRaisesRegex(ValueError, "require --relay-interface"):
            relay_config_or_none(args(relay_hard_timeout_ms=500))

    def test_timeout_with_interfaces_is_applied(self):
        config = relay_config_or_none(args(
            relay_interfaces=["vr0", "vr1"],
            relay_hard_timeout_ms=500,
            relay_quiet_timeout_ms=200,
        ))
        self.assertEqual(config.enabled_interfaces, ("vr0", "vr1"))
        self.assertEqual(config.discovery_hard_timeout_ms, 500)
        self.assertEqual(config.discovery_quiet_timeout_ms, 200)


class OneShotPrngTests(unittest.TestCase):
    def test_forces_exactly_one_session_id(self):
        class Fallback:
            def randint(self, lower, upper):
                self.bounds = (lower, upper)
                return 91

        fallback = Fallback()
        prng = _OneShotPrng(77, fallback)
        self.assertEqual(prng.randint(0, 100), 77)
        self.assertEqual(prng.randint(0, 100), 91)
        self.assertEqual(fallback.bounds, (0, 100))

    def test_rejects_out_of_range_forced_id(self):
        with self.assertRaisesRegex(ValueError, "outside allocator range"):
            _OneShotPrng(101, None).randint(0, 100)


if __name__ == "__main__":
    unittest.main()
