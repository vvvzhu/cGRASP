# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_response_retransmit_pcaps import validate_logs


class ResponseRetransmitCheckerTests(unittest.TestCase):
    def write_result(self, directory: Path, name: str, result: dict) -> Path:
        path = directory / name
        path.write_text(json.dumps({"event": "result", **result}) + "\n", encoding="utf-8")
        return path

    def test_drop_ack_accepts_transport_layer_duplicate_suppression(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            r2 = self.write_result(directory, "r2.log", {
                "counters": {
                    "response_received": 1,
                    "accepted": 1,
                    "response_forwarded": 1,
                },
                "audit": {},
                "remaining_transactions": 0,
            })
            initiator = self.write_result(
                directory, "initiator.log", {"ok": True, "locators": 1})
            errors, evidence = validate_logs("drop-ack", r2, initiator)
            self.assertEqual(errors, [])
            self.assertIn("duplicate_suppressed_below_cgrasp=true", evidence)

    def test_drop_ack_accepts_cgrasp_layer_duplicate_suppression(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            r2 = self.write_result(directory, "r2.log", {
                "counters": {
                    "response_received": 2,
                    "accepted": 1,
                    "response_forwarded": 1,
                    "response_duplicate_dropped": 1,
                },
                "audit": {},
                "remaining_transactions": 0,
            })
            initiator = self.write_result(
                directory, "initiator.log", {"ok": True, "locators": 1})
            errors, _evidence = validate_logs("drop-ack", r2, initiator)
            self.assertEqual(errors, [])

    def test_drop_ack_rejects_unaccounted_duplicate(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            r2 = self.write_result(directory, "r2.log", {
                "counters": {
                    "response_received": 2,
                    "accepted": 1,
                    "response_forwarded": 1,
                },
                "audit": {},
                "remaining_transactions": 0,
            })
            errors, _evidence = validate_logs("drop-ack", r2, None)
            self.assertTrue(any("dropped only 0 duplicate" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
