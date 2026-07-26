import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "collect_hardware_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("collect_hardware_evidence", SCRIPT_PATH)
assert SPEC and SPEC.loader
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
SPEC.loader.exec_module(collector)


class ValidateTlsResultTests(unittest.TestCase):
    def test_accepts_completed_manual_schema_three_result(self):
        collector.validate_tls_result(
            {
                "schemaVersion": 3,
                "state": "completed",
                "trigger": "manual-http",
                "targetIp": "192.168.2.26",
                "tcpReachable": False,
                "tlsAttempted": False,
            },
            "192.168.2.26",
        )

    def test_rejects_stale_automatic_result(self):
        with self.assertRaisesRegex(
            collector.EvidenceError, "accepted manual run"
        ):
            collector.validate_tls_result(
                {
                    "schemaVersion": 3,
                    "state": "completed",
                    "trigger": "main-probe-complete",
                    "targetIp": "192.168.2.26",
                },
                "192.168.2.26",
            )

    def test_rejects_old_schema(self):
        with self.assertRaisesRegex(collector.EvidenceError, "older than version 3"):
            collector.validate_tls_result(
                {
                    "schemaVersion": 2,
                    "state": "completed",
                    "trigger": "manual-http",
                    "targetIp": "192.168.2.26",
                },
                "192.168.2.26",
            )

    def test_rejects_wrong_target(self):
        with self.assertRaisesRegex(collector.EvidenceError, "does not match"):
            collector.validate_tls_result(
                {
                    "schemaVersion": 3,
                    "state": "completed",
                    "trigger": "manual-http",
                    "targetIp": "192.168.2.99",
                },
                "192.168.2.26",
            )


class AtomicWriteTests(unittest.TestCase):
    def test_writes_parseable_json_and_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            output.write_text('{"old": true}\n', encoding="utf-8")

            collector.write_json_atomically(output, {"new": True, "count": 1})

            self.assertEqual(
                {"new": True, "count": 1},
                json.loads(output.read_text(encoding="utf-8")),
            )
            self.assertFalse((Path(directory) / ".evidence.json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
