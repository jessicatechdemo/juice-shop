#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("evaluate_codex_security_gate.py")
SPEC = importlib.util.spec_from_file_location("evaluate_codex_security_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class EvaluateCodexSecurityGateTest(unittest.TestCase):
    def findings(self, *levels: str) -> dict:
        return {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": "scan-1",
            "findings": [
                {
                    "findingId": f"finding-{index}",
                    "title": f"Finding {index}",
                    "severity": {"level": level},
                }
                for index, level in enumerate(levels, start=1)
            ],
        }

    def test_empty_finding_set_passes(self) -> None:
        result = gate.evaluate(self.findings())

        self.assertEqual(result["decision"], "pass")
        self.assertEqual(result["warning_count"], 0)

    def test_non_blocking_findings_pass(self) -> None:
        result = gate.evaluate(self.findings("medium", "low", "informational"))

        self.assertEqual(result["decision"], "pass")
        self.assertEqual(result["finding_count"], 3)

    def test_high_and_critical_findings_warn(self) -> None:
        result = gate.evaluate(self.findings("high", "critical", "medium"))

        self.assertEqual(result["decision"], "warn")
        self.assertEqual(result["warning_count"], 2)
        self.assertEqual(
            [finding["finding_id"] for finding in result["warning_findings"]],
            ["finding-1", "finding-2"],
        )

    def test_unknown_severity_fails_closed(self) -> None:
        with self.assertRaisesRegex(gate.GateEvaluationError, "severity.level is invalid"):
            gate.evaluate(self.findings("unknown"))

    def test_malformed_document_fails_closed(self) -> None:
        with self.assertRaisesRegex(gate.GateEvaluationError, "documentType"):
            gate.evaluate({"documentType": "unexpected", "findings": []})


if __name__ == "__main__":
    unittest.main()
