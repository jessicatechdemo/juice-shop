import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "evaluate_codeql_gate.py"
SPEC = importlib.util.spec_from_file_location("evaluate_codeql_gate", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
evaluate_codeql_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluate_codeql_gate)


class EvaluateCodeqlGateTest(unittest.TestCase):
    def intake(self, severities):
        alerts = [
            {
                "number": index,
                "state": "open",
                "tool": {"name": "CodeQL"},
                "rule": {"security_severity_level": severity},
            }
            for index, severity in enumerate(severities, 1)
        ]
        return {
            "schema_version": "codeql-pr-intake/v1",
            "expected_count": len(alerts),
            "alerts": alerts,
        }

    def triage(self, verdicts):
        return {
            "schema_version": "triage-finding/v0",
            "findings": [
                {
                    "input_id": f"github-codeql-alert-{index}",
                    "source_type": "sarif",
                    "verdict": verdict,
                }
                for index, verdict in enumerate(verdicts, 1)
            ],
        }

    def decision(self, severity, verdict):
        return evaluate_codeql_gate.evaluate(
            self.intake([severity]), self.triage([verdict])
        )["decision"]

    def test_confirmed_high_and_critical_block(self):
        self.assertEqual(self.decision("critical", "confirmed"), "block")
        self.assertEqual(self.decision("high", "confirmed"), "block")

    def test_needs_review_high_and_critical_block(self):
        self.assertEqual(self.decision("critical", "needs_review"), "block")
        self.assertEqual(self.decision("high", "needs_review"), "block")

    def test_not_actionable_high_and_critical_pass(self):
        self.assertEqual(self.decision("critical", "not_actionable"), "pass")
        self.assertEqual(self.decision("high", "not_actionable"), "pass")

    def test_medium_low_and_missing_security_severity_pass(self):
        for severity in ("medium", "low", None):
            for verdict in ("confirmed", "needs_review", "not_actionable"):
                with self.subTest(severity=severity, verdict=verdict):
                    self.assertEqual(self.decision(severity, verdict), "pass")

    def test_any_blocking_finding_blocks_the_result(self):
        result = evaluate_codeql_gate.evaluate(
            self.intake(["medium", "high", "critical"]),
            self.triage(["confirmed", "not_actionable", "needs_review"]),
        )

        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["blocking_count"], 1)
        self.assertEqual(result["blocking_findings"][0]["alert_number"], 3)

    def test_empty_alert_set_passes(self):
        result = evaluate_codeql_gate.evaluate(self.intake([]), self.triage([]))

        self.assertEqual(result["decision"], "pass")
        self.assertEqual(result["finding_count"], 0)

    def test_mismatched_alert_sets_are_rejected(self):
        with self.assertRaisesRegex(
            evaluate_codeql_gate.GateEvaluationError, "does not match intake"
        ):
            evaluate_codeql_gate.evaluate(
                self.intake(["high", "medium"]), self.triage(["confirmed"])
            )

    def test_non_codeql_alert_is_rejected(self):
        intake = self.intake(["high"])
        intake["alerts"][0]["tool"]["name"] = "Other"

        with self.assertRaisesRegex(
            evaluate_codeql_gate.GateEvaluationError, "not a CodeQL alert"
        ):
            evaluate_codeql_gate.evaluate(intake, self.triage(["confirmed"]))

    def test_non_sarif_triage_is_rejected(self):
        triage = self.triage(["confirmed"])
        triage["findings"][0]["source_type"] = "text"

        with self.assertRaisesRegex(
            evaluate_codeql_gate.GateEvaluationError, "source_type"
        ):
            evaluate_codeql_gate.evaluate(self.intake(["high"]), triage)


if __name__ == "__main__":
    unittest.main()
