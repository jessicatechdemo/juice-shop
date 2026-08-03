import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "codeql_clean_reset.py"
SPEC = importlib.util.spec_from_file_location("codeql_clean_reset", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
reset = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reset)


class CodeQLCleanResetTest(unittest.TestCase):
    def plan(self):
        return {
            "schema_version": reset.PLAN_SCHEMA,
            "repository": "example/repo",
            "branch": "feature",
            "workflow": "codeql-analysis.yml",
            "created_at": "20260803T000000.000000Z",
            "source_receipt_path": "receipt.json",
            "source_receipt_sha256": "a" * 64,
            "alerts": [
                {
                    "alert_number": number,
                    "expected_state": "dismissed",
                    "expected_reason": "false positive",
                    "expected_comment": f"Codex triage alert {number}",
                    "current_state": "dismissed",
                }
                for number in (7, 8)
            ],
            "analysis": {
                "id": 123,
                "ref": "refs/heads/feature",
                "commit_sha": "b" * 40,
                "analysis_key": "workflow:analyze",
                "category": "workflow:analyze/language:javascript",
                "created_at": "2026-08-03T00:00:00Z",
                "results_count": 2,
                "deletable": True,
            },
            "workflow_run": {
                "databaseId": 456,
                "headSha": "b" * 40,
                "status": "completed",
                "conclusion": "success",
            },
        }

    def test_apply_reopens_before_delete_and_rerun(self):
        plan = self.plan()
        operations = []

        def fake_api(method, endpoint, body=None):
            operations.append((method, endpoint, body))
            return {}

        def fake_validate(repository, expected, required_state):
            return {"number": expected["alert_number"], "state": required_state}

        def fake_command(command):
            operations.append(("COMMAND", " ".join(command), None))
            return ""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            plan_path = root / "plan.json"
            raw = reset.json_bytes(plan)
            plan_path.write_bytes(raw)
            args = argparse.Namespace(
                plan=str(plan_path),
                approval_token=hashlib.sha256(raw).hexdigest(),
                receipt_root=str(root / "receipts"),
            )
            with (
                patch.object(reset, "codeql_analyses", return_value=[plan["analysis"]]),
                patch.object(
                    reset,
                    "preflight_reset_alert",
                    return_value=("dismissed", {"state": "dismissed"}),
                ),
                patch.object(reset, "validate_live_alert", side_effect=fake_validate),
                patch.object(reset, "gh_api", side_effect=fake_api),
                patch.object(reset, "run_command", side_effect=fake_command),
            ):
                result = reset.apply_plan(args)

            self.assertEqual(result, 0)
            mutating = [operation[0] for operation in operations]
            self.assertEqual(mutating, ["PATCH", "PATCH", "DELETE", "COMMAND"])
            self.assertIn("confirm_delete=true", operations[2][1])
            receipt = json.loads((root / "receipts" / "current.json").read_text())
            self.assertTrue(receipt["complete"])
            self.assertEqual(len(receipt["reopened_alerts"]), 2)

    def test_normalizes_open_state_from_branch_instance(self):
        alert = {
            "state": None,
            "dismissed_at": None,
            "most_recent_instance": {"state": "open"},
        }

        self.assertEqual(reset.normalized_alert_state(alert), "open")

    def test_preview_skips_already_open_alerts(self):
        plan = self.plan()
        plan["alerts"][0]["current_state"] = "open"
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "plan.json"
            plan_path.write_bytes(reset.json_bytes(plan))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                reset.preview_plan(argparse.Namespace(plan=str(plan_path)))

        preview = json.loads(output.getvalue())
        self.assertEqual(preview["already_open_alerts"], [7])
        self.assertEqual(len(preview["reopen_requests"]), 1)
        self.assertTrue(preview["reopen_requests"][0]["endpoint"].endswith("/8"))


if __name__ == "__main__":
    unittest.main()
