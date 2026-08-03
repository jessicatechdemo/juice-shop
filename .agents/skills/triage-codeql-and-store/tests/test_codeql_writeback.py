import argparse
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "codeql_writeback.py"
SPEC = importlib.util.spec_from_file_location("codeql_writeback", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
codeql_writeback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codeql_writeback)


class CodeQLWritebackTest(unittest.TestCase):
    def item(self):
        return {
            "alert_number": 7,
            "alert_url": "https://github.com/example/repo/security/code-scanning/7",
            "triage_item_id": "triage-7",
            "input_id": "alert-7",
            "title": "Example alert",
            "verdict": "not_actionable",
            "confidence": 0.95,
            "action": "request_dismissal",
            "selected": True,
            "dismissed_reason": "false positive",
            "dismissed_comment": (
                "Codex triage verdict: not_actionable\n"
                "GitHub disposition: false positive\n"
                "Triage item: triage-7"
            ),
            "summary": "The data flow is sanitized before the sink.",
        }

    def request(self, item):
        return {
            "id": 21,
            "number": 42,
            "request_type": "code_scanning_alert_dismissal",
            "status": "open",
            "data": [
                {
                    "reason": item["dismissed_reason"],
                    "alert_number": item["alert_number"],
                }
            ],
            "requester_comment": item["dismissed_comment"],
            "requester": {"actor_name": "requester"},
            "created_at": "2026-08-03T00:00:00Z",
            "expires_at": None,
            "url": "https://api.github.com/example/request/7",
            "html_url": item["alert_url"],
        }

    def plan(self, item):
        return {
            "schema_version": codeql_writeback.PLAN_SCHEMA,
            "repository": "example/repo",
            "branch": "feature",
            "triage_revision": "a" * 40,
            "triage_path": "current.json",
            "triage_sha256": "b" * 64,
            "created_at": "20260803T000000.000000Z",
            "write_mode": codeql_writeback.WRITE_MODE,
            "items": [item],
        }

    def alert(self):
        return {
            "number": 7,
            "html_url": "https://github.com/example/repo/security/code-scanning/7",
            "state": "open",
            "dismissed_at": None,
            "dismissed_reason": None,
            "dismissed_comment": None,
            "most_recent_instance": {
                "state": "open",
                "ref": "refs/heads/feature",
                "commit_sha": "a" * 40,
            },
        }

    def test_direct_dismissal_plan_is_rejected(self):
        plan = self.plan(self.item())
        plan["write_mode"] = "direct_dismissal"

        with self.assertRaisesRegex(
            codeql_writeback.WritebackError, "direct dismissal is disabled"
        ):
            codeql_writeback.validate_plan(plan, require_selection=True)

    def test_apply_submits_and_verifies_open_request(self):
        item = self.item()
        plan = self.plan(item)
        alert = self.alert()
        request = self.request(item)
        calls = []

        def fake_gh_api(method, endpoint, body=None):
            calls.append((method, endpoint, body))
            if endpoint.startswith(
                "repos/example/repo/dismissal-requests/code-scanning?"
            ):
                return []
            if endpoint.startswith("repos/example/repo/code-scanning/alerts?"):
                return [alert]
            if method == "PATCH":
                return alert
            if endpoint == "repos/example/repo/code-scanning/alerts/7":
                return alert
            if endpoint == (
                "repos/example/repo/dismissal-requests/code-scanning/7"
            ):
                return request
            self.fail(f"unexpected GitHub API call: {method} {endpoint}")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            plan_path = root / "plan.json"
            raw = codeql_writeback.json_bytes(plan)
            plan_path.write_bytes(raw)
            args = argparse.Namespace(
                plan=str(plan_path),
                approval_token=hashlib.sha256(raw).hexdigest(),
                receipt_root=str(root / "receipts"),
            )

            with patch.object(codeql_writeback, "gh_api", side_effect=fake_gh_api):
                result = codeql_writeback.apply_plan(args)

            self.assertEqual(result, 0)
            patch_calls = [call for call in calls if call[0] == "PATCH"]
            self.assertEqual(len(patch_calls), 1)
            self.assertTrue(patch_calls[0][2]["create_request"])

            receipt = json.loads((root / "receipts" / "current.json").read_text())
            self.assertTrue(receipt["complete"])
            self.assertEqual(receipt["results"][0]["outcome"], "request_submitted")
            self.assertEqual(receipt["results"][0]["state_after"], "open")
            self.assertEqual(
                receipt["results"][0]["dismissal_request"]["status"], "open"
            )


if __name__ == "__main__":
    unittest.main()
