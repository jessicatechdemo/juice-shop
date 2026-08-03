import argparse
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "codeql_writeback.py"
SPEC = importlib.util.spec_from_file_location("codeql_writeback", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
codeql_writeback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codeql_writeback)


class CodeQLWritebackTest(unittest.TestCase):
    def finding(self, verdict="confirmed"):
        return {
            "affected_locations": [
                {
                    "detail": "scanner location",
                    "label": "sink",
                    "lines": "12-12",
                    "path": "routes/example.ts",
                }
            ],
            "confidence": "high",
            "counterevidence": ["No effective sanitizer was found."],
            "evidence": ["Request data reaches the sink."],
            "fix_finding_handoff": (
                "Use $codex-security:fix-finding for github-codeql-alert-7."
                if verdict == "confirmed"
                else None
            ),
            "input_id": "github-codeql-alert-7",
            "proof_gaps": ["Runtime verification remains."],
            "recommended_next_step": (
                "fix-finding" if verdict == "confirmed" else "manual-review"
            ),
            "source_type": "sarif",
            "title": "SQL injection in routes/example.ts",
            "triage_item_id": "triage-007",
            "verdict": verdict,
        }

    def comment(self, verdict="confirmed"):
        return codeql_writeback.build_comment(
            self.finding(verdict),
            "example/repo",
            "feature",
            "a" * 40,
            "security-results/triage/codeql/feature/report.html",
            7,
            "https://github.com/example/repo/security/code-scanning/7",
            "c" * 64,
        )

    def item(self, verdict="confirmed", action="create"):
        issue_number = 17 if action in {"comment", "reuse"} else None
        issue_url = (
            "https://github.com/example/repo/issues/17" if issue_number else None
        )
        return {
            "action": action,
            "alert_number": 7,
            "alert_url": "https://github.com/example/repo/security/code-scanning/7",
            "comment": self.comment(verdict),
            "finding_fingerprint": "c" * 64,
            "finding_id": "github-codeql-alert-7",
            "issue_body": (
                "Finding ID: `github-codeql-alert-7`\n"
                f"Finding fingerprint: `{'c' * 64}`\n"
            ),
            "issue_number": issue_number,
            "issue_title": f"[CodeQL][{verdict}][#7] Example",
            "issue_url": issue_url,
            "manual_link_required": True,
            "title": "Example",
            "triage_item_id": "triage-007",
            "verdict": verdict,
        }

    def plan(self, item=None):
        return {
            "branch": "feature",
            "created_at": "20260803T000000.000000Z",
            "github": {
                "host": "github.com",
                "login": "octocat",
                "repository": "example/repo",
                "repository_url": "https://github.com/example/repo",
                "viewer_permission": "WRITE",
                "visibility": "PUBLIC",
            },
            "items": [item or self.item()],
            "manual_link_required": True,
            "report_path": "security-results/triage/codeql/feature/report.html",
            "report_sha256": "d" * 64,
            "repository": "example/repo",
            "schema_version": codeql_writeback.PLAN_SCHEMA,
            "triage_path": "security-results/triage/codeql/feature/current.json",
            "triage_revision": "a" * 40,
            "triage_sha256": "b" * 64,
            "write_mode": codeql_writeback.WRITE_MODE,
        }

    def test_comment_has_status_finding_id_report_path_and_handoff(self):
        for verdict in ("confirmed", "needs_review", "not_actionable"):
            comment = self.comment(verdict)
            self.assertIn(f"Status: `{verdict}`", comment)
            self.assertIn("Finding ID: `github-codeql-alert-7`", comment)
            self.assertIn(
                "Report path: `security-results/triage/codeql/feature/report.html`",
                comment,
            )
        self.assertIn("Fix-finding handoff:", self.comment("confirmed"))
        self.assertIn("$codex-security:fix-finding", self.comment("confirmed"))

    def test_validate_plan_accepts_every_verdict(self):
        plan = self.plan()
        plan["items"] = [
            {**self.item(verdict, "create"), "alert_number": index}
            for index, verdict in enumerate(
                ("confirmed", "needs_review", "not_actionable"), start=1
            )
        ]
        for item in plan["items"]:
            item["comment"] = item["comment"].replace(
                "Status: `confirmed`", f"Status: `{item['verdict']}`"
            )

        validated = codeql_writeback.validate_plan(plan)

        self.assertEqual(len(validated), 3)

    def test_plan_rejects_more_than_twenty_five_findings(self):
        plan = self.plan()
        plan["items"] = []
        for number in range(1, 27):
            item = {**self.item(), "alert_number": number}
            plan["items"].append(item)

        with self.assertRaisesRegex(
            codeql_writeback.WritebackError, "cannot exceed 25"
        ):
            codeql_writeback.validate_plan(plan)

    def test_preview_contains_only_issue_posts_and_manual_link_notice(self):
        plan = self.plan()
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "plan.json"
            raw = codeql_writeback.json_bytes(plan)
            plan_path.write_bytes(raw)
            output = io.StringIO()
            with redirect_stdout(output):
                result = codeql_writeback.preview_plan(
                    argparse.Namespace(plan=str(plan_path))
                )

        preview = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertTrue(preview["manual_link_required"])
        self.assertEqual(len(preview["requests"]), 2)
        self.assertTrue(
            all(request["transport"] == "gh" for request in preview["requests"])
        )
        self.assertTrue(
            all(request["command"][0] == "gh" for request in preview["requests"])
        )
        self.assertTrue(
            all(
                request["command"][-2:] == [
                    "--body-file",
                    "<mode-0600-temporary-file>",
                ]
                for request in preview["requests"]
            )
        )
        rendered = json.dumps(preview)
        self.assertNotIn("dismissed_reason", rendered)
        self.assertNotIn("create_request", rendered)
        self.assertEqual(preview["approval_token"], hashlib.sha256(raw).hexdigest())

    def test_apply_creates_issue_then_adds_and_verifies_comment(self):
        plan = self.plan()
        issue_without_comment = {
            "number": 17,
            "url": "https://github.com/example/repo/issues/17",
            "title": plan["items"][0]["issue_title"],
            "body": plan["items"][0]["issue_body"],
            "comments": [],
        }
        issue_with_comment = {
            **issue_without_comment,
            "comments": [
                {
                    "url": "https://github.com/example/repo/issues/17#issuecomment-1",
                    "body": plan["items"][0]["comment"],
                }
            ],
        }

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
            with (
                patch.object(codeql_writeback, "canonical_repo_root", return_value=root),
                patch.object(codeql_writeback, "revalidate_plan"),
                patch.object(
                    codeql_writeback,
                    "gh_with_body",
                    side_effect=[
                        "https://github.com/example/repo/issues/17",
                        "https://github.com/example/repo/issues/17#issuecomment-1",
                    ],
                ) as body_command,
                patch.object(
                    codeql_writeback,
                    "gh_issue_view",
                    side_effect=[issue_without_comment, issue_with_comment],
                ),
            ):
                result = codeql_writeback.apply_plan(args)

            receipt = json.loads((root / "receipts" / "current.json").read_text())

        self.assertEqual(result, 0)
        self.assertTrue(receipt["complete"])
        self.assertEqual(
            receipt["results"][0]["outcome"], "issue_created_and_commented"
        )
        self.assertTrue(receipt["results"][0]["manual_link_required"])
        self.assertEqual(body_command.call_count, 2)

    def test_apply_reuses_identical_existing_comment_without_write(self):
        plan = self.plan(self.item(action="reuse"))
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
            with (
                patch.object(codeql_writeback, "canonical_repo_root", return_value=root),
                patch.object(codeql_writeback, "revalidate_plan"),
                patch.object(codeql_writeback, "gh_with_body") as body_command,
                patch.object(codeql_writeback, "gh_issue_view") as issue_view,
            ):
                codeql_writeback.apply_plan(args)

            receipt = json.loads((root / "receipts" / "current.json").read_text())

        body_command.assert_not_called()
        issue_view.assert_not_called()
        self.assertEqual(receipt["results"][0]["outcome"], "already_commented")


if __name__ == "__main__":
    unittest.main()
