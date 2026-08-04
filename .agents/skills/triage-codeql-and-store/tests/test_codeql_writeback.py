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

    def issue_body(self, verdict="confirmed"):
        return codeql_writeback.build_issue_body(
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
        issue_number = (
            17
            if action in {"comment", "update", "update_comment", "reuse"}
            else None
        )
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
            "issue_body": self.issue_body(verdict),
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
                "Comment destination: `GitHub tracking issue`", comment
            )
            self.assertIn(
                "Report path: `security-results/triage/codeql/feature/report.html`",
                comment,
            )
        self.assertIn("Fix-finding handoff:", self.comment("confirmed"))
        self.assertIn("$codex-security:fix-finding", self.comment("confirmed"))

    def test_issue_body_has_complete_triage_record_for_every_verdict(self):
        for verdict in ("confirmed", "needs_review", "not_actionable"):
            body = self.issue_body(verdict)
            self.assertIn(f"Status: `{verdict}`", body)
            self.assertIn("Finding ID: `github-codeql-alert-7`", body)
            self.assertIn("Triage item ID: `triage-007`", body)
            self.assertIn(
                "Report path: `security-results/triage/codeql/feature/report.html`",
                body,
            )
            self.assertIn("### Evidence", body)
            self.assertIn("### Counterevidence", body)
            self.assertIn("### Proof gaps", body)
            self.assertIn("### Recommended next step", body)
            self.assertIn("### Fix-finding handoff", body)
            self.assertIn("### Tracking information", body)
        self.assertIn("$codex-security:fix-finding", self.issue_body("confirmed"))
        self.assertIn("Not applicable.", self.issue_body("not_actionable"))

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
        self.assertEqual(preview["comment_destination"], "github_tracking_issue")
        self.assertFalse(preview["direct_alert_comments_supported"])
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
        self.assertNotIn("dismissed_comment", rendered)
        self.assertNotIn("create_request", rendered)
        self.assertEqual(preview["approval_token"], hashlib.sha256(raw).hexdigest())

    def test_preview_updates_legacy_issue_body_before_commenting(self):
        plan = self.plan(self.item(action="update_comment"))
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = Path(temporary_directory) / "plan.json"
            raw = codeql_writeback.json_bytes(plan)
            plan_path.write_bytes(raw)
            output = io.StringIO()
            with redirect_stdout(output):
                codeql_writeback.preview_plan(argparse.Namespace(plan=str(plan_path)))

        preview = json.loads(output.getvalue())
        self.assertEqual(preview["action_counts"]["update_comment"], 1)
        self.assertEqual(len(preview["requests"]), 2)
        self.assertEqual(preview["requests"][0]["command"][1:3], ["issue", "edit"])
        self.assertEqual(preview["requests"][1]["command"][1:3], ["issue", "comment"])

    def test_standalone_code_scanning_alert_comments_are_unsupported(self):
        self.assertFalse(codeql_writeback.DIRECT_ALERT_COMMENTS_SUPPORTED)
        self.assertEqual(codeql_writeback.WRITE_MODE, "github_issue_comment")

    def test_all_findings_are_batched_and_receipt_coverage_is_audited(self):
        revision = "a" * 40
        findings = []
        for number in range(1, 27):
            finding = self.finding()
            finding["input_id"] = f"github-codeql-alert-{number}"
            finding["triage_item_id"] = f"triage-{number:03d}"
            findings.append(finding)
        triage = {
            "schema_version": codeql_writeback.TRIAGE_SCHEMA,
            "repository": {"revision": revision},
            "findings": findings,
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            triage_path = root / "current.json"
            report_path = root / "report.html"
            manifest_path = root / "github-tracking" / "manifest.json"
            triage_path.write_bytes(codeql_writeback.json_bytes(triage))
            report_path.write_text("<html></html>")
            args = argparse.Namespace(
                triage=str(triage_path),
                report=str(report_path),
                repository="example/repo",
                branch="feature",
                output=str(manifest_path),
            )
            with (
                patch.object(codeql_writeback, "canonical_repo_root", return_value=root),
                patch.object(
                    codeql_writeback,
                    "git_value",
                    side_effect=["feature", revision],
                ),
                redirect_stdout(io.StringIO()),
            ):
                result = codeql_writeback.build_batch_manifest(args)

            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(result, 0)
            self.assertEqual(manifest["finding_count"], 26)
            self.assertEqual(manifest["batch_count"], 2)
            self.assertEqual(len(manifest["batches"][0]["finding_ids"]), 25)
            self.assertEqual(len(manifest["batches"][1]["finding_ids"]), 1)

            receipt_paths = []
            for batch in manifest["batches"]:
                receipt = {
                    "schema_version": codeql_writeback.RECEIPT_SCHEMA,
                    "repository": manifest["repository"],
                    "branch": manifest["branch"],
                    "triage_revision": manifest["triage_revision"],
                    "triage_sha256": manifest["triage_sha256"],
                    "report_path": manifest["report_path"],
                    "report_sha256": manifest["report_sha256"],
                    "complete": True,
                    "results": [
                        {
                            "finding_id": finding_id,
                            "issue_url": f"https://github.com/example/repo/issues/{index}",
                            "manual_link_required": True,
                            "outcome": "issue_created_and_commented",
                        }
                        for index, finding_id in enumerate(batch["finding_ids"], start=1)
                    ],
                }
                receipt_path = root / f"{batch['batch_id']}-receipt.json"
                receipt_path.write_bytes(codeql_writeback.json_bytes(receipt))
                receipt_paths.append(str(receipt_path))

            output = io.StringIO()
            with redirect_stdout(output):
                audit_result = codeql_writeback.audit_batch_coverage(
                    argparse.Namespace(
                        manifest=str(manifest_path), receipt=receipt_paths
                    )
                )

        audit = json.loads(output.getvalue())
        self.assertEqual(audit_result, 0)
        self.assertTrue(audit["complete"])
        self.assertEqual(audit["verified_issue_count"], 26)
        self.assertEqual(audit["manual_link_count"], 26)

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

    def test_apply_updates_legacy_issue_body_with_exact_readback(self):
        plan = self.plan(self.item(action="update"))
        updated_issue = {
            "number": 17,
            "url": "https://github.com/example/repo/issues/17",
            "title": plan["items"][0]["issue_title"],
            "body": plan["items"][0]["issue_body"],
            "comments": [],
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
                patch.object(codeql_writeback, "gh_with_body") as body_command,
                patch.object(
                    codeql_writeback,
                    "gh_issue_view",
                    return_value=updated_issue,
                ),
            ):
                codeql_writeback.apply_plan(args)

            receipt = json.loads((root / "receipts" / "current.json").read_text())

        self.assertEqual(body_command.call_count, 1)
        self.assertEqual(receipt["results"][0]["outcome"], "issue_updated")


if __name__ == "__main__":
    unittest.main()
