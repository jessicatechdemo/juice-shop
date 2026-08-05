import argparse
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "jira_writeback.py"
SPEC = importlib.util.spec_from_file_location("jira_writeback", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
jira_writeback = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(jira_writeback)


class JiraWritebackTest(unittest.TestCase):
    def finding(self, number=7, verdict="confirmed", severity="high"):
        references = [
            f"https://github.com/example/repo/security/code-scanning/{number}",
            f"codeql-security-severity:{severity}",
        ]
        return {
            "affected_locations": [
                {"label": "sink", "path": "routes/example.ts", "lines": "12-12"}
            ],
            "confidence": "high",
            "counterevidence": ["No sanitizer was found."],
            "evidence": ["Request data reaches the sink."],
            "fix_finding_handoff": (
                f"Use $codex-security:fix-finding for github-codeql-alert-{number}."
                if verdict == "confirmed"
                else None
            ),
            "input_id": f"github-codeql-alert-{number}",
            "normalized_input": {"references": references},
            "proof_gaps": ["Runtime verification remains."],
            "recommended_next_step": (
                "fix-finding" if verdict == "confirmed" else "manual-review"
            ),
            "source_type": "sarif",
            "title": "SQL injection in routes/example.ts",
            "triage_item_id": f"triage-{number:03d}",
            "verdict": verdict,
        }

    def context(self):
        return {
            "site": "https://example.atlassian.net",
            "account_id": "account-1",
            "display_name": "Example User",
            "project_key": "SEC",
            "project_id": "10000",
            "project_name": "Security",
            "issue_type_id": "10001",
            "issue_type_name": "Task",
            "priorities": [
                {"id": "1", "name": "Highest"},
                {"id": "2", "name": "High"},
                {"id": "3", "name": "Medium"},
                {"id": "4", "name": "Low"},
            ],
            "permissions": list(jira_writeback.JIRA_PERMISSIONS),
        }

    def test_security_severity_and_priority_mapping(self):
        finding = self.finding(severity="critical")
        severity = jira_writeback.codeql_security_severity(finding)
        priority, source = jira_writeback.mapped_priority(
            severity, self.context()["priorities"]
        )

        self.assertEqual(severity, "critical")
        self.assertEqual(priority["name"], "Highest")
        self.assertEqual(source, "codeql_security_severity_critical_fallback")

    def test_missing_security_severity_uses_jira_default(self):
        finding = self.finding()
        finding["normalized_input"]["references"] = [
            "severity:error",
            "https://github.com/example/repo/security/code-scanning/7",
        ]

        severity = jira_writeback.codeql_security_severity(finding)
        priority, source = jira_writeback.mapped_priority(
            severity, self.context()["priorities"]
        )

        self.assertIsNone(severity)
        self.assertIsNone(priority)
        self.assertEqual(source, "jira_default")

    def test_subprocess_environment_removes_jira_credentials(self):
        with patch.dict(
            jira_writeback.os.environ,
            {
                "JIRA_BASE_URL": "https://example.atlassian.net",
                "JIRA_USER_EMAIL": "user@example.com",
                "JIRA_API_TOKEN": "secret-token",
                "SAFE_VALUE": "retained",
            },
            clear=True,
        ):
            environment = jira_writeback.subprocess_environment()

        self.assertNotIn("JIRA_BASE_URL", environment)
        self.assertNotIn("JIRA_USER_EMAIL", environment)
        self.assertNotIn("JIRA_API_TOKEN", environment)
        self.assertEqual(environment["SAFE_VALUE"], "retained")

    def test_jira_errors_redact_email_and_token(self):
        client = jira_writeback.JiraClient(
            "https://example.atlassian.net", "user@example.com", "secret-token"
        )
        response = json.dumps(
            {"errorMessages": ["secret-token is invalid for user@example.com"]}
        ).encode()
        error = HTTPError(
            "https://example.atlassian.net/rest/api/3/myself",
            401,
            "Unauthorized",
            {},
            BytesIO(response),
        )
        with (
            patch.object(jira_writeback, "urlopen", side_effect=error),
            self.assertRaises(jira_writeback.JiraWritebackError) as raised,
        ):
            client.request("GET", "/rest/api/3/myself")

        message = str(raised.exception)
        self.assertNotIn("secret-token", message)
        self.assertNotIn("user@example.com", message)

    def test_description_omits_pr_when_not_supplied(self):
        finding = self.finding()
        description = jira_writeback.build_description(
            finding,
            "example/repo",
            "feature",
            "a" * 40,
            "security-results/triage/codeql/feature/report.html",
            "b" * 64,
            None,
            7,
            "https://github.com/example/repo/security/code-scanning/7",
            "c" * 64,
            "high",
            {"id": "2", "name": "High"},
            "codeql_security_severity",
            None,
        )

        self.assertNotIn("Pull request", description)
        self.assertIn("Finding ID: github-codeql-alert-7", description)
        self.assertIn(
            "Report path: security-results/triage/codeql/feature/report.html",
            description,
        )
        self.assertIn("Fix-finding handoff", description)

    def test_description_includes_only_explicit_verified_pr(self):
        finding = self.finding()
        pr = {
            "number": 42,
            "url": "https://github.com/example/repo/pull/42",
            "state": "open",
            "base_branch": "develop",
            "head_branch": "feature",
            "head_revision": "a" * 40,
        }
        description = jira_writeback.build_description(
            finding,
            "example/repo",
            "feature",
            "a" * 40,
            "report.html",
            "b" * 64,
            None,
            7,
            "https://github.com/example/repo/security/code-scanning/7",
            "c" * 64,
            "high",
            {"id": "2", "name": "High"},
            "codeql_security_severity",
            pr,
        )

        self.assertIn("### Pull request", description)
        self.assertIn("URL: https://github.com/example/repo/pull/42", description)

    def test_codex_description_contains_reciprocal_relationship_rationale(self):
        codex = {
            "documentType": "codex-security.findings",
            "scanId": "scan-1",
            "findings": [
                {
                    "findingId": "csf-1",
                    "title": "Codex finding",
                    "summary": "Validated summary",
                    "locations": [],
                    "severity": {"level": "medium"},
                    "validation": {
                        "evidence": ["Validated evidence"],
                        "counterEvidence": [],
                    },
                }
            ],
        }
        finding = jira_writeback.validate_codex_findings(codex)[0]
        relationship = {
            "relationship_id": "rel-1",
            "classification": "exact_overlap",
            "counterpart_finding_ids": ["github-codeql-alert-7"],
            "same_source": True,
            "same_failed_control": True,
            "same_sink": True,
            "same_precondition": True,
            "same_impact": True,
            "rationale": "Both scanners identified the same data flow.",
        }

        description = jira_writeback.build_description(
            finding,
            "example/repo",
            "master",
            "a" * 40,
            "report.html",
            "b" * 64,
            None,
            0,
            "Codex Security scan scan-1",
            "c" * 64,
            "medium",
            {"id": "3", "name": "Medium"},
            "codex_security_severity",
            None,
            "codex_security",
            relationship,
        )

        self.assertIn("## Codex Security finding", description)
        self.assertIn("Relationship ID: rel-1", description)
        self.assertIn("github-codeql-alert-7", description)
        self.assertIn("Both scanners identified the same data flow.", description)

    def test_update_comment_contains_only_changed_fields(self):
        previous = {
            "status": "needs_review",
            "evidence": ["old"],
            "confidence": "high",
        }
        current = {
            "status": "confirmed",
            "evidence": ["new"],
            "confidence": "high",
        }
        changes = jira_writeback.changed_fields(previous, current)
        comment, fingerprint = jira_writeback.build_update_comment(
            "github-codeql-alert-7",
            "a" * 40,
            "report.html",
            previous["status"],
            current["status"],
            changes,
        )

        self.assertEqual(set(changes), {"status", "evidence"})
        self.assertNotIn("confidence", comment)
        self.assertIn("## [Update]", comment)
        self.assertIn(f"Update fingerprint: {fingerprint}", comment)

    def test_relationship_comment_and_link_readback_are_reciprocal(self):
        operation = {
            "relationship_id": "rel-1",
            "relationship_fingerprint": "f" * 64,
            "classification": "exact_overlap",
            "rationale": "Both scanners found the same source, control and sink.",
        }
        comment = jira_writeback.relationship_comment(
            operation, "csf-1", "SEC-2"
        )
        issue = {
            "fields": {
                "issuelinks": [
                    {"outwardIssue": {"key": "SEC-2"}}
                ]
            }
        }

        self.assertIn("Relationship ID: rel-1", comment)
        self.assertIn("Related Jira Task: SEC-2", comment)
        self.assertIn("Both scanners found", comment)
        self.assertTrue(jira_writeback.issue_has_link(issue, "SEC-2"))
        self.assertFalse(jira_writeback.issue_has_link(issue, "SEC-3"))

    def test_labels_preserve_unowned_values_and_replace_triage_status(self):
        labels = jira_writeback.labels_for(
            "confirmed", ["team-security", "triage-needs-review", "codex-codeql"]
        )

        self.assertEqual(
            labels,
            [
                "codex-codeql",
                "scanner-codeql",
                "team-security",
                "triage-confirmed",
            ],
        )

    def test_html_is_authoritative_plan_without_credentials(self):
        plan = {
            "schema_version": jira_writeback.PREVIEW_SCHEMA,
            "jira": self.context(),
            "finding_count": 1,
            "technical_batch_count": 1,
            "items": [
                {
                    "verdict": "confirmed",
                    "action": "create",
                    "summary": "[CodeQL][#7] Example",
                    "finding_id": "github-codeql-alert-7",
                    "technical_batch": 1,
                    "description": "Finding ID: github-codeql-alert-7\n",
                    "update_comment": None,
                    "create_fields": {},
                    "field_updates": {},
                }
            ],
        }
        content, token = jira_writeback.render_preview(plan)

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "preview.html"
            path.write_bytes(content)
            decoded, decoded_token = jira_writeback.read_preview(path)

        self.assertEqual(decoded, plan)
        self.assertEqual(decoded_token, token)
        self.assertNotIn(b"JIRA_API_TOKEN", content)
        self.assertNotIn(b"secret-token", content)

    def test_html_visible_content_cannot_be_changed_after_preview(self):
        plan = {
            "schema_version": jira_writeback.PREVIEW_SCHEMA,
            "jira": self.context(),
            "finding_count": 0,
            "technical_batch_count": 0,
            "items": [],
        }
        content, _ = jira_writeback.render_preview(plan)
        altered = content.replace(b"Findings:</strong> 0", b"Findings:</strong> 1")

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "preview.html"
            path.write_bytes(altered)
            with self.assertRaisesRegex(
                jira_writeback.JiraWritebackError, "visible content"
            ):
                jira_writeback.read_preview(path)

    def test_all_findings_share_one_preview_and_use_technical_batches(self):
        revision = "a" * 40
        findings = [
            self.finding(number, "not_actionable", "medium")
            for number in range(1, 60)
        ]
        triage = {
            "schema_version": jira_writeback.TRIAGE_SCHEMA,
            "repository": {"revision": revision},
            "findings": findings,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            triage_path = root / "current.json"
            report_path = root / "report.html"
            preview_path = root / "jira-tracking" / "preview.html"
            triage_path.write_bytes(jira_writeback.json_bytes(triage))
            report_path.write_text("<html></html>")
            with (
                patch.object(jira_writeback, "repo_root", return_value=root),
                patch.object(
                    jira_writeback,
                    "git_value",
                    side_effect=["feature", revision],
                ),
                patch.object(
                    jira_writeback,
                    "jira_context",
                    return_value=self.context(),
                ),
                patch.object(jira_writeback, "validate_pr", return_value=None),
                patch.object(jira_writeback, "find_issue", return_value=None),
            ):
                plan = jira_writeback.build_plan(
                    triage_path=triage_path,
                    report_path=report_path,
                    repository="example/repo",
                    branch="feature",
                    site="https://example.atlassian.net",
                    project_key="SEC",
                    issue_type="Task",
                    pr_url=None,
                    preview_path=preview_path,
                    audience_approved=True,
                    client=object(),
                )

        self.assertEqual(plan["finding_count"], 59)
        self.assertEqual(plan["technical_batch_count"], 3)
        self.assertEqual(plan["items"][0]["technical_batch"], 1)
        self.assertEqual(plan["items"][25]["technical_batch"], 2)
        self.assertEqual(plan["items"][50]["technical_batch"], 3)
        self.assertTrue(all(item["action"] == "create" for item in plan["items"]))

    def test_plan_command_writes_only_html_plan(self):
        fake_plan = {
            "schema_version": jira_writeback.PREVIEW_SCHEMA,
            "jira": self.context(),
            "finding_count": 0,
            "technical_batch_count": 0,
            "items": [],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "preview.html"
            args = argparse.Namespace(
                site="https://example.atlassian.net",
                triage="current.json",
                report="report.html",
                repository="example/repo",
                branch="feature",
                project="SEC",
                issue_type="Task",
                pr_url=None,
                output=str(output_path),
                audience_approved=True,
            )
            with (
                patch.object(
                    jira_writeback.JiraClient,
                    "from_environment",
                    return_value=object(),
                ),
                patch.object(jira_writeback, "build_plan", return_value=fake_plan),
                redirect_stdout(io.StringIO()),
            ):
                result = jira_writeback.plan_command(args)

            files = [path.name for path in Path(temporary_directory).iterdir()]

        self.assertEqual(result, 0)
        self.assertEqual(files, ["preview.html"])

    def test_apply_creates_task_and_verifies_readback(self):
        finding = self.finding()
        priority = {"id": "2", "name": "High"}
        description = jira_writeback.build_description(
            finding,
            "example/repo",
            "feature",
            "a" * 40,
            "report.html",
            "b" * 64,
            None,
            7,
            "https://github.com/example/repo/security/code-scanning/7",
            "c" * 64,
            "high",
            priority,
            "codeql_security_severity",
            None,
        )
        item = {
            "finding_id": finding["input_id"],
            "finding_fingerprint": "c" * 64,
            "verdict": "confirmed",
            "technical_batch": 1,
            "summary": "[CodeQL][#7] SQL injection in routes/example.ts",
            "description": description,
            "action": "create",
            "issue_key": None,
            "issue_url": None,
            "snapshot": {
                "jira_priority": "High",
                "priority_source": "codeql_security_severity",
            },
            "create_fields": {
                "project": {"key": "SEC"},
                "issuetype": {"id": "10001"},
                "summary": "[CodeQL][#7] SQL injection in routes/example.ts",
                "description": jira_writeback.adf_document(description),
                "labels": ["codex-codeql", "triage-confirmed"],
                "priority": {"id": "2"},
            },
            "field_updates": {},
            "update_comment": None,
            "update_fingerprint": None,
            "last_update_fingerprint": None,
        }
        plan = {
            "schema_version": jira_writeback.PREVIEW_SCHEMA,
            "jira": self.context(),
            "repository": "example/repo",
            "branch": "feature",
            "revision": "a" * 40,
            "triage_path": "current.json",
            "triage_sha256": "d" * 64,
            "report_path": "report.html",
            "report_sha256": "b" * 64,
            "report_url": None,
            "pull_request": None,
            "finding_count": 1,
            "technical_batch_count": 1,
            "items": [item],
        }

        class FakeClient:
            def request(self, method, path, body=None):
                if method == "POST" and path == "/rest/api/3/issue":
                    return {"key": "SEC-1"}
                raise AssertionError((method, path, body))

        issue = {
            "fields": {
                "summary": item["summary"],
                "description": item["create_fields"]["description"],
                "labels": item["create_fields"]["labels"],
                "priority": {"name": "High"},
            }
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            preview_path = root / "preview.html"
            content, token = jira_writeback.render_preview(plan)
            preview_path.write_bytes(content)
            args = argparse.Namespace(preview=str(preview_path), approval_token=token)
            with (
                patch.object(
                    jira_writeback.JiraClient,
                    "from_environment",
                    return_value=FakeClient(),
                ),
                patch.object(jira_writeback, "repo_root", return_value=root),
                patch.object(jira_writeback, "build_plan", return_value=plan),
                patch.object(jira_writeback, "get_issue", return_value=issue),
                redirect_stdout(io.StringIO()),
            ):
                result = jira_writeback.apply_command(args)

            receipt = json.loads(
                (root / "receipts" / "current.json").read_text()
            )

        self.assertEqual(result, 0)
        self.assertTrue(receipt["complete"])
        self.assertEqual(receipt["results"][0]["outcome"], "created")
        self.assertEqual(receipt["results"][0]["issue_key"], "SEC-1")

    def test_apply_adds_update_comment_and_verifies_fingerprint(self):
        update_fingerprint = "f" * 64
        comment = (
            "## [Update]\n\n"
            "Finding ID: github-codeql-alert-7\n\n"
            f"Update fingerprint: {update_fingerprint}\n"
        )
        item = {
            "finding_id": "github-codeql-alert-7",
            "finding_fingerprint": "c" * 64,
            "verdict": "confirmed",
            "technical_batch": 1,
            "summary": "[CodeQL][#7] Example",
            "description": "Finding ID: github-codeql-alert-7\n",
            "action": "comment",
            "issue_key": "SEC-1",
            "issue_url": "https://example.atlassian.net/browse/SEC-1",
            "snapshot": {
                "jira_priority": "Highest",
                "priority_source": "codeql_security_severity_critical_fallback",
            },
            "create_fields": {
                "labels": ["codex-codeql", "triage-confirmed"],
            },
            "field_updates": {
                "labels": ["codex-codeql", "triage-confirmed"],
                "priority": {"id": "1"},
            },
            "update_comment": comment,
            "update_fingerprint": update_fingerprint,
            "last_update_fingerprint": update_fingerprint,
        }
        plan = {
            "schema_version": jira_writeback.PREVIEW_SCHEMA,
            "jira": self.context(),
            "repository": "example/repo",
            "branch": "feature",
            "revision": "a" * 40,
            "triage_path": "current.json",
            "triage_sha256": "d" * 64,
            "report_path": "report.html",
            "report_sha256": "b" * 64,
            "report_url": None,
            "pull_request": None,
            "finding_count": 1,
            "technical_batch_count": 1,
            "items": [item],
        }

        class FakeClient:
            def request(self, method, path, body=None):
                if method == "PUT":
                    return None
                if method == "POST" and path.endswith("/comment"):
                    return {"id": "10010"}
                raise AssertionError((method, path, body))

        issue = {
            "fields": {
                "summary": item["summary"],
                "description": jira_writeback.adf_document(
                    "Finding ID: github-codeql-alert-7\n"
                ),
                "labels": item["field_updates"]["labels"],
                "priority": {"name": "Highest"},
            }
        }
        comments = [{"body": jira_writeback.adf_document(comment)}]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            preview_path = root / "preview.html"
            content, token = jira_writeback.render_preview(plan)
            preview_path.write_bytes(content)
            args = argparse.Namespace(preview=str(preview_path), approval_token=token)
            with (
                patch.object(
                    jira_writeback.JiraClient,
                    "from_environment",
                    return_value=FakeClient(),
                ),
                patch.object(jira_writeback, "repo_root", return_value=root),
                patch.object(jira_writeback, "build_plan", return_value=plan),
                patch.object(jira_writeback, "get_issue", return_value=issue),
                patch.object(jira_writeback, "get_comments", return_value=comments),
                redirect_stdout(io.StringIO()),
            ):
                jira_writeback.apply_command(args)

            receipt = json.loads(
                (root / "receipts" / "current.json").read_text()
            )

        self.assertEqual(receipt["results"][0]["outcome"], "commented")
        self.assertEqual(receipt["results"][0]["comment_id"], "10010")


if __name__ == "__main__":
    unittest.main()
