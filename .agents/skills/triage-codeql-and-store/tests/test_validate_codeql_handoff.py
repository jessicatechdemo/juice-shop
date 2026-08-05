import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "validate_codeql_handoff.py"
SPEC = importlib.util.spec_from_file_location("validate_codeql_handoff", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
validate_codeql_handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_codeql_handoff)


class ValidateCodeqlHandoffTest(unittest.TestCase):
    def write_json(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def digest(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_branch_handoff(self, root, branch="master"):
        revision = "c" * 40
        intake = {
            "schema_version": "codeql-branch-intake/v1",
            "repository": "example/repo",
            "local_repository": "/repo",
            "branch": branch,
            "ref": f"refs/heads/{branch}",
            "revision": revision,
            "alerts_endpoint": (
                "/repos/example/repo/code-scanning/alerts?state=open&"
                f"ref=refs%2Fheads%2F{branch}&tool_name=CodeQL&per_page=100"
            ),
            "expected_count": 1,
            "alerts": [
                {
                    "alert": {
                        "number": 9,
                        "state": "open",
                        "tool": {"name": "CodeQL"},
                        "rule": {"security_severity_level": "critical"},
                    },
                    "matching_instances": [
                        {
                            "ref": f"refs/heads/{branch}",
                            "commit_sha": revision,
                        }
                    ],
                }
            ],
        }
        triage = {
            "schema_version": "triage-finding/v0",
            "repository": {"path": "/repo", "revision": revision},
            "findings": [
                {
                    "triage_item_id": "triage-009",
                    "input_id": "github-codeql-alert-9",
                    "source_type": "sarif",
                    "verdict": "confirmed",
                    "confidence": "high",
                    "normalized_input": {
                        "references": [
                            "https://github.com/example/repo/security/code-scanning/9",
                            f"ref:refs/heads/{branch}",
                            f"commit:{revision}",
                            "codeql-security-severity:critical",
                        ]
                    },
                    "evidence": [],
                    "counterevidence": [],
                    "proof_gaps": [],
                    "boundary_assessment": {},
                    "exploitability_stack_rank": {},
                }
            ],
        }
        self.write_json(root / "intake.json", intake)
        self.write_json(root / "current.json", triage)
        codex = {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": "scan-1",
            "findings": [],
        }
        self.write_json(root / "codex-findings.json", codex)
        self.write_json(
            root / "codex-scan-metadata.json",
            {
                "schema_version": "codex-security-scan-metadata/v1",
                "revision": revision,
                "scan_id": "scan-1",
                "status": "complete",
                "finding_count": 0,
                "findings_sha256": self.digest(root / "codex-findings.json"),
            },
        )
        self.write_json(
            root / "relationships.json",
            {
                "schema_version": "security-relationships/v1",
                "repository": {"revision": revision},
                "relationships": [
                    {
                        "relationship_id": "rel-9",
                        "status": "proposed",
                        "classification": "no_candidate",
                        "codeql_finding_id": "github-codeql-alert-9",
                        "codex_finding_ids": [],
                        "same_source": None,
                        "same_failed_control": None,
                        "same_sink": None,
                        "same_precondition": None,
                        "same_impact": None,
                        "rationale": "No Codex Security candidate was found.",
                        "evidence": [],
                        "human_review_required": True,
                    }
                ],
                "codex_finding_accounting": [],
            },
        )
        (root / "report.html").write_text("<html></html>\n", encoding="utf-8")
        (root / "summary.md").write_text("summary\n", encoding="utf-8")
        self.write_json(
            root / "persist-receipt.json",
            {
                "sha256": self.digest(root / "current.json"),
                "stored_result_count": 1,
            },
        )
        self.write_json(
            root / "report-receipt.json",
            {
                "sha256": self.digest(root / "report.html"),
                "finding_count": 1,
                "codex_finding_count": 0,
                "relationship_count": 1,
            },
        )
        files = {
            name: self.digest(root / name)
            for name in (
                "intake.json",
                "current.json",
                "codex-findings.json",
                "codex-scan-metadata.json",
                "relationships.json",
                "report.html",
                "summary.md",
                "persist-receipt.json",
                "report-receipt.json",
            )
        }
        self.write_json(
            root / "metadata.json",
            {
                "schema_version": "codeql-jira-branch-handoff/v1",
                "scope": "branch",
                "repository": "example/repo",
                "branch": branch,
                "ref": f"refs/heads/{branch}",
                "revision": revision,
                "source_workflow": "CodeQL Scheduled Scan",
                "source_event": "schedule",
                "source_run_id": 1234,
                "source_run_attempt": 1,
                "files": files,
            },
        )

    def test_validates_bound_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision = "a" * 40
            base_revision = "b" * 40
            intake = {
                "schema_version": "codeql-pr-intake/v1",
                "repository": "example/repo",
                "local_repository": "/repo",
                "branch": "feature/current",
                "ref": "refs/heads/feature/current",
                "revision": revision,
                "base_revision": base_revision,
                "pull_request_number": 42,
                "alerts_endpoint": (
                    "/repos/example/repo/code-scanning/alerts?pr=42&"
                    "tool_name=CodeQL&state=open&per_page=100"
                ),
                "expected_count": 1,
                "alerts": [
                    {
                        "number": 7,
                        "state": "open",
                        "tool": {"name": "CodeQL"},
                        "rule": {"security_severity_level": "high"},
                    }
                ],
            }
            triage = {
                "schema_version": "triage-finding/v0",
                "repository": {"path": "/repo", "revision": revision},
                "findings": [
                    {
                        "triage_item_id": "triage-007",
                        "input_id": "github-codeql-alert-7",
                        "source_type": "sarif",
                        "verdict": "needs_review",
                        "confidence": "medium",
                        "normalized_input": {
                            "references": [
                                "https://github.com/example/repo/security/code-scanning/7",
                                "ref:refs/heads/feature/current",
                                f"commit:{revision}",
                                "codeql-security-severity:high",
                            ]
                        },
                        "evidence": [],
                        "counterevidence": [],
                        "proof_gaps": [],
                        "boundary_assessment": {},
                        "exploitability_stack_rank": {},
                    }
                ],
            }
            self.write_json(root / "intake.json", intake)
            self.write_json(root / "current.json", triage)
            (root / "report.html").write_text("<html></html>\n", encoding="utf-8")
            (root / "summary.md").write_text("summary\n", encoding="utf-8")
            self.write_json(
                root / "persist-receipt.json",
                {
                    "sha256": self.digest(root / "current.json"),
                    "stored_result_count": 1,
                },
            )
            self.write_json(
                root / "report-receipt.json",
                {
                    "sha256": self.digest(root / "report.html"),
                    "finding_count": 1,
                },
            )
            files = {
                name: self.digest(root / name)
                for name in (
                    "intake.json",
                    "current.json",
                    "report.html",
                    "summary.md",
                    "persist-receipt.json",
                    "report-receipt.json",
                )
            }
            self.write_json(
                root / "metadata.json",
                {
                    "schema_version": "codeql-jira-handoff/v1",
                    "repository": "example/repo",
                    "branch": "feature/current",
                    "ref": "refs/heads/feature/current",
                    "revision": revision,
                    "base_revision": base_revision,
                    "pull_request_number": 42,
                    "pull_request_url": "https://github.com/example/repo/pull/42",
                    "files": files,
                },
            )

            result = validate_codeql_handoff.validate(root, "example/repo")

            self.assertEqual(result["revision"], revision)
            self.assertEqual(result["pull_request_url"], "https://github.com/example/repo/pull/42")

    def test_validates_master_branch_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_branch_handoff(root)

            result = validate_codeql_handoff.validate(
                root,
                "example/repo",
                "CodeQL Scheduled Scan",
                "schedule",
                "1234",
            )

            self.assertEqual(result["scope"], "branch")
            self.assertEqual(result["branch"], "master")
            self.assertNotIn("pull_request_url", result)

    def test_rejects_scheduled_handoff_for_non_master_branch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_branch_handoff(root, "develop")

            with self.assertRaisesRegex(
                validate_codeql_handoff.HandoffError,
                "branch must be master",
            ):
                validate_codeql_handoff.validate(root, "example/repo")


if __name__ == "__main__":
    unittest.main()
