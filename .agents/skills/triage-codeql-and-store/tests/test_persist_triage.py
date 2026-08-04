import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "persist_triage.py"
SPEC = importlib.util.spec_from_file_location("persist_triage", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
persist_triage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(persist_triage)


class PersistTriageTest(unittest.TestCase):
    def intake(self):
        return {
            "schema_version": "codeql-branch-intake/v1",
            "repository": "example/repo",
            "local_repository": "/repo",
            "branch": "feature/current",
            "ref": "refs/heads/feature/current",
            "revision": "a" * 40,
            "alerts_endpoint": (
                "/repos/example/repo/code-scanning/alerts?state=open&"
                "ref=refs%2Fheads%2Ffeature%2Fcurrent&tool_name=CodeQL&per_page=100"
            ),
            "expected_count": 1,
            "alerts": [
                {
                    "alert": {
                        "number": 7,
                        "state": "open",
                        "tool": {"name": "CodeQL"},
                        "rule": {"security_severity_level": "high"},
                    },
                    "matching_instances": [
                        {
                            "ref": "refs/heads/feature/current",
                            "commit_sha": "a" * 40,
                        }
                    ],
                }
            ],
        }

    def payload(self):
        return {
            "schema_version": "triage-finding/v0",
            "repository": {"path": "/repo", "revision": "a" * 40},
            "findings": [
                {
                    "triage_item_id": "triage-007",
                    "input_id": "github-codeql-alert-7",
                    "source_type": "sarif",
                    "verdict": "confirmed",
                    "confidence": "high",
                    "normalized_input": {
                        "references": [
                            "https://github.com/example/repo/security/code-scanning/7",
                            "ref:refs/heads/feature/current",
                            f"commit:{'a' * 40}",
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

    def test_branch_intake_and_payload_align(self):
        payload = self.payload()
        count, intake_ref, commits = persist_triage.validate_intake(
            self.intake(), payload, "feature/current"
        )

        self.assertEqual(count, 1)
        persist_triage.validate_payload(payload, count)
        persist_triage.validate_payload_against_intake(
            payload, intake_ref, commits, self.intake()
        )

    def test_wrong_branch_is_rejected(self):
        with self.assertRaisesRegex(
            persist_triage.ValidationError, "does not match requested branch"
        ):
            persist_triage.validate_intake(
                self.intake(), self.payload(), "feature/other"
            )

    def test_wrong_finding_ref_is_rejected(self):
        payload = self.payload()
        payload["findings"][0]["normalized_input"]["references"][1] = (
            "ref:refs/heads/other"
        )
        _, intake_ref, commits = persist_triage.validate_intake(
            self.intake(), payload, "feature/current"
        )

        with self.assertRaisesRegex(
            persist_triage.ValidationError, "does not preserve current branch ref"
        ):
            persist_triage.validate_payload_against_intake(
                payload, intake_ref, commits
            )

    def test_security_severity_reference_must_match_intake(self):
        payload = self.payload()
        payload["findings"][0]["normalized_input"]["references"][-1] = (
            "codeql-security-severity:medium"
        )
        intake = self.intake()
        _, intake_ref, commits = persist_triage.validate_intake(
            intake, payload, "feature/current"
        )

        with self.assertRaisesRegex(
            persist_triage.ValidationError, "security severity reference"
        ):
            persist_triage.validate_payload_against_intake(
                payload, intake_ref, commits, intake
            )

    def test_finding_id_must_match_alert_number(self):
        payload = self.payload()
        payload["findings"][0]["input_id"] = "github-codeql-alert-8"
        intake = self.intake()
        _, intake_ref, commits = persist_triage.validate_intake(
            intake, payload, "feature/current"
        )

        with self.assertRaisesRegex(
            persist_triage.ValidationError, "input_id does not match alert"
        ):
            persist_triage.validate_payload_against_intake(
                payload, intake_ref, commits, intake
            )

    def test_missing_security_severity_requires_no_reference(self):
        intake = self.intake()
        intake["alerts"][0]["alert"]["rule"]["security_severity_level"] = None
        payload = self.payload()
        payload["findings"][0]["normalized_input"]["references"].pop()
        _, intake_ref, commits = persist_triage.validate_intake(
            intake, payload, "feature/current"
        )

        persist_triage.validate_payload_against_intake(
            payload, intake_ref, commits, intake
        )

    def test_pr_intake_and_payload_align(self):
        intake = {
            "schema_version": "codeql-pr-intake/v1",
            "repository": "example/repo",
            "local_repository": "/repo",
            "branch": "feature/current",
            "ref": "refs/heads/feature/current",
            "revision": "a" * 40,
            "base_revision": "b" * 40,
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

        count, intake_ref, commits = persist_triage.validate_intake(
            intake, self.payload(), "feature/current"
        )
        persist_triage.validate_payload_against_intake(
            self.payload(), intake_ref, commits, intake
        )

        self.assertEqual(count, 1)
        self.assertEqual(commits, {7: {"a" * 40}})


if __name__ == "__main__":
    unittest.main()
