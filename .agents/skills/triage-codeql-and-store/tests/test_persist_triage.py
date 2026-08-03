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
                "ref=refs%2Fheads%2Ffeature%2Fcurrent&per_page=100"
            ),
            "expected_count": 1,
            "alerts": [
                {
                    "alert": {"number": 7},
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
            payload, intake_ref, commits
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


if __name__ == "__main__":
    unittest.main()
