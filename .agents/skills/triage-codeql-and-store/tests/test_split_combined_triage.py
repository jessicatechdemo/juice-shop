import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "split_combined_triage.py"
SPEC = importlib.util.spec_from_file_location("split_combined_triage", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
split_combined_triage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(split_combined_triage)


class SplitCombinedTriageTest(unittest.TestCase):
    revision = "a" * 40

    def intake(self):
        return {
            "schema_version": "codeql-branch-intake/v1",
            "repository": "example/repo",
            "local_repository": "/repo",
            "branch": "master",
            "ref": "refs/heads/master",
            "revision": self.revision,
            "alerts_endpoint": (
                "/repos/example/repo/code-scanning/alerts?state=open&"
                "ref=refs%2Fheads%2Fmaster&tool_name=CodeQL&per_page=100"
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
                        {"ref": "refs/heads/master", "commit_sha": self.revision}
                    ],
                }
            ],
        }

    def triage(self):
        return {
            "schema_version": "triage-finding/v0",
            "repository": {"path": "/repo", "revision": self.revision},
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
                            "ref:refs/heads/master",
                            f"commit:{self.revision}",
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

    def codex(self):
        return {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": "scan-1",
            "findings": [
                {
                    "findingId": "csf-1",
                    "title": "Related finding",
                    "summary": "Summary",
                    "locations": [],
                    "severity": {"level": "medium"},
                    "validation": {"evidence": []},
                }
            ],
        }

    def relationship(self, classification="exact_overlap"):
        return {
            "relationship_id": "rel-1",
            "status": "proposed",
            "classification": classification,
            "codeql_finding_id": "github-codeql-alert-7",
            "codex_finding_ids": ["csf-1"],
            "same_source": True,
            "same_failed_control": True,
            "same_sink": True,
            "same_precondition": True,
            "same_impact": True,
            "rationale": "The source, failed control, sink and impact match.",
            "evidence": ["routes/example.ts:12"],
            "human_review_required": True,
        }

    def write_fixture(self, root, name, value):
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run_split(self, combined):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        codex = self.codex()
        codex_path = self.write_fixture(root, "codex.json", codex)
        codex_raw = codex_path.read_bytes()
        metadata = {
            "schema_version": "codex-security-scan-metadata/v1",
            "revision": self.revision,
            "scan_id": "scan-1",
            "status": "complete",
            "finding_count": 1,
            "findings_sha256": hashlib.sha256(codex_raw).hexdigest(),
        }
        result = split_combined_triage.split(
            self.write_fixture(root, "combined.json", combined),
            self.write_fixture(root, "intake.json", self.intake()),
            codex_path,
            self.write_fixture(root, "metadata.json", metadata),
            self.revision,
            root / "triage.json",
            root / "relationships.json",
        )
        return result, root

    def test_splits_complete_exact_overlap(self):
        combined = {
            "schema_version": "combined-security-triage/v1",
            "codeql_triage": self.triage(),
            "relationships": [self.relationship()],
            "codex_finding_accounting": [
                {
                    "codex_finding_id": "csf-1",
                    "relationship_ids": ["rel-1"],
                    "status": "candidate",
                }
            ],
        }

        result, root = self.run_split(combined)

        self.assertEqual(result["codeql_finding_count"], 1)
        self.assertEqual(result["codex_finding_count"], 1)
        relationships = json.loads((root / "relationships.json").read_text())
        self.assertEqual(relationships["schema_version"], "security-relationships/v1")

    def test_exact_overlap_requires_all_identity_criteria(self):
        relationship = self.relationship()
        relationship["same_sink"] = False
        combined = {
            "schema_version": "combined-security-triage/v1",
            "codeql_triage": self.triage(),
            "relationships": [relationship],
            "codex_finding_accounting": [
                {
                    "codex_finding_id": "csf-1",
                    "relationship_ids": ["rel-1"],
                    "status": "candidate",
                }
            ],
        }

        with self.assertRaisesRegex(
            split_combined_triage.CombinedTriageError,
            "requires all identity criteria",
        ):
            self.run_split(combined)

    def test_every_codex_finding_must_be_accounted(self):
        combined = {
            "schema_version": "combined-security-triage/v1",
            "codeql_triage": self.triage(),
            "relationships": [self.relationship()],
            "codex_finding_accounting": [],
        }

        with self.assertRaisesRegex(
            split_combined_triage.CombinedTriageError,
            "does not cover Codex findings",
        ):
            self.run_split(combined)

    def test_zero_codeql_findings_still_accounts_for_codex(self):
        result = split_combined_triage.validate_relationships(
            {
                "relationships": [],
                "codex_finding_accounting": [
                    {
                        "codex_finding_id": "csf-1",
                        "relationship_ids": [],
                        "status": "no_candidate",
                    }
                ],
            },
            set(),
            {"csf-1"},
            self.revision,
        )

        self.assertEqual(result["relationships"], [])
        self.assertEqual(
            result["codex_finding_accounting"][0]["status"], "no_candidate"
        )

    def test_zero_codex_findings_allows_codeql_no_candidate(self):
        relationship = self.relationship("no_candidate")
        relationship["codex_finding_ids"] = []
        for criterion in (
            "same_source",
            "same_failed_control",
            "same_sink",
            "same_precondition",
            "same_impact",
        ):
            relationship[criterion] = None

        result = split_combined_triage.validate_relationships(
            {
                "relationships": [relationship],
                "codex_finding_accounting": [],
            },
            {"github-codeql-alert-7"},
            set(),
            self.revision,
        )

        self.assertEqual(result["relationships"][0]["classification"], "no_candidate")


if __name__ == "__main__":
    unittest.main()
