import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "render_triage_report.py"
SPEC = importlib.util.spec_from_file_location("render_triage_report", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
render_triage_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render_triage_report)


class RenderTriageReportTest(unittest.TestCase):
    def finding(self, verdict, number):
        return {
            "triage_item_id": f"triage-{number}",
            "input_id": f"github-codeql-alert-{number}",
            "source_type": "sarif",
            "title": f"<script>alert({number})</script>",
            "normalized_input": {
                "vulnerable_component": "routes/example.ts",
                "references": [
                    "javascript:alert(1)//github.com/example/code-scanning/999",
                    f"https://github.com/example/repo/security/code-scanning/{number}",
                    "rule:js/example",
                ],
            },
            "verdict": verdict,
            "confidence": "high",
            "affected_locations": [
                {
                    "label": "sink",
                    "path": "routes/example.ts",
                    "lines": "10-12",
                    "detail": "Dangerous operation",
                }
            ],
            "boundary_assessment": {
                "product_surface": "hosted service",
                "source_trust": "untrusted",
                "boundary_crossed": verdict == "confirmed",
                "policy_basis": "SECURITY.md",
            },
            "exploitability_stack_rank": {
                "rank_queue": verdict if verdict != "not_actionable" else None,
                "rank": 1 if verdict != "not_actionable" else None,
                "rationale": "test",
                "drivers": [],
            },
            "evidence": ["Static evidence"],
            "counterevidence": [],
            "proof_gaps": [],
            "recommended_next_step": "manual-review",
            "fix_finding_handoff": None,
        }

    def payload(self):
        return {
            "schema_version": "triage-finding/v0",
            "repository": {"path": "/repo", "revision": "a" * 40},
            "findings": [
                self.finding("confirmed", 1),
                self.finding("needs_review", 2),
                self.finding("not_actionable", 3),
            ],
        }

    def test_report_maps_and_filters_all_verdicts(self):
        report, counts = render_triage_report.build_report(
            self.payload(), "feature/report"
        )

        self.assertEqual(counts["confirmed"], 1)
        self.assertEqual(counts["needs_review"], 1)
        self.assertEqual(counts["not_actionable"], 1)
        for verdict in render_triage_report.VERDICTS:
            self.assertIn(f'data-filter="{verdict}"', report)
            self.assertIn(f'data-verdict="{verdict}"', report)
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertNotIn('href="javascript:', report)
        self.assertIn(
            "https://github.com/example/repo/security/code-scanning/1", report
        )
        self.assertIn("<strong>Finding ID:</strong> github-codeql-alert-1", report)
        self.assertIn("<strong>Triage item ID:</strong> triage-1", report)

    def test_empty_report_is_explicit(self):
        payload = self.payload()
        payload["findings"] = []

        report, counts = render_triage_report.build_report(payload, "main")

        self.assertEqual(sum(counts.values()), 0)
        self.assertIn("No CodeQL findings were imported.", report)

    def test_report_renders_both_scanners_and_relationship_rationale(self):
        codex = {
            "documentType": "codex-security.findings",
            "findings": [
                {
                    "findingId": "csf-1",
                    "title": "Codex finding",
                    "summary": "Codex summary",
                    "locations": [
                        {
                            "path": "routes/example.ts",
                            "startLine": 10,
                            "endLine": 12,
                            "role": "sink",
                        }
                    ],
                    "severity": {"level": "medium"},
                    "validation": {"evidence": ["Validated path"]},
                }
            ],
        }
        relationships = {
            "schema_version": "security-relationships/v1",
            "repository": {"revision": "a" * 40},
            "relationships": [
                {
                    "relationship_id": "rel-1",
                    "classification": "exact_overlap",
                    "codeql_finding_id": "github-codeql-alert-1",
                    "codex_finding_ids": ["csf-1"],
                    "same_source": True,
                    "same_failed_control": True,
                    "same_sink": True,
                    "same_precondition": True,
                    "same_impact": True,
                    "rationale": "Same source, control and sink.",
                    "evidence": ["routes/example.ts:10-12"],
                }
            ],
        }

        report, _ = render_triage_report.build_report(
            self.payload(), "master", codex, relationships
        )

        self.assertIn("CodeQL ↔ Codex Security correlation", report)
        self.assertIn("Codex Security Finding ID:</strong> csf-1", report)
        self.assertIn("Same source, control and sink.", report)
        self.assertIn("pending human review", report)

    def test_load_triage_rejects_unknown_verdict(self):
        payload = self.payload()
        payload["findings"][0]["verdict"] = "unknown"

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "triage.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                render_triage_report.ReportError, "verdict is invalid"
            ):
                render_triage_report.load_triage(path)


if __name__ == "__main__":
    unittest.main()
