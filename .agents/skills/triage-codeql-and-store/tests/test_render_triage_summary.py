import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "render_triage_summary.py"
SPEC = importlib.util.spec_from_file_location("render_triage_summary", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
render_triage_summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(render_triage_summary)


class RenderTriageSummaryTest(unittest.TestCase):
    def test_renders_alert_and_escapes_imported_html(self):
        payload = {
            "findings": [
                {
                    "title": "<script>alert(1)</script>",
                    "verdict": "needs_review",
                    "confidence": "medium",
                    "input_id": "github-codeql-alert-7",
                    "normalized_input": {
                        "references": [
                            "https://github.com/example/repo/security/code-scanning/7"
                        ]
                    },
                    "evidence": ["source reaches sink; notify @security-team"],
                    "counterevidence": [],
                    "proof_gaps": ["runtime configuration"],
                    "recommended_next_step": "review configuration",
                }
            ]
        }

        result = render_triage_summary.render(payload)

        self.assertIn("[Alert #7]", result)
        self.assertIn("&lt;script&gt;alert", result)
        self.assertNotIn("<script>", result)
        self.assertIn("&#64;security-team", result)
        self.assertNotIn("@security-team", result)

    def test_does_not_render_noncanonical_alert_reference_as_a_link(self):
        finding = {
            "title": "finding",
            "verdict": "needs_review",
            "confidence": "medium",
            "input_id": "github-codeql-alert-7",
            "normalized_input": {
                "references": [
                    "https://github.com/example/repo/security/code-scanning/7?text=)"
                ]
            },
            "evidence": [],
            "counterevidence": [],
            "proof_gaps": [],
            "recommended_next_step": "review",
        }

        result = render_triage_summary.render({"findings": [finding]})

        self.assertIn("### CodeQL alert", result)
        self.assertNotIn("](https://", result)


if __name__ == "__main__":
    unittest.main()
