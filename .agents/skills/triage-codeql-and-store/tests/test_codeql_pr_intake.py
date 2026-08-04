import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "codeql_pr_intake.py"
SPEC = importlib.util.spec_from_file_location("codeql_pr_intake", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
codeql_pr_intake = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codeql_pr_intake)


class CodeqlPrIntakeTest(unittest.TestCase):
    def context(self):
        return {
            "path": "/repo",
            "branch": "feature/pr-triage",
            "ref": "refs/heads/feature/pr-triage",
            "revision": "a" * 40,
        }

    def alert(self):
        return {
            "number": 7,
            "state": "open",
            "tool": {"name": "CodeQL"},
            "rule": {"security_severity_level": "high"},
        }

    def test_builds_revision_bound_pr_intake(self):
        intake = codeql_pr_intake.build_intake(
            alerts=[self.alert()],
            repository="example/repo",
            context=self.context(),
            pr_number=42,
            base_revision="b" * 40,
        )

        self.assertEqual(intake["schema_version"], "codeql-pr-intake/v1")
        self.assertEqual(intake["expected_count"], 1)
        self.assertEqual(intake["pull_request_number"], 42)
        self.assertIn("pr=42&tool_name=CodeQL&state=open", intake["alerts_endpoint"])

    def test_rejects_invalid_base_revision(self):
        with self.assertRaisesRegex(codeql_pr_intake.IntakeError, "base revision"):
            codeql_pr_intake.build_intake(
                alerts=[self.alert()],
                repository="example/repo",
                context=self.context(),
                pr_number=42,
                base_revision="main",
            )


if __name__ == "__main__":
    unittest.main()
