import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "codeql_branch_intake.py"
SPEC = importlib.util.spec_from_file_location("codeql_branch_intake", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
codeql_branch_intake = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codeql_branch_intake)


class CodeQLBranchIntakeTest(unittest.TestCase):
    def context(self):
        return {
            "path": "/repo",
            "branch": "feature/current",
            "ref": "refs/heads/feature/current",
            "revision": "a" * 40,
        }

    def test_collect_intake_queries_and_keeps_only_current_branch(self):
        endpoints = []

        def request(endpoint):
            endpoints.append(endpoint)
            if "/instances?" in endpoint:
                return [
                    {"ref": "refs/heads/other", "commit_sha": "b" * 40},
                    {
                        "ref": "refs/heads/feature/current",
                        "commit_sha": "a" * 40,
                    },
                ]
            return [{"number": 7, "html_url": "https://github.com/example/repo/7"}]

        intake = codeql_branch_intake.collect_intake(
            "example/repo", self.context(), request
        )

        self.assertIn(
            "state=open&ref=refs%2Fheads%2Ffeature%2Fcurrent&per_page=100",
            endpoints[0],
        )
        self.assertEqual(intake["branch"], "feature/current")
        self.assertEqual(intake["ref"], "refs/heads/feature/current")
        self.assertEqual(intake["expected_count"], 1)
        self.assertEqual(
            intake["alerts"][0]["matching_instances"],
            [{"ref": "refs/heads/feature/current", "commit_sha": "a" * 40}],
        )

    def test_collect_intake_rejects_alert_without_current_branch_instance(self):
        def request(endpoint):
            if "/instances?" in endpoint:
                return [{"ref": "refs/heads/other", "commit_sha": "b" * 40}]
            return [{"number": 7}]

        with self.assertRaisesRegex(
            codeql_branch_intake.IntakeError, "no instance matches current branch"
        ):
            codeql_branch_intake.collect_intake(
                "example/repo", self.context(), request
            )

    def test_output_must_be_outside_repository(self):
        with self.assertRaisesRegex(
            codeql_branch_intake.IntakeError, "outside the repository"
        ):
            codeql_branch_intake.validate_output_path(
                Path("/repo/intake.json"), Path("/repo")
            )


if __name__ == "__main__":
    unittest.main()
