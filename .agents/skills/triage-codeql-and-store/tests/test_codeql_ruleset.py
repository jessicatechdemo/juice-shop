import json
import unittest
from pathlib import Path


RULESET_PATH = Path(__file__).parents[4] / ".github" / "rulesets" / "codeql-security-gate.json"


class CodeqlRulesetTest(unittest.TestCase):
    def test_native_codeql_gate_remains_required(self):
        ruleset = json.loads(RULESET_PATH.read_text())
        code_scanning_rules = [
            rule for rule in ruleset["rules"] if rule["type"] == "code_scanning"
        ]

        self.assertTrue(code_scanning_rules)
        self.assertIn(
            {
                "tool": "CodeQL",
                "alerts_threshold": "none",
                "security_alerts_threshold": "high_or_higher",
            },
            code_scanning_rules[0]["parameters"]["code_scanning_tools"],
        )


if __name__ == "__main__":
    unittest.main()
