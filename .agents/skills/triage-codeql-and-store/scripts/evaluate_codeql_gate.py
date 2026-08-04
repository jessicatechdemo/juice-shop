#!/usr/bin/env python3
"""Evaluate the combined CodeQL severity and Codex triage PR gate."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


INTAKE_SCHEMA_VERSION = "codeql-pr-intake/v1"
TRIAGE_SCHEMA_VERSION = "triage-finding/v0"
GATE_SCHEMA_VERSION = "codeql-codex-gate/v1"
BLOCKING_SEVERITIES = {"critical", "high"}
BLOCKING_VERDICTS = {"confirmed", "needs_review"}
VERDICTS = BLOCKING_VERDICTS | {"not_actionable"}
SECURITY_SEVERITIES = BLOCKING_SEVERITIES | {"medium", "low"}


class GateEvaluationError(ValueError):
    pass


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateEvaluationError(f"cannot read {label}: {error}") from error
    if not isinstance(payload, dict):
        raise GateEvaluationError(f"{label} must be a JSON object")
    return payload


def intake_alerts(intake: dict[str, Any]) -> dict[int, str | None]:
    if intake.get("schema_version") != INTAKE_SCHEMA_VERSION:
        raise GateEvaluationError(
            f'intake.schema_version must be "{INTAKE_SCHEMA_VERSION}"'
        )
    alerts = intake.get("alerts")
    expected_count = intake.get("expected_count")
    if not isinstance(alerts, list):
        raise GateEvaluationError("intake.alerts must be an array")
    if expected_count != len(alerts):
        raise GateEvaluationError("intake alert count does not match expected_count")

    severities: dict[int, str | None] = {}
    for index, alert in enumerate(alerts):
        field = f"intake.alerts[{index}]"
        if not isinstance(alert, dict):
            raise GateEvaluationError(f"{field} must be an object")
        number = alert.get("number")
        if not isinstance(number, int) or number < 1:
            raise GateEvaluationError(f"{field}.number must be a positive integer")
        if number in severities:
            raise GateEvaluationError(f"duplicate intake alert number: {number}")
        if alert.get("state") != "open":
            raise GateEvaluationError(f"alert {number} is not open")
        tool = alert.get("tool")
        if not isinstance(tool, dict) or tool.get("name") != "CodeQL":
            raise GateEvaluationError(f"alert {number} is not a CodeQL alert")
        rule = alert.get("rule")
        severity = (
            rule.get("security_severity_level")
            if isinstance(rule, dict)
            else None
        )
        if not isinstance(severity, str) or severity not in SECURITY_SEVERITIES:
            severity = None
        severities[number] = severity
    return severities


def triage_verdicts(triage: dict[str, Any]) -> dict[int, str]:
    if triage.get("schema_version") != TRIAGE_SCHEMA_VERSION:
        raise GateEvaluationError(
            f'triage.schema_version must be "{TRIAGE_SCHEMA_VERSION}"'
        )
    findings = triage.get("findings")
    if not isinstance(findings, list):
        raise GateEvaluationError("triage.findings must be an array")

    verdicts: dict[int, str] = {}
    for index, finding in enumerate(findings):
        field = f"triage.findings[{index}]"
        if not isinstance(finding, dict):
            raise GateEvaluationError(f"{field} must be an object")
        if finding.get("source_type") != "sarif":
            raise GateEvaluationError(f'{field}.source_type must be "sarif"')
        input_id = finding.get("input_id")
        prefix = "github-codeql-alert-"
        if not isinstance(input_id, str) or not input_id.startswith(prefix):
            raise GateEvaluationError(f"{field}.input_id is not a CodeQL alert ID")
        number_text = input_id.removeprefix(prefix)
        if not number_text.isdigit() or int(number_text) < 1:
            raise GateEvaluationError(f"{field}.input_id is not a CodeQL alert ID")
        number = int(number_text)
        if number in verdicts:
            raise GateEvaluationError(f"duplicate triage alert number: {number}")
        verdict = finding.get("verdict")
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            raise GateEvaluationError(f"{field}.verdict is invalid: {verdict!r}")
        verdicts[number] = verdict
    return verdicts


def evaluate(intake: dict[str, Any], triage: dict[str, Any]) -> dict[str, Any]:
    severities = intake_alerts(intake)
    verdicts = triage_verdicts(triage)
    if set(verdicts) != set(severities):
        missing = sorted(set(severities) - set(verdicts))
        unexpected = sorted(set(verdicts) - set(severities))
        raise GateEvaluationError(
            "triage alert set does not match intake "
            f"(missing={missing}, unexpected={unexpected})"
        )

    blocking_findings = [
        {
            "alert_number": number,
            "security_severity": severities[number],
            "verdict": verdicts[number],
        }
        for number in sorted(severities)
        if severities[number] in BLOCKING_SEVERITIES
        and verdicts[number] in BLOCKING_VERDICTS
    ]
    verdict_counts = Counter(verdicts.values())
    return {
        "schema_version": GATE_SCHEMA_VERSION,
        "decision": "block" if blocking_findings else "pass",
        "finding_count": len(severities),
        "blocking_count": len(blocking_findings),
        "blocking_findings": blocking_findings,
        "verdict_counts": {
            verdict: verdict_counts[verdict]
            for verdict in ("confirmed", "needs_review", "not_actionable")
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the combined CodeQL and Codex SAST gate."
    )
    parser.add_argument("--intake", required=True)
    parser.add_argument("--triage", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = evaluate(
            load_json(Path(args.intake), "CodeQL intake"),
            load_json(Path(args.triage), "Codex triage"),
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (GateEvaluationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
