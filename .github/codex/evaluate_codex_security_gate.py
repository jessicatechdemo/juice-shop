#!/usr/bin/env python3
"""Evaluate high-severity Codex Security pull request warnings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


DOCUMENT_TYPE = "codex-security.findings"
RESULT_SCHEMA_VERSION = "codex-security-warning/v1"
WARNING_SEVERITIES = {"critical", "high"}
SUPPORTED_SEVERITIES = WARNING_SEVERITIES | {"medium", "low", "informational"}


class GateEvaluationError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateEvaluationError(f"cannot read Codex Security findings: {error}") from error
    if not isinstance(payload, dict):
        raise GateEvaluationError("Codex Security findings must be a JSON object")
    return payload


def evaluate(findings: dict[str, Any]) -> dict[str, Any]:
    if findings.get("documentType") != DOCUMENT_TYPE:
        raise GateEvaluationError(
            f'findings.documentType must be "{DOCUMENT_TYPE}"'
        )
    if not isinstance(findings.get("scanId"), str) or not findings["scanId"]:
        raise GateEvaluationError("findings.scanId must be a non-empty string")

    items = findings.get("findings")
    if not isinstance(items, list):
        raise GateEvaluationError("findings.findings must be an array")

    warning_findings = []
    for index, finding in enumerate(items):
        field = f"findings.findings[{index}]"
        if not isinstance(finding, dict):
            raise GateEvaluationError(f"{field} must be an object")
        finding_id = finding.get("findingId")
        title = finding.get("title")
        severity = finding.get("severity")
        if not isinstance(finding_id, str) or not finding_id:
            raise GateEvaluationError(f"{field}.findingId must be a non-empty string")
        if not isinstance(title, str) or not title:
            raise GateEvaluationError(f"{field}.title must be a non-empty string")
        if not isinstance(severity, dict):
            raise GateEvaluationError(f"{field}.severity must be an object")
        level = severity.get("level")
        if level not in SUPPORTED_SEVERITIES:
            raise GateEvaluationError(f"{field}.severity.level is invalid: {level!r}")
        if level in WARNING_SEVERITIES:
            warning_findings.append(
                {
                    "finding_id": finding_id,
                    "severity": level,
                    "title": title,
                }
            )

    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "decision": "warn" if warning_findings else "pass",
        "scan_id": findings["scanId"],
        "finding_count": len(items),
        "warning_count": len(warning_findings),
        "warning_findings": warning_findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report high or critical Codex Security findings as warnings."
    )
    parser.add_argument("--findings", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        result = evaluate(load_json(Path(args.findings)))
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
