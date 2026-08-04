#!/usr/bin/env python3
"""Validate and persist a CodeQL triage-finding/v0 payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "triage-finding/v0"
INTAKE_SCHEMA_VERSION = "codeql-branch-intake/v1"
PR_INTAKE_SCHEMA_VERSION = "codeql-pr-intake/v1"
VERDICTS = {"confirmed", "needs_review", "not_actionable"}
CONFIDENCE_LEVELS = {"high", "medium", "low"}
CODEQL_SECURITY_SEVERITIES = {"critical", "high", "medium", "low"}
SECURITY_SEVERITY_REFERENCE_PREFIX = "codeql-security-severity:"
ALERT_URL_PATTERN = re.compile(
    r"(?:/security/code-scanning/|/code-scanning/alerts/)([0-9]+)(?:$|[/?#])"
)


class ValidationError(ValueError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Persist a validated CodeQL triage result atomically."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the triage JSON payload, or - to read stdin.",
    )
    parser.add_argument("--branch", required=True, help="Git branch or ref triaged.")
    parser.add_argument(
        "--intake",
        required=True,
        help="Branch-bound codeql-branch-intake/v1 JSON path",
    )
    parser.add_argument(
        "--expected-count",
        type=int,
        help="Optional independent count assertion",
    )
    parser.add_argument(
        "--output-root",
        default="security-results/triage/codeql",
        help="Root directory for persisted results.",
    )
    return parser.parse_args()


def load_payload(input_value: str) -> dict[str, Any]:
    try:
        if input_value == "-":
            payload = json.load(sys.stdin)
        else:
            with Path(input_value).open(encoding="utf-8") as input_file:
                payload = json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read input JSON: {error}") from error

    if not isinstance(payload, dict):
        raise ValidationError("top-level JSON value must be an object")
    return payload


def load_intake(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        intake = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read branch intake JSON: {error}") from error
    if not isinstance(intake, dict):
        raise ValidationError("branch intake JSON must be an object")
    return intake, raw


def require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value.strip()


def validate_payload(payload: dict[str, Any], expected_count: int) -> Counter[str]:
    if expected_count < 0:
        raise ValidationError("expected count must not be negative")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValidationError(f'schema_version must be "{SCHEMA_VERSION}"')

    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise ValidationError("repository must be an object")
    require_nonempty_string(repository.get("path"), "repository.path")
    require_nonempty_string(repository.get("revision"), "repository.revision")

    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ValidationError("findings must be an array")
    if len(findings) != expected_count:
        raise ValidationError(
            f"stored result count {len(findings)} does not match "
            f"imported alert count {expected_count}"
        )

    triage_ids: set[str] = set()
    input_ids: set[str] = set()
    counts: Counter[str] = Counter()

    for index, finding in enumerate(findings):
        field = f"findings[{index}]"
        if not isinstance(finding, dict):
            raise ValidationError(f"{field} must be an object")

        triage_id = require_nonempty_string(
            finding.get("triage_item_id"), f"{field}.triage_item_id"
        )
        input_id = require_nonempty_string(
            finding.get("input_id"), f"{field}.input_id"
        )
        if triage_id in triage_ids:
            raise ValidationError(f"duplicate triage_item_id: {triage_id}")
        if input_id in input_ids:
            raise ValidationError(f"duplicate input_id: {input_id}")
        triage_ids.add(triage_id)
        input_ids.add(input_id)

        if finding.get("source_type") != "sarif":
            raise ValidationError(f'{field}.source_type must be "sarif"')

        verdict = finding.get("verdict")
        if verdict not in VERDICTS:
            raise ValidationError(f"{field}.verdict is invalid: {verdict!r}")
        counts[verdict] += 1

        confidence = finding.get("confidence")
        if confidence not in CONFIDENCE_LEVELS:
            raise ValidationError(f"{field}.confidence is invalid: {confidence!r}")

        normalized = finding.get("normalized_input")
        if not isinstance(normalized, dict):
            raise ValidationError(f"{field}.normalized_input must be an object")
        references = normalized.get("references")
        if not isinstance(references, list) or not references:
            raise ValidationError(f"{field}.normalized_input.references must not be empty")
        if not any(
            isinstance(reference, str)
            and ("github.com/" in reference or "code-scanning" in reference)
            for reference in references
        ):
            raise ValidationError(f"{field} does not preserve a GitHub CodeQL reference")

        for list_field in ("evidence", "counterevidence", "proof_gaps"):
            if not isinstance(finding.get(list_field), list):
                raise ValidationError(f"{field}.{list_field} must be an array")
        if not isinstance(finding.get("boundary_assessment"), dict):
            raise ValidationError(f"{field}.boundary_assessment must be an object")
        if not isinstance(finding.get("exploitability_stack_rank"), dict):
            raise ValidationError(f"{field}.exploitability_stack_rank must be an object")

    for verdict in VERDICTS:
        counts[verdict] += 0
    return counts


def normalized_branch(branch: str) -> str:
    value = require_nonempty_string(branch, "branch")
    return value[len("refs/heads/") :] if value.startswith("refs/heads/") else value


def validate_intake(
    intake: dict[str, Any], payload: dict[str, Any], branch: str
) -> tuple[int, str, dict[int, set[str]]]:
    intake_schema = intake.get("schema_version")
    if intake_schema not in {INTAKE_SCHEMA_VERSION, PR_INTAKE_SCHEMA_VERSION}:
        raise ValidationError(
            "intake schema_version must be "
            f'"{INTAKE_SCHEMA_VERSION}" or "{PR_INTAKE_SCHEMA_VERSION}"'
        )
    intake_branch = require_nonempty_string(intake.get("branch"), "intake.branch")
    if intake_branch != normalized_branch(branch):
        raise ValidationError(
            f"intake branch {intake_branch!r} does not match requested branch "
            f"{normalized_branch(branch)!r}"
        )
    expected_ref = f"refs/heads/{intake_branch}"
    intake_ref = require_nonempty_string(intake.get("ref"), "intake.ref")
    if intake_ref != expected_ref:
        raise ValidationError(
            f"intake ref {intake_ref!r} does not match current branch ref {expected_ref!r}"
        )
    endpoint = require_nonempty_string(
        intake.get("alerts_endpoint"), "intake.alerts_endpoint"
    )
    if intake_schema == INTAKE_SCHEMA_VERSION:
        encoded_ref = expected_ref.replace("/", "%2F")
        if (
            f"state=open&ref={encoded_ref}&tool_name=CodeQL&"
            not in endpoint
        ):
            raise ValidationError("intake endpoint is not bound to the current branch ref")
    else:
        pr_number = intake.get("pull_request_number")
        if not isinstance(pr_number, int) or pr_number < 1:
            raise ValidationError("intake.pull_request_number must be positive")
        if (
            f"?pr={pr_number}&tool_name=CodeQL&state=open&" not in endpoint
            or not re.fullmatch(r"[0-9a-fA-F]{40}", str(intake.get("base_revision", "")))
        ):
            raise ValidationError("intake endpoint or base revision is not bound to the pull request")

    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise ValidationError("repository must be an object")
    payload_path = Path(
        require_nonempty_string(repository.get("path"), "repository.path")
    ).resolve()
    intake_path = Path(
        require_nonempty_string(
            intake.get("local_repository"), "intake.local_repository"
        )
    ).resolve()
    if payload_path != intake_path:
        raise ValidationError("triage repository path does not match branch intake")
    payload_revision = require_nonempty_string(
        repository.get("revision"), "repository.revision"
    )
    intake_revision = require_nonempty_string(
        intake.get("revision"), "intake.revision"
    )
    if payload_revision != intake_revision:
        raise ValidationError("triage revision does not match branch intake")

    alerts = intake.get("alerts")
    expected_count = intake.get("expected_count")
    if not isinstance(alerts, list):
        raise ValidationError("intake.alerts must be an array")
    if not isinstance(expected_count, int) or expected_count < 0:
        raise ValidationError("intake.expected_count must be a non-negative integer")
    if len(alerts) != expected_count:
        raise ValidationError("intake alert count does not match expected_count")

    commits_by_alert: dict[int, set[str]] = {}
    for index, item in enumerate(alerts):
        field = f"intake.alerts[{index}]"
        alert = item.get("alert") if intake_schema == INTAKE_SCHEMA_VERSION and isinstance(item, dict) else item
        if not isinstance(alert, dict):
            raise ValidationError(f"{field} must preserve an alert object")
        number = alert.get("number")
        if not isinstance(number, int) or number < 1:
            raise ValidationError(f"{field}.number must be a positive integer")
        if number in commits_by_alert:
            raise ValidationError(f"duplicate intake alert number: {number}")
        if alert.get("state") != "open":
            raise ValidationError(f"{field} is not open")
        tool = alert.get("tool")
        if not isinstance(tool, dict) or tool.get("name") != "CodeQL":
            raise ValidationError(f"{field} is not a CodeQL alert")
        if intake_schema == INTAKE_SCHEMA_VERSION:
            instances = item.get("matching_instances")
            if not isinstance(instances, list) or not instances:
                raise ValidationError(f"{field}.matching_instances must not be empty")
            commits = set()
            for instance in instances:
                if not isinstance(instance, dict) or instance.get("ref") != expected_ref:
                    raise ValidationError(f"{field} contains an instance for another ref")
                commit = instance.get("commit_sha")
                if isinstance(commit, str) and commit:
                    commits.add(commit)
            if not commits:
                raise ValidationError(f"{field} does not preserve an instance commit")
        else:
            commits = {intake_revision}
        commits_by_alert[number] = commits
    return expected_count, expected_ref, commits_by_alert


def finding_alert_number(finding: dict[str, Any], field: str) -> int:
    normalized = finding.get("normalized_input")
    if not isinstance(normalized, dict):
        raise ValidationError(f"{field}.normalized_input must be an object")
    references = normalized.get("references")
    if not isinstance(references, list):
        raise ValidationError(f"{field}.normalized_input.references must be an array")
    for reference in references:
        if isinstance(reference, str):
            match = ALERT_URL_PATTERN.search(reference)
            if match:
                return int(match.group(1))
    raise ValidationError(f"{field} does not preserve a GitHub alert number")


def validate_payload_against_intake(
    payload: dict[str, Any],
    intake_ref: str,
    commits_by_alert: dict[int, set[str]],
    intake: dict[str, Any] | None = None,
) -> None:
    security_severity_by_alert: dict[int, str | None] = {}
    if intake is not None:
        for item in intake["alerts"]:
            alert = item.get("alert") if intake.get("schema_version") == INTAKE_SCHEMA_VERSION else item
            if not isinstance(alert, dict):
                raise ValidationError("intake alert must be an object")
            rule = alert.get("rule")
            severity = (
                rule.get("security_severity_level")
                if isinstance(rule, dict)
                else None
            )
            if severity not in CODEQL_SECURITY_SEVERITIES:
                severity = None
            security_severity_by_alert[alert["number"]] = severity

    seen: set[int] = set()
    for index, finding in enumerate(payload["findings"]):
        field = f"findings[{index}]"
        number = finding_alert_number(finding, field)
        if number not in commits_by_alert:
            raise ValidationError(f"{field} alert {number} is absent from branch intake")
        if number in seen:
            raise ValidationError(f"duplicate triage result for alert {number}")
        seen.add(number)
        if finding.get("input_id") != f"github-codeql-alert-{number}":
            raise ValidationError(f"{field}.input_id does not match alert {number}")
        references = finding["normalized_input"]["references"]
        repository = intake.get("repository") if intake is not None else None
        if repository:
            canonical_alert_url = (
                f"https://github.com/{repository}/security/code-scanning/{number}"
            )
            if canonical_alert_url not in references:
                raise ValidationError(
                    f"{field} does not preserve the canonical GitHub alert URL"
                )
        if f"ref:{intake_ref}" not in references:
            raise ValidationError(f"{field} does not preserve current branch ref")
        intake_commits = commits_by_alert[number]
        if not any(f"commit:{commit}" in references for commit in intake_commits):
            raise ValidationError(f"{field} does not preserve a matching instance commit")
        if intake is not None:
            expected_severity = security_severity_by_alert[number]
            severity_references = [
                reference.removeprefix(SECURITY_SEVERITY_REFERENCE_PREFIX)
                for reference in references
                if isinstance(reference, str)
                and reference.startswith(SECURITY_SEVERITY_REFERENCE_PREFIX)
            ]
            expected_references = (
                [expected_severity] if expected_severity is not None else []
            )
            if severity_references != expected_references:
                raise ValidationError(
                    f"{field} CodeQL security severity reference does not match "
                    "branch intake"
                )
    if seen != set(commits_by_alert):
        missing = sorted(set(commits_by_alert) - seen)
        raise ValidationError(f"triage results are missing intake alerts: {missing}")


def validate_current_checkout(intake: dict[str, Any]) -> None:
    repository_path = require_nonempty_string(
        intake.get("local_repository"), "intake.local_repository"
    )
    checks = (
        (["git", "symbolic-ref", "--quiet", "--short", "HEAD"], intake["branch"]),
        (["git", "rev-parse", "HEAD"], intake["revision"]),
    )
    for command, expected in checks:
        result = subprocess.run(
            command,
            cwd=repository_path,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or result.stdout.strip() != expected:
            raise ValidationError(
                "current checkout changed after branch-bound CodeQL intake"
            )


def branch_slug(branch: str) -> str:
    normalized = require_nonempty_string(branch, "branch")
    if normalized.startswith("refs/heads/"):
        normalized = normalized[len("refs/heads/") :]
    slug = normalized.replace("/", "__")
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", slug).strip(".")
    if not slug or slug in {".", ".."}:
        raise ValidationError("branch does not produce a safe storage path")
    return slug[:180]


def serialized_payload(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def atomic_write(path: Path, content: bytes, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output_file:
            output_file.write(content)
            output_file.flush()
            os.fsync(output_file.fileno())
        if exclusive:
            try:
                os.link(temporary_path, path)
            except FileExistsError as error:
                raise ValidationError(f"history file already exists: {path}") from error
            temporary_path.unlink()
        else:
            os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def verify_written_file(path: Path, expected: bytes) -> None:
    try:
        actual = path.read_bytes()
        json.loads(actual)
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot verify {path}: {error}") from error
    if actual != expected:
        raise ValidationError(f"written content mismatch: {path}")


def main() -> int:
    args = parse_args()
    try:
        payload = load_payload(args.input)
        intake, intake_raw = load_intake(Path(args.intake))
        expected_count, intake_ref, commits_by_alert = validate_intake(
            intake, payload, args.branch
        )
        if args.expected_count is not None and args.expected_count != expected_count:
            raise ValidationError(
                "expected-count does not match branch intake expected_count"
            )
        counts = validate_payload(payload, expected_count)
        validate_payload_against_intake(
            payload, intake_ref, commits_by_alert, intake
        )
        validate_current_checkout(intake)
        slug = branch_slug(args.branch)
        repository = payload["repository"]
        revision = require_nonempty_string(repository["revision"], "repository.revision")
        revision_slug = re.sub(r"[^A-Za-z0-9._-]", "_", revision)[:12]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")

        branch_directory = Path(args.output_root) / slug
        current_path = branch_directory / "current.json"
        history_path = branch_directory / "history" / f"{timestamp}-{revision_slug}.json"
        content = serialized_payload(payload)

        atomic_write(history_path, content, exclusive=True)
        atomic_write(current_path, content)
        verify_written_file(history_path, content)
        verify_written_file(current_path, content)

        receipt = {
            "schema_version": SCHEMA_VERSION,
            "branch": args.branch,
            "ref": intake_ref,
            "revision": revision,
            "imported_alert_count": expected_count,
            "stored_result_count": len(payload["findings"]),
            "verdict_counts": {
                verdict: counts[verdict]
                for verdict in ("confirmed", "needs_review", "not_actionable")
            },
            "current_path": str(current_path),
            "history_path": str(history_path),
            "intake_path": str(Path(args.intake)),
            "intake_sha256": hashlib.sha256(intake_raw).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "github_modified": False,
        }
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except ValidationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
