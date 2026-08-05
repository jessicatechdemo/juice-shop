#!/usr/bin/env python3
"""Validate a CodeQL triage handoff before a trusted Jira workflow consumes it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import persist_triage


PR_HANDOFF_SCHEMA = "codeql-jira-handoff/v1"
BRANCH_HANDOFF_SCHEMA = "codeql-jira-branch-handoff/v1"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class HandoffError(ValueError):
    pass


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HandoffError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise HandoffError(f"{path} must contain a JSON object")
    return value


def digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise HandoffError(f"cannot read handoff file {path}: {error}") from error


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HandoffError(f"{field} must be a non-empty string")
    return value.strip()


def validate_branch(value: Any) -> str:
    branch = require_string(value, "metadata.branch")
    if (
        branch.startswith("-")
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch)
        or any(part in {"", ".", ".."} for part in branch.split("/"))
    ):
        raise HandoffError("metadata.branch is unsafe")
    return branch


def validate(
    directory: Path,
    expected_repository: str,
    expected_source_workflow: str | None = None,
    expected_source_event: str | None = None,
    expected_source_run_id: str | None = None,
) -> dict[str, str]:
    if not REPOSITORY_PATTERN.fullmatch(expected_repository):
        raise HandoffError("expected repository must use owner/repo format")
    metadata = load_object(directory / "metadata.json")
    schema = metadata.get("schema_version")
    if schema not in {PR_HANDOFF_SCHEMA, BRANCH_HANDOFF_SCHEMA}:
        raise HandoffError(
            "metadata.schema_version must be a supported CodeQL Jira handoff"
        )
    repository = require_string(metadata.get("repository"), "metadata.repository")
    if repository.lower() != expected_repository.lower():
        raise HandoffError("handoff repository does not match the workflow repository")
    branch = validate_branch(metadata.get("branch"))
    ref = require_string(metadata.get("ref"), "metadata.ref")
    if ref != f"refs/heads/{branch}":
        raise HandoffError("handoff ref does not match its branch")
    revision = require_string(metadata.get("revision"), "metadata.revision").lower()
    if not REVISION_PATTERN.fullmatch(revision):
        raise HandoffError("handoff revision must be a full lowercase commit SHA")

    scope = "pull_request" if schema == PR_HANDOFF_SCHEMA else "branch"
    base_revision = None
    pr_number = None
    pr_url = None
    source_workflow = None
    source_event = None
    source_run_id = None
    source_run_attempt = None
    if scope == "pull_request":
        base_revision = require_string(
            metadata.get("base_revision"), "metadata.base_revision"
        ).lower()
        if not REVISION_PATTERN.fullmatch(base_revision):
            raise HandoffError(
                "handoff base revision must be a full lowercase commit SHA"
            )
        pr_number = metadata.get("pull_request_number")
        if not isinstance(pr_number, int) or pr_number < 1:
            raise HandoffError("metadata.pull_request_number must be positive")
        pr_url = require_string(
            metadata.get("pull_request_url"), "metadata.pull_request_url"
        )
        if pr_url != f"https://github.com/{repository}/pull/{pr_number}":
            raise HandoffError("handoff pull request URL is not canonical")
    else:
        if metadata.get("scope") != "branch":
            raise HandoffError('metadata.scope must be "branch"')
        if branch != "master":
            raise HandoffError("scheduled handoff branch must be master")
        for field in ("base_revision", "pull_request_number", "pull_request_url"):
            if field in metadata:
                raise HandoffError(f"branch handoff must omit metadata.{field}")
        source_workflow = require_string(
            metadata.get("source_workflow"), "metadata.source_workflow"
        )
        if source_workflow != "CodeQL Scheduled Scan":
            raise HandoffError("branch handoff source workflow is invalid")
        source_event = require_string(
            metadata.get("source_event"), "metadata.source_event"
        )
        if source_event not in {"schedule", "workflow_dispatch"}:
            raise HandoffError("branch handoff source event is invalid")
        source_run_id = metadata.get("source_run_id")
        source_run_attempt = metadata.get("source_run_attempt")
        if not isinstance(source_run_id, int) or source_run_id < 1:
            raise HandoffError("metadata.source_run_id must be positive")
        if not isinstance(source_run_attempt, int) or source_run_attempt < 1:
            raise HandoffError("metadata.source_run_attempt must be positive")
        expected_source = (
            ("workflow", source_workflow, expected_source_workflow),
            ("event", source_event, expected_source_event),
            ("run ID", str(source_run_id), expected_source_run_id),
        )
        for label, actual, expected in expected_source:
            if expected is not None and actual != expected:
                raise HandoffError(f"branch handoff source {label} does not match")

    files = metadata.get("files")
    if not isinstance(files, dict):
        raise HandoffError("metadata.files must be an object")
    required_files = (
        "intake.json",
        "current.json",
        "report.html",
        "summary.md",
        "persist-receipt.json",
        "report-receipt.json",
    )
    for name in required_files:
        expected_digest = require_string(files.get(name), f"metadata.files.{name}")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            raise HandoffError(f"metadata.files.{name} is not a SHA-256 digest")
        if digest(directory / name) != expected_digest:
            raise HandoffError(f"handoff digest mismatch for {name}")

    intake = load_object(directory / "intake.json")
    triage = load_object(directory / "current.json")
    expected_count, intake_ref, commits = persist_triage.validate_intake(
        intake, triage, branch
    )
    persist_triage.validate_payload(triage, expected_count)
    persist_triage.validate_payload_against_intake(triage, intake_ref, commits, intake)
    if intake.get("repository") != repository or intake.get("revision") != revision:
        raise HandoffError("handoff metadata does not match the validated intake")
    if scope == "pull_request":
        if (
            intake.get("schema_version") != persist_triage.PR_INTAKE_SCHEMA_VERSION
            or intake.get("base_revision") != base_revision
            or intake.get("pull_request_number") != pr_number
        ):
            raise HandoffError("PR handoff metadata does not match its intake")
    elif intake.get("schema_version") != persist_triage.INTAKE_SCHEMA_VERSION:
        raise HandoffError("branch handoff must contain a branch intake")
    triage_repository = triage.get("repository")
    if not isinstance(triage_repository, dict) or triage_repository.get("revision") != revision:
        raise HandoffError("triage revision does not match the handoff")

    persist_receipt = load_object(directory / "persist-receipt.json")
    report_receipt = load_object(directory / "report-receipt.json")
    if (
        persist_receipt.get("sha256") != digest(directory / "current.json")
        or persist_receipt.get("stored_result_count") != expected_count
        or report_receipt.get("sha256") != digest(directory / "report.html")
        or report_receipt.get("finding_count") != expected_count
    ):
        raise HandoffError("handoff receipts do not match the triage artifacts")
    result = {
        "scope": scope,
        "repository": repository,
        "branch": branch,
        "ref": ref,
        "revision": revision,
    }
    if scope == "pull_request":
        result.update(
            {
                "base_revision": str(base_revision),
                "pull_request_number": str(pr_number),
                "pull_request_url": str(pr_url),
            }
        )
    else:
        result.update(
            {
                "source_workflow": str(source_workflow),
                "source_event": str(source_event),
                "source_run_id": str(source_run_id),
                "source_run_attempt": str(source_run_attempt),
            }
        )
    return result


def write_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise HandoffError(f"output {key} contains a newline")
            output.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a CodeQL Jira handoff.")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-workflow")
    parser.add_argument("--source-event")
    parser.add_argument("--source-run-id")
    parser.add_argument("--github-output")
    args = parser.parse_args()
    try:
        values = validate(
            Path(args.directory),
            args.repository,
            args.source_workflow,
            args.source_event,
            args.source_run_id,
        )
        if args.github_output:
            write_github_output(Path(args.github_output), values)
        print(json.dumps(values, indent=2, sort_keys=True))
        return 0
    except (HandoffError, persist_triage.ValidationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
