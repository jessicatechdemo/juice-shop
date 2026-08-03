#!/usr/bin/env python3
"""Validate and persist a CodeQL triage-finding/v0 payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "triage-finding/v0"
VERDICTS = {"confirmed", "needs_review", "not_actionable"}
CONFIDENCE_LEVELS = {"high", "medium", "low"}


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
        "--expected-count",
        required=True,
        type=int,
        help="Number of CodeQL alerts imported before triage.",
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
        counts = validate_payload(payload, args.expected_count)
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
            "revision": revision,
            "imported_alert_count": args.expected_count,
            "stored_result_count": len(payload["findings"]),
            "verdict_counts": {
                verdict: counts[verdict]
                for verdict in ("confirmed", "needs_review", "not_actionable")
            },
            "current_path": str(current_path),
            "history_path": str(history_path),
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
