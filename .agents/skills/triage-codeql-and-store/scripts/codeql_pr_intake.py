#!/usr/bin/env python3
"""Build a revision-bound intake from CodeQL alerts filtered to one pull request."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "codeql-pr-intake/v1"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REVISION_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class IntakeError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a CodeQL intake for alerts already filtered to one pull request."
    )
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--base-revision", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def command_output(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise IntakeError(f"{' '.join(command[:2])}: {message}")
    value = result.stdout.strip()
    if not value:
        raise IntakeError(f"{' '.join(command[:2])}: empty output")
    return value


def resolve_git_context(repo_root: Path) -> dict[str, str]:
    canonical_root = Path(
        command_output(["git", "rev-parse", "--show-toplevel"], repo_root)
    ).resolve()
    branch = command_output(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"], canonical_root
    )
    revision = command_output(["git", "rev-parse", "HEAD"], canonical_root).lower()
    if not REVISION_PATTERN.fullmatch(revision):
        raise IntakeError("git revision is not a full commit SHA")
    return {
        "path": str(canonical_root),
        "branch": branch,
        "ref": f"refs/heads/{branch}",
        "revision": revision,
    }


def load_alerts(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise IntakeError(f"cannot read CodeQL alerts from {path}: {error}") from error
    if not isinstance(value, list):
        raise IntakeError("CodeQL alerts must be an array")
    alerts: list[dict[str, Any]] = []
    numbers: set[int] = set()
    for index, alert in enumerate(value):
        if not isinstance(alert, dict):
            raise IntakeError(f"alerts[{index}] must be an object")
        number = alert.get("number")
        if not isinstance(number, int) or number < 1:
            raise IntakeError(f"alerts[{index}].number must be a positive integer")
        if number in numbers:
            raise IntakeError(f"duplicate GitHub alert number: {number}")
        numbers.add(number)
        if alert.get("state") != "open":
            raise IntakeError(f"alert {number} is not open")
        tool = alert.get("tool")
        if not isinstance(tool, dict) or tool.get("name") != "CodeQL":
            raise IntakeError(f"alert {number} is not a CodeQL alert")
        alerts.append(alert)
    return alerts


def validate_output_path(output_path: Path, repository_path: Path) -> Path:
    resolved_output = output_path.resolve()
    try:
        resolved_output.relative_to(repository_path.resolve())
    except ValueError:
        return resolved_output
    raise IntakeError("intake output must be outside the repository")


def build_intake(
    *,
    alerts: list[dict[str, Any]],
    repository: str,
    context: dict[str, str],
    pr_number: int,
    base_revision: str,
) -> dict[str, Any]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise IntakeError("repository must use owner/repo format")
    if pr_number < 1:
        raise IntakeError("pull request number must be positive")
    if not REVISION_PATTERN.fullmatch(base_revision):
        raise IntakeError("base revision is not a full commit SHA")
    endpoint = (
        f"/repos/{repository}/code-scanning/alerts"
        f"?pr={pr_number}&tool_name=CodeQL&state=open&per_page=100"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "local_repository": context["path"],
        "branch": context["branch"],
        "ref": context["ref"],
        "revision": context["revision"],
        "base_revision": base_revision.lower(),
        "pull_request_number": pr_number,
        "alerts_endpoint": endpoint,
        "expected_count": len(alerts),
        "alerts": alerts,
    }


def atomic_write(path: Path, content: bytes) -> None:
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
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def main() -> int:
    args = parse_args()
    try:
        context = resolve_git_context(Path(args.repo_root))
        output_path = validate_output_path(Path(args.output), Path(context["path"]))
        intake = build_intake(
            alerts=load_alerts(Path(args.alerts)),
            repository=args.repository,
            context=context,
            pr_number=args.pr_number,
            base_revision=args.base_revision,
        )
        content = (json.dumps(intake, indent=2, sort_keys=True) + "\n").encode()
        atomic_write(output_path, content)
        if output_path.read_bytes() != content:
            raise IntakeError(f"written content mismatch: {output_path}")
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "repository": intake["repository"],
                    "branch": intake["branch"],
                    "ref": intake["ref"],
                    "revision": intake["revision"],
                    "base_revision": intake["base_revision"],
                    "pull_request_number": intake["pull_request_number"],
                    "expected_count": intake["expected_count"],
                    "output_path": str(output_path),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "github_modified": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (IntakeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
