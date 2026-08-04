#!/usr/bin/env python3
"""Import open CodeQL alerts for the exact currently checked-out branch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote


SCHEMA_VERSION = "codeql-branch-intake/v1"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GITHUB_API_VERSION = "2022-11-28"


class IntakeError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import open CodeQL alerts for the current Git branch."
    )
    parser.add_argument("--repository", required=True, help="GitHub owner/repo")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument(
        "--output",
        required=True,
        help="Temporary JSON path outside the repository",
    )
    return parser.parse_args()


def command_output(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
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
    revision = command_output(["git", "rev-parse", "HEAD"], canonical_root)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise IntakeError("git revision is not a full commit SHA")
    return {
        "path": str(canonical_root),
        "branch": branch,
        "ref": f"refs/heads/{branch}",
        "revision": revision.lower(),
    }


def flatten_pages(value: Any, endpoint: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise IntakeError(f"invalid GitHub response for {endpoint}")
    pages = value if all(isinstance(page, list) for page in value) else [value]
    items: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
            raise IntakeError(f"invalid GitHub page for {endpoint}")
        items.extend(page)
    return items


def gh_api(endpoint: str) -> list[dict[str, Any]]:
    if shutil.which("gh") is None:
        raise IntakeError("GitHub CLI is not installed")
    command = [
        "gh",
        "api",
        "--paginate",
        "--slurp",
        endpoint,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or "GitHub API request failed"
        raise IntakeError(f"GET {endpoint}: {message}")
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise IntakeError(f"GET {endpoint}: invalid JSON response") from error
    return flatten_pages(response, endpoint)


def collect_intake(
    repository: str,
    git_context: dict[str, str],
    request: Callable[[str], list[dict[str, Any]]],
) -> dict[str, Any]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise IntakeError("repository must use owner/repo format")
    target_ref = git_context["ref"]
    encoded_ref = quote(target_ref, safe="")
    alerts_endpoint = (
        f"/repos/{repository}/code-scanning/alerts"
        f"?state=open&ref={encoded_ref}&tool_name=CodeQL&per_page=100"
    )
    alerts = request(alerts_endpoint)
    imported = []
    alert_numbers: set[int] = set()
    for alert in alerts:
        number = alert.get("number")
        if not isinstance(number, int) or number < 1:
            raise IntakeError("GitHub alert has an invalid number")
        if number in alert_numbers:
            raise IntakeError(f"duplicate GitHub alert number: {number}")
        alert_numbers.add(number)
        if alert.get("state") != "open":
            raise IntakeError(f"alert {number} is not open")
        tool = alert.get("tool")
        if not isinstance(tool, dict) or tool.get("name") != "CodeQL":
            raise IntakeError(f"alert {number} is not a CodeQL alert")
        instances_endpoint = (
            f"/repos/{repository}/code-scanning/alerts/{number}/instances?per_page=100"
        )
        instances = request(instances_endpoint)
        matching_instances = [
            instance for instance in instances if instance.get("ref") == target_ref
        ]
        if not matching_instances:
            raise IntakeError(
                f"alert {number}: no instance matches current branch ref {target_ref}"
            )
        imported.append(
            {
                "alert": alert,
                "matching_instances": matching_instances,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "local_repository": git_context["path"],
        "branch": git_context["branch"],
        "ref": target_ref,
        "revision": git_context["revision"],
        "alerts_endpoint": alerts_endpoint,
        "expected_count": len(imported),
        "alerts": imported,
    }


def validate_output_path(output_path: Path, repository_path: Path) -> Path:
    resolved_output = output_path.resolve()
    resolved_repository = repository_path.resolve()
    try:
        resolved_output.relative_to(resolved_repository)
    except ValueError:
        return resolved_output
    raise IntakeError("intake output must be outside the repository")


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


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
        output_path = validate_output_path(
            Path(args.output), Path(context["path"])
        )
        intake = collect_intake(args.repository, context, gh_api)
        content = json_bytes(intake)
        atomic_write(output_path, content)
        if output_path.read_bytes() != content:
            raise IntakeError(f"written content mismatch: {output_path}")
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "repository": intake["repository"],
                    "local_repository": intake["local_repository"],
                    "branch": intake["branch"],
                    "ref": intake["ref"],
                    "revision": intake["revision"],
                    "alerts_endpoint": intake["alerts_endpoint"],
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
