#!/usr/bin/env python3
"""Plan and apply approval-gated GitHub issue comments for CodeQL triage."""

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus


PLAN_SCHEMA = "codeql-triage-issue-comments/v1"
RECEIPT_SCHEMA = "codeql-triage-issue-comments-receipt/v1"
TRIAGE_SCHEMA = "triage-finding/v0"
VERDICTS = {"confirmed", "needs_review", "not_actionable"}
WRITE_MODE = "github_issue_comment"
GITHUB_HOST = "github.com"
GITHUB_API_VERSION = "2026-03-10"
MAX_BATCH_SIZE = 25
MAX_GITHUB_BODY = 65536
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ALERT_URL_PATTERN = re.compile(
    r"(?:/security/code-scanning/|/code-scanning/alerts/)([0-9]+)(?:$|[/?#])"
)


class WritebackError(RuntimeError):
    pass


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise WritebackError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise WritebackError(f"top-level JSON value in {path} must be an object")
    return value, raw


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
                raise WritebackError(f"file already exists: {path}") from error
            temporary_path.unlink()
        else:
            os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WritebackError(f"{field} must be a non-empty string")
    return value.strip()


def validate_repository(repository: Any) -> str:
    value = require_string(repository, "repository")
    if not REPOSITORY_PATTERN.fullmatch(value):
        raise WritebackError("repository must use owner/repo format")
    return value


def run_command(command: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise WritebackError(f"{' '.join(command[:3])}: {message}")
    return result.stdout.strip()


def git_value(repo_root: Path, *arguments: str) -> str:
    return run_command(["git", *arguments], cwd=repo_root)


def canonical_repo_root() -> Path:
    return Path(run_command(["git", "rev-parse", "--show-toplevel"])).resolve()


def relative_report_path(report: Path, repo_root: Path) -> str:
    resolved = report.resolve()
    if not resolved.is_file():
        raise WritebackError(f"report does not exist: {report}")
    try:
        return resolved.relative_to(repo_root).as_posix()
    except ValueError as error:
        raise WritebackError("report must be inside the current repository") from error


def github_references(finding: dict[str, Any]) -> list[str]:
    normalized = finding.get("normalized_input")
    if not isinstance(normalized, dict):
        return []
    references = normalized.get("references")
    if not isinstance(references, list):
        return []
    return [reference for reference in references if isinstance(reference, str)]


def extract_alert_number(finding: dict[str, Any]) -> int:
    for reference in github_references(finding):
        match = ALERT_URL_PATTERN.search(reference)
        if match:
            return int(match.group(1))
    input_id = str(finding.get("input_id", ""))
    match = re.search(r"(?:alert|code[-_ ]?scanning)[^0-9]*([0-9]+)$", input_id, re.I)
    if match:
        return int(match.group(1))
    raise WritebackError(
        f"cannot resolve GitHub alert number for {finding.get('triage_item_id', 'unknown')}"
    )


def extract_alert_url(finding: dict[str, Any], repository: str, number: int) -> str:
    for reference in github_references(finding):
        if "github.com/" in reference and ALERT_URL_PATTERN.search(reference):
            return reference
    return f"https://github.com/{repository}/security/code-scanning/{number}"


def validate_triage(triage: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    if triage.get("schema_version") != TRIAGE_SCHEMA:
        raise WritebackError(f'triage schema_version must be "{TRIAGE_SCHEMA}"')
    repository = triage.get("repository")
    if not isinstance(repository, dict):
        raise WritebackError("triage.repository must be an object")
    revision = require_string(repository.get("revision"), "triage.repository.revision")
    findings = triage.get("findings")
    if not isinstance(findings, list):
        raise WritebackError("triage.findings must be an array")
    for index, finding in enumerate(findings):
        field = f"triage.findings[{index}]"
        if not isinstance(finding, dict):
            raise WritebackError(f"{field} must be an object")
        if finding.get("source_type") != "sarif":
            raise WritebackError(f"{field} is not a SARIF finding")
        verdict = finding.get("verdict")
        if verdict not in VERDICTS:
            raise WritebackError(f"{field} has an invalid verdict")
        require_string(finding.get("triage_item_id"), f"{field}.triage_item_id")
        require_string(finding.get("input_id"), f"{field}.input_id")
        if verdict == "confirmed":
            require_string(
                finding.get("fix_finding_handoff"), f"{field}.fix_finding_handoff"
            )
    return revision, findings


def clean_line(value: Any) -> str:
    return " ".join(str(value).split())


def list_lines(values: Any, fallback: str) -> list[str]:
    if not isinstance(values, list):
        return [fallback]
    result = [clean_line(value) for value in values if clean_line(value)]
    return result or [fallback]


def location_lines(finding: dict[str, Any]) -> list[str]:
    locations = finding.get("affected_locations")
    if not isinstance(locations, list):
        return ["- unavailable"]
    result = []
    for location in locations:
        if not isinstance(location, dict):
            continue
        path = clean_line(location.get("path", "unknown"))
        lines = clean_line(location.get("lines", "unknown"))
        label = clean_line(location.get("label", "location"))
        result.append(f"- {label}: `{path}:{lines}`")
    return result or ["- unavailable"]


def finding_fingerprint(repository: str, alert_number: int, finding_id: str) -> str:
    value = f"{repository}\n{alert_number}\n{finding_id}\n".encode("utf-8")
    return sha256(value)


def build_comment(
    finding: dict[str, Any],
    repository: str,
    branch: str,
    revision: str,
    report_path: str,
    alert_number: int,
    alert_url: str,
    fingerprint: str,
) -> str:
    finding_id = require_string(finding.get("input_id"), "finding.input_id")
    triage_item_id = require_string(
        finding.get("triage_item_id"), "finding.triage_item_id"
    )
    verdict = require_string(finding.get("verdict"), "finding.verdict")
    confidence = clean_line(finding.get("confidence", "unknown"))
    next_step = clean_line(finding.get("recommended_next_step", "unspecified"))
    handoff = finding.get("fix_finding_handoff")
    handoff_text = clean_line(handoff) if isinstance(handoff, str) else "not applicable"
    evidence = list_lines(finding.get("evidence"), "No affirmative evidence recorded.")
    counterevidence = list_lines(
        finding.get("counterevidence"), "No counterevidence recorded."
    )
    proof_gaps = list_lines(finding.get("proof_gaps"), "None recorded.")

    parts = [
        f"<!-- codex-codeql-triage:v1 finding-id={finding_id} -->",
        "## Codex Security CodeQL triage",
        "",
        f"Status: `{verdict}`",
        f"Finding ID: `{finding_id}`",
        f"Triage item ID: `{triage_item_id}`",
        f"Finding fingerprint: `{fingerprint}`",
        f"Report path: `{report_path}`",
        f"Code scanning alert: [#{alert_number}]({alert_url})",
        f"Repository: `{repository}`",
        f"Branch: `{branch}`",
        f"Revision: `{revision}`",
        f"Confidence: `{confidence}`",
        "",
        "### Affected locations",
        *location_lines(finding),
        "",
        "### Evidence",
        *[f"- {value}" for value in evidence],
        "",
        "### Counterevidence",
        *[f"- {value}" for value in counterevidence],
        "",
        "### Proof gaps",
        *[f"- {value}" for value in proof_gaps],
        "",
        f"Recommended next step: `{next_step}`",
        f"Fix-finding handoff: {handoff_text}",
    ]
    comment = "\n".join(parts).strip() + "\n"
    if len(comment) > MAX_GITHUB_BODY:
        raise WritebackError(f"finding {finding_id}: comment exceeds GitHub body limit")
    return comment


def build_issue_body(
    finding_id: str,
    fingerprint: str,
    alert_url: str,
    report_path: str,
) -> str:
    return (
        "This issue tracks one GitHub Code Scanning finding without changing the "
        "alert state.\n\n"
        f"Finding ID: `{finding_id}`\n"
        f"Finding fingerprint: `{fingerprint}`\n"
        f"Code scanning alert: {alert_url}\n"
        f"Report path: `{report_path}`\n\n"
        "After creation, link this issue from the alert's **Tracking** section in "
        "the GitHub UI. GitHub does not currently expose that relationship through "
        "its public REST or GraphQL APIs.\n"
    )


def gh_command(arguments: list[str]) -> str:
    if shutil.which("gh") is None:
        raise WritebackError("GitHub CLI is not installed")
    return run_command(["gh", *arguments])


def gh_with_body(arguments: list[str], body: str) -> str:
    descriptor, name = tempfile.mkstemp(prefix="codeql-triage-", suffix=".md")
    temporary_path = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as body_file:
            body_file.write(body)
        return gh_command([*arguments, "--body-file", str(temporary_path)])
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def gh_issue_view(repository: str, issue: str | int) -> dict[str, Any]:
    output = gh_command(
        [
            "issue",
            "view",
            str(issue),
            "--repo",
            repository,
            "--json",
            "number,url,title,body,state,comments",
        ]
    )
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise WritebackError("gh issue view returned invalid JSON") from error
    if not isinstance(value, dict):
        raise WritebackError("gh issue view returned a non-object")
    return value


def gh_api(method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
    command = [
        "api",
        "--hostname",
        GITHUB_HOST,
        "--method",
        method,
        endpoint,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
    ]
    temporary_path: Path | None = None
    try:
        if body is not None:
            descriptor, name = tempfile.mkstemp(prefix="codeql-triage-", suffix=".json")
            temporary_path = Path(name)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as body_file:
                body_file.write(json_bytes(body))
            command.extend(["--input", str(temporary_path)])
        output = gh_command(command)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise WritebackError(f"{method} {endpoint}: invalid JSON response") from error


def github_context(repository: str) -> dict[str, Any]:
    gh_command(["auth", "status", "--hostname", GITHUB_HOST])
    profile = gh_api("GET", "user")
    output = gh_command(
        [
            "repo",
            "view",
            f"{GITHUB_HOST}/{repository}",
            "--json",
            "nameWithOwner,visibility,hasIssuesEnabled,viewerPermission,url",
        ]
    )
    try:
        metadata = json.loads(output)
    except json.JSONDecodeError as error:
        raise WritebackError("gh repo view returned invalid JSON") from error
    if metadata.get("nameWithOwner", "").lower() != repository.lower():
        raise WritebackError("GitHub repository identity does not match")
    if metadata.get("hasIssuesEnabled") is not True:
        raise WritebackError("GitHub Issues is not enabled for the repository")
    permission = metadata.get("viewerPermission")
    if permission not in {"ADMIN", "MAINTAIN", "WRITE"}:
        raise WritebackError(f"GitHub issue write permission is required, found {permission!r}")
    return {
        "host": GITHUB_HOST,
        "login": require_string(profile.get("login"), "GitHub login"),
        "repository": metadata["nameWithOwner"],
        "repository_url": metadata.get("url"),
        "visibility": metadata.get("visibility"),
        "viewer_permission": permission,
    }


def paged_issue_comments(repository: str, issue_number: int) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    page = 1
    while True:
        batch = gh_api(
            "GET",
            f"repos/{repository}/issues/{issue_number}/comments?per_page=100&page={page}",
        )
        if not isinstance(batch, list) or not all(isinstance(value, dict) for value in batch):
            raise WritebackError(f"issue {issue_number}: invalid comments response")
        comments.extend(batch)
        if len(batch) < 100:
            return comments
        page += 1


def find_tracking_issue(
    repository: str, finding_id: str, fingerprint: str, comment: str
) -> dict[str, Any]:
    query = f'repo:{repository} is:issue "Finding ID: `{finding_id}`" in:body'
    response = gh_api("GET", f"search/issues?q={quote_plus(query)}&per_page=100")
    if not isinstance(response, dict) or not isinstance(response.get("items"), list):
        raise WritebackError(f"finding {finding_id}: invalid duplicate search response")
    matches = []
    binding = f"Finding ID: `{finding_id}`"
    fingerprint_binding = f"Finding fingerprint: `{fingerprint}`"
    for candidate in response["items"]:
        if not isinstance(candidate, dict) or "pull_request" in candidate:
            continue
        number = candidate.get("number")
        if not isinstance(number, int):
            continue
        issue = gh_api("GET", f"repos/{repository}/issues/{number}")
        body = issue.get("body") if isinstance(issue, dict) else None
        if isinstance(body, str) and binding in body and fingerprint_binding in body:
            matches.append(issue)
    if len(matches) > 1:
        numbers = sorted(issue.get("number") for issue in matches)
        raise WritebackError(f"finding {finding_id}: duplicate tracking issues {numbers}")
    if not matches:
        return {"outcome": "create", "issue": None, "comment_exists": False}
    issue = matches[0]
    number = issue["number"]
    comments = paged_issue_comments(repository, number)
    exact_comment = any(value.get("body") == comment for value in comments)
    return {
        "outcome": "reuse" if exact_comment else "comment",
        "issue": issue,
        "comment_exists": exact_comment,
    }


def build_plan(args: argparse.Namespace) -> int:
    requested = list(dict.fromkeys(args.alert))
    if len(requested) != len(args.alert):
        raise WritebackError("duplicate --alert values are not allowed")
    if len(requested) > MAX_BATCH_SIZE:
        raise WritebackError(f"a GitHub issue batch cannot exceed {MAX_BATCH_SIZE} findings")

    repo_root = canonical_repo_root()
    triage_path = Path(args.triage).resolve()
    triage, triage_raw = read_json(triage_path)
    revision, findings = validate_triage(triage)
    branch = require_string(args.branch, "branch")
    if git_value(repo_root, "rev-parse", "--abbrev-ref", "HEAD") != branch:
        raise WritebackError("requested branch is not the current checkout")
    if git_value(repo_root, "rev-parse", "HEAD") != revision:
        raise WritebackError("triage revision is not the current checkout revision")

    report = Path(args.report)
    report_path = relative_report_path(report, repo_root)
    report_raw = report.resolve().read_bytes()
    repository = validate_repository(args.repository)
    context = github_context(repository)

    by_number: dict[int, dict[str, Any]] = {}
    for finding in findings:
        number = extract_alert_number(finding)
        if number in by_number:
            raise WritebackError(f"duplicate alert number in triage: {number}")
        by_number[number] = finding
    missing = sorted(set(requested) - set(by_number))
    if missing:
        raise WritebackError(f"alert numbers not found in triage: {missing}")

    items = []
    for number in requested:
        finding = by_number[number]
        finding_id = require_string(finding.get("input_id"), "finding.input_id")
        alert_url = extract_alert_url(finding, repository, number)
        fingerprint = finding_fingerprint(repository, number, finding_id)
        comment = build_comment(
            finding,
            repository,
            branch,
            revision,
            report_path,
            number,
            alert_url,
            fingerprint,
        )
        duplicate = find_tracking_issue(repository, finding_id, fingerprint, comment)
        issue = duplicate["issue"]
        issue_number = issue.get("number") if isinstance(issue, dict) else None
        issue_url = issue.get("html_url") if isinstance(issue, dict) else None
        verdict = finding["verdict"]
        title = clean_line(finding.get("title", "CodeQL alert"))
        issue_title = f"[CodeQL][{verdict}][#{number}] {title}"[:256]
        items.append(
            {
                "alert_number": number,
                "alert_url": alert_url,
                "finding_id": finding_id,
                "triage_item_id": finding["triage_item_id"],
                "finding_fingerprint": fingerprint,
                "verdict": verdict,
                "title": title,
                "action": duplicate["outcome"],
                "issue_number": issue_number,
                "issue_url": issue_url,
                "issue_title": issue_title,
                "issue_body": build_issue_body(
                    finding_id, fingerprint, alert_url, report_path
                ),
                "comment": comment,
                "manual_link_required": True,
            }
        )

    plan = {
        "schema_version": PLAN_SCHEMA,
        "repository": repository,
        "branch": branch,
        "triage_revision": revision,
        "triage_path": triage_path.relative_to(repo_root).as_posix(),
        "triage_sha256": sha256(triage_raw),
        "report_path": report_path,
        "report_sha256": sha256(report_raw),
        "github": context,
        "created_at": utc_timestamp(),
        "write_mode": WRITE_MODE,
        "manual_link_required": True,
        "items": items,
    }
    validate_plan(plan)
    output_path = Path(args.output)
    atomic_write(output_path, json_bytes(plan))
    print(json.dumps(plan_summary(plan, output_path), indent=2, sort_keys=True))
    return 0


def validate_plan(plan: dict[str, Any]) -> list[dict[str, Any]]:
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise WritebackError(f'plan schema_version must be "{PLAN_SCHEMA}"')
    validate_repository(plan.get("repository"))
    require_string(plan.get("branch"), "plan.branch")
    require_string(plan.get("triage_revision"), "plan.triage_revision")
    require_string(plan.get("triage_path"), "plan.triage_path")
    require_string(plan.get("report_path"), "plan.report_path")
    for digest_name in ("triage_sha256", "report_sha256"):
        digest = require_string(plan.get(digest_name), f"plan.{digest_name}")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise WritebackError(f"plan.{digest_name} must be a lowercase SHA-256")
    if plan.get("write_mode") != WRITE_MODE:
        raise WritebackError("plan.write_mode must be github_issue_comment")
    if plan.get("manual_link_required") is not True:
        raise WritebackError("plan must disclose that manual alert linking is required")
    github = plan.get("github")
    if not isinstance(github, dict):
        raise WritebackError("plan.github must be an object")
    require_string(github.get("login"), "plan.github.login")
    if github.get("host") != GITHUB_HOST:
        raise WritebackError(f"plan.github.host must be {GITHUB_HOST}")

    items = plan.get("items")
    if not isinstance(items, list) or not items:
        raise WritebackError("plan.items must contain one to 25 findings")
    if len(items) > MAX_BATCH_SIZE:
        raise WritebackError(f"plan.items cannot exceed {MAX_BATCH_SIZE} findings")
    numbers: set[int] = set()
    for index, item in enumerate(items):
        field = f"plan.items[{index}]"
        if not isinstance(item, dict):
            raise WritebackError(f"{field} must be an object")
        number = item.get("alert_number")
        if not isinstance(number, int) or number < 1 or number in numbers:
            raise WritebackError(f"{field}.alert_number must be unique and positive")
        numbers.add(number)
        if item.get("verdict") not in VERDICTS:
            raise WritebackError(f"{field}.verdict is invalid")
        finding_id = require_string(item.get("finding_id"), f"{field}.finding_id")
        report_binding = f"Report path: `{plan['report_path']}`"
        comment = require_string(item.get("comment"), f"{field}.comment")
        if f"Finding ID: `{finding_id}`" not in comment:
            raise WritebackError(f"{field}.comment is missing finding-id")
        if report_binding not in comment:
            raise WritebackError(f"{field}.comment is missing report-path")
        if f"Status: `{item['verdict']}`" not in comment:
            raise WritebackError(f"{field}.comment is missing verdict status")
        if len(comment) > MAX_GITHUB_BODY:
            raise WritebackError(f"{field}.comment exceeds GitHub body limit")
        action = item.get("action")
        if action not in {"create", "comment", "reuse"}:
            raise WritebackError(f"{field}.action is invalid")
        if action in {"comment", "reuse"}:
            if not isinstance(item.get("issue_number"), int):
                raise WritebackError(f"{field}.issue_number is required")
            require_string(item.get("issue_url"), f"{field}.issue_url")
        if item.get("manual_link_required") is not True:
            raise WritebackError(f"{field} must require manual alert linking")
    return items


def action_counts(plan: dict[str, Any]) -> dict[str, int]:
    return {
        action: sum(item["action"] == action for item in plan["items"])
        for action in ("create", "comment", "reuse")
    }


def verdict_alerts(plan: dict[str, Any]) -> dict[str, list[int]]:
    return {
        verdict: [
            item["alert_number"]
            for item in plan["items"]
            if item["verdict"] == verdict
        ]
        for verdict in ("confirmed", "needs_review", "not_actionable")
    }


def plan_summary(plan: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "plan_path": str(path),
        "repository": plan["repository"],
        "branch": plan["branch"],
        "triage_revision": plan["triage_revision"],
        "report_path": plan["report_path"],
        "github_login": plan["github"]["login"],
        "github_visibility": plan["github"].get("visibility"),
        "write_mode": plan["write_mode"],
        "finding_count": len(plan["items"]),
        "verdict_alerts": verdict_alerts(plan),
        "action_counts": action_counts(plan),
        "manual_link_required": True,
        "github_modified": False,
    }


def preview_requests(plan: dict[str, Any]) -> list[dict[str, Any]]:
    requests = []
    for item in plan["items"]:
        if item["action"] == "reuse":
            continue
        if item["action"] == "create":
            requests.append(
                {
                    "finding_id": item["finding_id"],
                    "transport": "gh",
                    "command": [
                        "gh",
                        "issue",
                        "create",
                        "--repo",
                        plan["repository"],
                        "--title",
                        item["issue_title"],
                        "--body-file",
                        "<mode-0600-temporary-file>",
                    ],
                    "body_file_content": item["issue_body"],
                }
            )
            issue_selector: str | int = "<created_issue_number>"
        else:
            issue_selector = item["issue_number"]
        requests.append(
            {
                "finding_id": item["finding_id"],
                "transport": "gh",
                "command": [
                    "gh",
                    "issue",
                    "comment",
                    str(issue_selector),
                    "--repo",
                    plan["repository"],
                    "--body-file",
                    "<mode-0600-temporary-file>",
                ],
                "body_file_content": item["comment"],
            }
        )
    return requests


def preview_plan(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    plan, raw = read_json(plan_path)
    validate_plan(plan)
    preview = {
        "schema_version": PLAN_SCHEMA,
        "repository": plan["repository"],
        "branch": plan["branch"],
        "triage_revision": plan["triage_revision"],
        "report_path": plan["report_path"],
        "github": plan["github"],
        "write_mode": plan["write_mode"],
        "approval_token": sha256(raw),
        "verdict_alerts": verdict_alerts(plan),
        "action_counts": action_counts(plan),
        "requests": preview_requests(plan),
        "manual_link_required": True,
        "manual_link_instructions": (
            "For each resulting issue, open the Code Scanning alert, choose "
            "Tracking, and add the existing issue."
        ),
        "github_modified": False,
    }
    print(json.dumps(preview, indent=2, sort_keys=True))
    return 0


def revalidate_plan(plan: dict[str, Any], repo_root: Path) -> None:
    if git_value(repo_root, "rev-parse", "--abbrev-ref", "HEAD") != plan["branch"]:
        raise WritebackError("checkout branch changed after preview")
    if git_value(repo_root, "rev-parse", "HEAD") != plan["triage_revision"]:
        raise WritebackError("checkout revision changed after preview")
    triage_path = repo_root / plan["triage_path"]
    report_path = repo_root / plan["report_path"]
    if sha256(triage_path.read_bytes()) != plan["triage_sha256"]:
        raise WritebackError("triage artifact changed after preview")
    if sha256(report_path.read_bytes()) != plan["report_sha256"]:
        raise WritebackError("HTML report changed after preview")
    context = github_context(plan["repository"])
    if context != plan["github"]:
        raise WritebackError("GitHub identity, repository, visibility, or permission changed")
    for item in plan["items"]:
        duplicate = find_tracking_issue(
            plan["repository"],
            item["finding_id"],
            item["finding_fingerprint"],
            item["comment"],
        )
        issue = duplicate["issue"]
        issue_number = issue.get("number") if isinstance(issue, dict) else None
        if duplicate["outcome"] != item["action"] or issue_number != item["issue_number"]:
            raise WritebackError(
                f"finding {item['finding_id']}: duplicate state changed after preview"
            )


def receipt_paths(plan_path: Path, receipt_root: str | None) -> tuple[Path, Path]:
    root = Path(receipt_root) if receipt_root else plan_path.parent / "receipts"
    history = root / "history" / f"{utc_timestamp()}.json"
    return root / "current.json", history


def persist_receipt(
    receipt: dict[str, Any], current_path: Path, history_path: Path
) -> None:
    content = json_bytes(receipt)
    atomic_write(history_path, content, exclusive=True)
    atomic_write(current_path, content)


def apply_plan(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    plan, raw = read_json(plan_path)
    items = validate_plan(plan)
    token = sha256(raw)
    if args.approval_token != token:
        raise WritebackError("approval token does not match; preview the plan again")
    repo_root = canonical_repo_root()
    revalidate_plan(plan, repo_root)

    current_receipt, history_receipt = receipt_paths(plan_path, args.receipt_root)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "repository": plan["repository"],
        "branch": plan["branch"],
        "triage_revision": plan["triage_revision"],
        "triage_sha256": plan["triage_sha256"],
        "report_path": plan["report_path"],
        "report_sha256": plan["report_sha256"],
        "plan_sha256": token,
        "github": plan["github"],
        "write_mode": plan["write_mode"],
        "started_at": utc_timestamp(),
        "completed_at": None,
        "complete": False,
        "manual_link_required": True,
        "results": [],
    }

    for item in items:
        result = {
            "alert_number": item["alert_number"],
            "alert_url": item["alert_url"],
            "finding_id": item["finding_id"],
            "verdict": item["verdict"],
            "action": item["action"],
            "issue_number": item["issue_number"],
            "issue_url": item["issue_url"],
            "comment_url": None,
            "manual_link_required": True,
            "outcome": None,
        }
        try:
            if item["action"] == "reuse":
                result["outcome"] = "already_commented"
            else:
                if item["action"] == "create":
                    issue_url = gh_with_body(
                        [
                            "issue",
                            "create",
                            "--repo",
                            plan["repository"],
                            "--title",
                            item["issue_title"],
                        ],
                        item["issue_body"],
                    )
                    issue = gh_issue_view(plan["repository"], issue_url)
                    if (
                        not isinstance(issue, dict)
                        or not isinstance(issue.get("number"), int)
                        or issue.get("title") != item["issue_title"]
                        or issue.get("body") != item["issue_body"]
                    ):
                        raise WritebackError(
                            f"finding {item['finding_id']}: issue create readback failed"
                        )
                    result["issue_number"] = issue["number"]
                    result["issue_url"] = issue.get("url")
                issue_number = result["issue_number"]
                gh_with_body(
                    [
                        "issue",
                        "comment",
                        str(issue_number),
                        "--repo",
                        plan["repository"],
                    ],
                    item["comment"],
                )
                issue_readback = gh_issue_view(plan["repository"], issue_number)
                comments = issue_readback.get("comments")
                matching_comments = (
                    [value for value in comments if value.get("body") == item["comment"]]
                    if isinstance(comments, list)
                    else []
                )
                if not matching_comments:
                    raise WritebackError(
                        f"finding {item['finding_id']}: comment readback failed"
                    )
                result["comment_url"] = matching_comments[-1].get("url")
                result["outcome"] = (
                    "issue_created_and_commented"
                    if item["action"] == "create"
                    else "comment_added"
                )
        except (WritebackError, OSError) as error:
            result["outcome"] = "uncertain"
            result["error"] = str(error)
            receipt["results"].append(result)
            receipt["completed_at"] = utc_timestamp()
            persist_receipt(receipt, current_receipt, history_receipt)
            raise WritebackError(
                f"finding {item['finding_id']}: write or readback failed; "
                "inspect the partial receipt before retrying"
            ) from error
        receipt["results"].append(result)

    receipt["complete"] = True
    receipt["completed_at"] = utc_timestamp()
    persist_receipt(receipt, current_receipt, history_receipt)
    print(
        json.dumps(
            {
                "receipt_path": str(current_receipt),
                "history_receipt_path": str(history_receipt),
                "complete": True,
                "result_count": len(receipt["results"]),
                "manual_link_required": True,
                "github_modified": any(
                    result["outcome"] != "already_commented"
                    for result in receipt["results"]
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan and apply approval-gated GitHub issue comments for CodeQL triage."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="Build a live duplicate-checked plan.")
    plan_parser.add_argument("--triage", required=True)
    plan_parser.add_argument("--report", required=True)
    plan_parser.add_argument("--repository", required=True)
    plan_parser.add_argument("--branch", required=True)
    plan_parser.add_argument("--alert", action="append", type=int, required=True)
    plan_parser.add_argument("--output", required=True)
    plan_parser.set_defaults(handler=build_plan)

    preview_parser = subparsers.add_parser(
        "preview", help="Print every exact GitHub issue/comment request and approval token."
    )
    preview_parser.add_argument("--plan", required=True)
    preview_parser.set_defaults(handler=preview_plan)

    apply_parser = subparsers.add_parser(
        "apply", help="Apply an explicitly approved issue/comment plan."
    )
    apply_parser.add_argument("--plan", required=True)
    apply_parser.add_argument("--approval-token", required=True)
    apply_parser.add_argument("--receipt-root")
    apply_parser.set_defaults(handler=apply_plan)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return args.handler(args)
    except (WritebackError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
