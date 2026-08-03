#!/usr/bin/env python3
"""Plan and submit approval-gated CodeQL dismissal requests."""

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


PLAN_SCHEMA = "codeql-triage-writeback/v1"
RECEIPT_SCHEMA = "codeql-triage-writeback-receipt/v1"
TRIAGE_SCHEMA = "triage-finding/v0"
VERDICTS = {"confirmed", "needs_review", "not_actionable"}
DISMISSAL_REASONS = {"false positive", "won't fix", "used in tests"}
WRITE_MODE = "dismissal_request"
GITHUB_API_VERSION = "2026-03-10"
MAX_DISMISSED_COMMENT_LENGTH = 280
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ALERT_URL_PATTERN = re.compile(
    r"(?:/security/code-scanning/|/code-scanning/alerts/)([0-9]+)(?:$|[/?#])"
)


class WritebackError(RuntimeError):
    pass


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise WritebackError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise WritebackError(f"top-level JSON value in {path} must be an object")
    return value, raw


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


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


def validate_repository(repository: str) -> str:
    value = require_string(repository, "repository")
    if not REPOSITORY_PATTERN.fullmatch(value):
        raise WritebackError("repository must use owner/repo format")
    return value


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
    if input_id.isdigit():
        return int(input_id)
    raise WritebackError(
        f"cannot resolve GitHub alert number for {finding.get('triage_item_id', 'unknown')}"
    )


def extract_alert_url(finding: dict[str, Any], repository: str, number: int) -> str:
    for reference in github_references(finding):
        if "github.com/" in reference and ALERT_URL_PATTERN.search(reference):
            return reference
    return f"https://github.com/{repository}/security/code-scanning/{number}"


def summarize_not_actionable(finding: dict[str, Any]) -> str:
    for field in ("counterevidence", "evidence"):
        values = finding.get(field)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and value.strip():
                    return " ".join(value.split())[:500]
    return require_string(finding.get("title"), "finding.title")[:500]


def build_dismissed_comment(
    plan: dict[str, Any], item: dict[str, Any], reason: str
) -> str:
    prefix = (
        "Codex triage verdict: not_actionable\n"
        f"GitHub disposition: {reason}\n"
        f"Triage item: {item['triage_item_id']}\n"
        f"Revision: {plan['triage_revision'][:12]}\n"
        "Evidence: "
    )
    suffix = f"\nArtifact SHA-256: {plan['triage_sha256'][:16]}"
    available = MAX_DISMISSED_COMMENT_LENGTH - len(prefix) - len(suffix)
    if available < 4:
        raise WritebackError("dismissal comment metadata exceeds GitHub limit")

    summary = require_string(item.get("summary"), "dismissal summary")
    if len(summary) > available:
        summary = summary[: available - 3].rstrip() + "..."
    return prefix + summary + suffix


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
        if not isinstance(finding, dict):
            raise WritebackError(f"triage.findings[{index}] must be an object")
        if finding.get("source_type") != "sarif":
            raise WritebackError(f"triage.findings[{index}] is not a SARIF finding")
        if finding.get("verdict") not in VERDICTS:
            raise WritebackError(f"triage.findings[{index}] has an invalid verdict")
        require_string(finding.get("triage_item_id"), f"triage.findings[{index}].triage_item_id")
        require_string(finding.get("input_id"), f"triage.findings[{index}].input_id")
    return revision, findings


def build_plan(args: argparse.Namespace) -> int:
    triage_path = Path(args.triage)
    triage, triage_raw = read_json(triage_path)
    revision, findings = validate_triage(triage)
    repository = validate_repository(args.repository)
    branch = require_string(args.branch, "branch")

    items = []
    alert_numbers: set[int] = set()
    for finding in findings:
        number = extract_alert_number(finding)
        if number in alert_numbers:
            raise WritebackError(f"duplicate GitHub alert number in triage: {number}")
        alert_numbers.add(number)
        verdict = finding["verdict"]
        item = {
            "alert_number": number,
            "alert_url": extract_alert_url(finding, repository, number),
            "triage_item_id": finding["triage_item_id"],
            "input_id": finding["input_id"],
            "title": finding.get("title", "CodeQL alert"),
            "verdict": verdict,
            "confidence": finding.get("confidence"),
            "action": "pending" if verdict == "not_actionable" else "keep_open",
            "selected": False,
            "dismissed_reason": None,
            "dismissed_comment": None,
            "summary": summarize_not_actionable(finding)
            if verdict == "not_actionable"
            else None,
        }
        items.append(item)

    plan = {
        "schema_version": PLAN_SCHEMA,
        "repository": repository,
        "branch": branch,
        "triage_revision": revision,
        "triage_path": str(triage_path),
        "triage_sha256": sha256(triage_raw),
        "created_at": utc_timestamp(),
        "write_mode": args.write_mode,
        "items": items,
    }
    validate_plan(plan, require_selection=False)
    output_path = Path(args.output)
    atomic_write(output_path, json_bytes(plan))
    print(json.dumps(plan_summary(plan, output_path), indent=2, sort_keys=True))
    return 0


def validate_plan(
    plan: dict[str, Any], require_selection: bool
) -> list[dict[str, Any]]:
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise WritebackError(f'plan schema_version must be "{PLAN_SCHEMA}"')
    validate_repository(plan.get("repository"))
    require_string(plan.get("branch"), "plan.branch")
    require_string(plan.get("triage_revision"), "plan.triage_revision")
    digest = require_string(plan.get("triage_sha256"), "plan.triage_sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise WritebackError("plan.triage_sha256 must be a lowercase SHA-256 digest")
    if plan.get("write_mode") != WRITE_MODE:
        raise WritebackError(
            "plan.write_mode must be dismissal_request; direct dismissal is disabled"
        )

    items = plan.get("items")
    if not isinstance(items, list):
        raise WritebackError("plan.items must be an array")
    numbers: set[int] = set()
    selected: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        field = f"plan.items[{index}]"
        if not isinstance(item, dict):
            raise WritebackError(f"{field} must be an object")
        number = item.get("alert_number")
        if not isinstance(number, int) or number < 1:
            raise WritebackError(f"{field}.alert_number must be a positive integer")
        if number in numbers:
            raise WritebackError(f"duplicate plan alert number: {number}")
        numbers.add(number)
        verdict = item.get("verdict")
        action = item.get("action")
        selected_for_dismissal = item.get("selected")
        if verdict not in VERDICTS:
            raise WritebackError(f"{field}.verdict is invalid")
        if not isinstance(selected_for_dismissal, bool):
            raise WritebackError(f"{field}.selected must be boolean")

        if verdict in {"confirmed", "needs_review"}:
            if action != "keep_open" or selected_for_dismissal:
                raise WritebackError(
                    f"alert {number}: {verdict} must remain unselected and keep_open"
                )
            if item.get("dismissed_reason") is not None:
                raise WritebackError(f"alert {number}: keep_open cannot have a reason")
        elif action == "pending":
            if selected_for_dismissal or item.get("dismissed_reason") is not None:
                raise WritebackError(
                    f"alert {number}: pending item cannot be selected or have a reason"
                )
        elif action == "request_dismissal":
            if not selected_for_dismissal:
                raise WritebackError(f"alert {number}: dismissal must be selected")
            if item.get("dismissed_reason") not in DISMISSAL_REASONS:
                raise WritebackError(f"alert {number}: invalid dismissal reason")
            comment = require_string(
                item.get("dismissed_comment"), f"alert {number}.dismissed_comment"
            )
            if not comment.startswith("Codex triage verdict: not_actionable"):
                raise WritebackError(f"alert {number}: dismissal comment lost verdict")
            if len(comment) > MAX_DISMISSED_COMMENT_LENGTH:
                raise WritebackError(
                    f"alert {number}: dismissal comment exceeds GitHub's "
                    f"{MAX_DISMISSED_COMMENT_LENGTH}-character limit"
                )
            selected.append(item)
        else:
            raise WritebackError(f"alert {number}: invalid action {action!r}")

    if require_selection and not selected:
        raise WritebackError("plan has no selected dismissal candidates")
    return selected


def plan_summary(plan: dict[str, Any], path: Path) -> dict[str, Any]:
    counts = {"keep_open": 0, "pending": 0, "request_dismissal": 0}
    for item in plan["items"]:
        counts[item["action"]] += 1
    return {
        "plan_path": str(path),
        "repository": plan["repository"],
        "branch": plan["branch"],
        "triage_revision": plan["triage_revision"],
        "write_mode": plan["write_mode"],
        "action_counts": counts,
        "github_modified": False,
    }


def select_items(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    plan, _ = read_json(plan_path)
    validate_plan(plan, require_selection=False)
    requested = set(args.alert)
    found: set[int] = set()
    for item in plan["items"]:
        number = item["alert_number"]
        if number not in requested:
            continue
        found.add(number)
        if item["verdict"] != "not_actionable":
            raise WritebackError(
                f"alert {number}: only not_actionable findings may be dismissed"
            )
        item["action"] = "request_dismissal"
        item["selected"] = True
        item["dismissed_reason"] = args.reason
        item["dismissed_comment"] = build_dismissed_comment(
            plan, item, args.reason
        )

    missing = sorted(requested - found)
    if missing:
        raise WritebackError(f"alert numbers not found in plan: {missing}")
    validate_plan(plan, require_selection=True)
    atomic_write(plan_path, json_bytes(plan))
    print(json.dumps(plan_summary(plan, plan_path), indent=2, sort_keys=True))
    return 0


def preview_plan(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    plan, raw = read_json(plan_path)
    selected = validate_plan(plan, require_selection=True)
    preview = {
        "schema_version": PLAN_SCHEMA,
        "repository": plan["repository"],
        "branch": plan["branch"],
        "triage_revision": plan["triage_revision"],
        "write_mode": plan["write_mode"],
        "approval_token": sha256(raw),
        "requests": [
            {
                "method": "PATCH",
                "endpoint": (
                    f"/repos/{plan['repository']}/code-scanning/alerts/"
                    f"{item['alert_number']}"
                ),
                "alert_url": item["alert_url"],
                "body": {
                    "state": "dismissed",
                    "dismissed_reason": item["dismissed_reason"],
                    "dismissed_comment": item["dismissed_comment"],
                    "create_request": True,
                },
            }
            for item in selected
        ],
        "keep_open_count": sum(
            item["action"] == "keep_open" for item in plan["items"]
        ),
        "pending_count": sum(item["action"] == "pending" for item in plan["items"]),
        "github_modified": False,
    }
    print(json.dumps(preview, indent=2, sort_keys=True))
    return 0


def gh_api(method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
    if shutil.which("gh") is None:
        raise WritebackError("GitHub CLI is not installed")
    command = [
        "gh",
        "api",
        "--method",
        method,
        endpoint,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
    ]
    if body is not None:
        command.extend(["--input", "-"])
    result = subprocess.run(
        command,
        input=json.dumps(body) if body is not None else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or "GitHub API request failed"
        raise WritebackError(f"{method} {endpoint}: {message}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise WritebackError(f"{method} {endpoint}: invalid JSON response") from error


def normalized_ref(branch: str) -> str:
    return branch if branch.startswith("refs/") else f"refs/heads/{branch}"


def normalized_alert_state(alert: dict[str, Any]) -> str | None:
    state = alert.get("state")
    if isinstance(state, str):
        return state

    if alert.get("dismissed_at") is not None:
        return "dismissed"
    if alert.get("fixed_at") is not None:
        return "fixed"

    most_recent_instance = alert.get("most_recent_instance")
    if (
        isinstance(most_recent_instance, dict)
        and most_recent_instance.get("state") == "open"
    ):
        return "open"
    return None


def open_alerts_for_ref(repository: str, target_ref: str) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    page = 1
    while True:
        endpoint = (
            f"repos/{repository}/code-scanning/alerts"
            f"?state=open&ref={target_ref}&per_page=100&page={page}"
        )
        batch = gh_api("GET", endpoint)
        if not isinstance(batch, list) or not all(
            isinstance(alert, dict) for alert in batch
        ):
            raise WritebackError("invalid branch-filtered open alerts response")
        alerts.extend(batch)
        if len(batch) < 100:
            return alerts
        page += 1


def request_entry_for_alert(
    request: dict[str, Any], alert_number: int
) -> dict[str, Any] | None:
    data = request.get("data")
    if not isinstance(data, list):
        return None
    for entry in data:
        if isinstance(entry, dict) and entry.get("alert_number") == alert_number:
            return entry
    return None


def dismissal_request_record(
    request: dict[str, Any], item: dict[str, Any]
) -> dict[str, Any]:
    number = item["alert_number"]
    if request.get("request_type") != "code_scanning_alert_dismissal":
        raise WritebackError(f"alert {number}: unexpected dismissal request type")
    if request.get("status") != "open":
        raise WritebackError(
            f"alert {number}: dismissal request is not open: "
            f"{request.get('status')!r}"
        )
    entry = request_entry_for_alert(request, number)
    if entry is None:
        raise WritebackError(
            f"alert {number}: dismissal request does not reference the alert"
        )
    if entry.get("reason") != item["dismissed_reason"]:
        raise WritebackError(
            f"alert {number}: dismissal request reason does not match the plan"
        )
    if request.get("requester_comment") != item["dismissed_comment"]:
        raise WritebackError(
            f"alert {number}: dismissal request comment does not match the plan"
        )

    requester = request.get("requester")
    return {
        "id": request.get("id"),
        "number": request.get("number"),
        "status": request["status"],
        "reason": entry["reason"],
        "requester_comment": request["requester_comment"],
        "requester": (
            requester.get("actor_name") if isinstance(requester, dict) else None
        ),
        "created_at": request.get("created_at"),
        "expires_at": request.get("expires_at"),
        "url": request.get("url"),
        "html_url": request.get("html_url"),
    }


def open_dismissal_requests(repository: str) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    page = 1
    while True:
        endpoint = (
            f"repos/{repository}/dismissal-requests/code-scanning"
            f"?request_status=open&per_page=100&page={page}"
        )
        try:
            batch = gh_api("GET", endpoint)
        except WritebackError as error:
            raise WritebackError(
                "cannot verify delegated CodeQL dismissal requests; ensure the "
                "feature is enabled and the token can read organization dismissal "
                f"requests: {error}"
            ) from error
        if not isinstance(batch, list) or not all(
            isinstance(request, dict) for request in batch
        ):
            raise WritebackError("invalid open dismissal requests response")
        requests.extend(batch)
        if len(batch) < 100:
            return requests
        page += 1


def preflight(plan: dict[str, Any], selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    repository = plan["repository"]
    target_ref = normalized_ref(plan["branch"])
    existing_requests: dict[int, dict[str, Any]] = {}
    for request in open_dismissal_requests(repository):
        data = request.get("data")
        if not isinstance(data, list):
            raise WritebackError("open dismissal request has invalid data")
        for entry in data:
            if not isinstance(entry, dict):
                raise WritebackError("open dismissal request has invalid data entry")
            alert_number = entry.get("alert_number")
            if not isinstance(alert_number, int):
                raise WritebackError("open dismissal request has invalid alert number")
            if alert_number in existing_requests:
                raise WritebackError(
                    f"alert {alert_number}: multiple open dismissal requests found"
                )
            existing_requests[alert_number] = request

    open_alerts = open_alerts_for_ref(repository, target_ref)
    open_by_number = {alert.get("number"): alert for alert in open_alerts}
    records = []
    for item in selected:
        number = item["alert_number"]
        endpoint = f"repos/{repository}/code-scanning/alerts/{number}"
        alert = open_by_number.get(number)
        if alert is None:
            alert = gh_api("GET", endpoint)
        if not isinstance(alert, dict) or alert.get("number") != number:
            raise WritebackError(f"alert {number}: GitHub identity check failed")
        actual_url = alert.get("html_url")
        expected_url = item.get("alert_url")
        if isinstance(actual_url, str) and isinstance(expected_url, str):
            if actual_url.rstrip("/").lower() != expected_url.rstrip("/").lower():
                raise WritebackError(f"alert {number}: GitHub URL does not match plan")

        state = normalized_alert_state(alert)
        if state != "open":
            raise WritebackError(
                f"alert {number}: expected open state, found {state!r}"
            )

        existing_request = existing_requests.get(number)
        existing_request_record = (
            dismissal_request_record(existing_request, item)
            if existing_request is not None
            else None
        )

        most_recent_instance = alert.get("most_recent_instance")
        matching = (
            [most_recent_instance]
            if isinstance(most_recent_instance, dict)
            and most_recent_instance.get("ref") == target_ref
            else []
        )
        if not matching:
            instances_endpoint = f"{endpoint}/instances?per_page=100"
            instances = gh_api("GET", instances_endpoint)
            if not isinstance(instances, list):
                raise WritebackError(f"alert {number}: invalid instances response")
            matching = [
                instance for instance in instances if instance.get("ref") == target_ref
            ]
        if not matching:
            raise WritebackError(
                f"alert {number}: no instance found for requested ref {target_ref}"
            )
        records.append(
            {
                "alert_number": number,
                "state_before": state,
                "already_requested": existing_request_record is not None,
                "dismissal_request_before": existing_request_record,
                "matching_ref": target_ref,
                "instance_commits": sorted(
                    {
                        instance.get("commit_sha")
                        for instance in matching
                        if isinstance(instance.get("commit_sha"), str)
                    }
                ),
            }
        )
    return records


def receipt_paths(plan_path: Path, receipt_root: str | None) -> tuple[Path, Path]:
    root = Path(receipt_root) if receipt_root else plan_path.parent / "receipts"
    timestamp = utc_timestamp()
    history = root / "history" / f"{timestamp}.json"
    current = root / "current.json"
    return current, history


def persist_receipt(
    receipt: dict[str, Any], current_path: Path, history_path: Path
) -> None:
    content = json_bytes(receipt)
    atomic_write(history_path, content, exclusive=True)
    atomic_write(current_path, content)


def apply_plan(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    plan, raw = read_json(plan_path)
    selected = validate_plan(plan, require_selection=True)
    actual_token = sha256(raw)
    if args.approval_token != actual_token:
        raise WritebackError(
            "approval token does not match the current plan; preview it again"
        )

    preflight_records = preflight(plan, selected)
    current_receipt, history_receipt = receipt_paths(plan_path, args.receipt_root)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "repository": plan["repository"],
        "branch": plan["branch"],
        "triage_revision": plan["triage_revision"],
        "triage_sha256": plan["triage_sha256"],
        "plan_sha256": actual_token,
        "write_mode": plan["write_mode"],
        "started_at": utc_timestamp(),
        "completed_at": None,
        "complete": False,
        "results": [],
    }

    for item, check in zip(selected, preflight_records):
        number = item["alert_number"]
        endpoint = f"repos/{plan['repository']}/code-scanning/alerts/{number}"
        request_endpoint = (
            f"repos/{plan['repository']}/dismissal-requests/code-scanning/{number}"
        )
        if check["already_requested"]:
            result_record = {
                **check,
                "outcome": "already_pending",
                "state_after": check["state_before"],
                "dismissal_request": check["dismissal_request_before"],
            }
        else:
            body = {
                "state": "dismissed",
                "dismissed_reason": item["dismissed_reason"],
                "dismissed_comment": item["dismissed_comment"],
                "create_request": True,
            }
            try:
                gh_api("PATCH", endpoint, body)
                readback = gh_api("GET", endpoint)
                request_readback = gh_api("GET", request_endpoint)
                readback_state = normalized_alert_state(readback)
                if (
                    readback_state != "open"
                    or readback.get("dismissed_at") is not None
                    or readback.get("dismissed_reason") is not None
                    or readback.get("dismissed_comment") is not None
                ):
                    raise WritebackError(
                        f"alert {number}: expected open after dismissal request, "
                        f"found {readback_state!r}"
                    )
                request_record = dismissal_request_record(request_readback, item)
                result_record = {
                    **check,
                    "outcome": "request_submitted",
                    "state_after": readback_state,
                    "dismissed_reason_after": readback.get("dismissed_reason"),
                    "dismissed_comment_after": readback.get("dismissed_comment"),
                    "dismissed_at": readback.get("dismissed_at"),
                    "dismissal_request": request_record,
                }
            except WritebackError as error:
                receipt["results"].append(
                    {
                        **check,
                        "outcome": "request_verification_failed",
                        "error": str(error),
                    }
                )
                receipt["completed_at"] = utc_timestamp()
                persist_receipt(receipt, current_receipt, history_receipt)
                raise
        receipt["results"].append(result_record)

    receipt["complete"] = True
    receipt["completed_at"] = utc_timestamp()
    persist_receipt(receipt, current_receipt, history_receipt)
    print(
        json.dumps(
            {
                "receipt_path": str(current_receipt),
                "history_receipt_path": str(history_receipt),
                "request_submitted_count": sum(
                    result["outcome"] == "request_submitted"
                    for result in receipt["results"]
                ),
                "already_pending_count": sum(
                    result["outcome"] == "already_pending"
                    for result in receipt["results"]
                ),
                "complete": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan and submit approval-gated CodeQL dismissal requests."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan", help="Generate a local writeback plan.")
    plan_parser.add_argument("--triage", required=True)
    plan_parser.add_argument("--repository", required=True)
    plan_parser.add_argument("--branch", required=True)
    plan_parser.add_argument("--output", required=True)
    plan_parser.add_argument("--write-mode", choices=[WRITE_MODE], default=WRITE_MODE)
    plan_parser.set_defaults(handler=build_plan)

    select_parser = subparsers.add_parser(
        "select", help="Select not_actionable alerts for a dismissal request."
    )
    select_parser.add_argument("--plan", required=True)
    select_parser.add_argument("--alert", action="append", type=int, required=True)
    select_parser.add_argument("--reason", choices=sorted(DISMISSAL_REASONS), required=True)
    select_parser.set_defaults(handler=select_items)

    preview_parser = subparsers.add_parser(
        "preview", help="Print exact requests and an approval token."
    )
    preview_parser.add_argument("--plan", required=True)
    preview_parser.set_defaults(handler=preview_plan)

    apply_parser = subparsers.add_parser(
        "apply", help="Submit an explicitly approved plan through GitHub REST."
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
    except WritebackError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
