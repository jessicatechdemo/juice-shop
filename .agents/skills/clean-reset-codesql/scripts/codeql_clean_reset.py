#!/usr/bin/env python3
"""Plan, apply, and verify an approval-gated CodeQL branch reset."""

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


PLAN_SCHEMA = "codeql-clean-reset/v0"
RECEIPT_SCHEMA = "codeql-clean-reset-receipt/v0"
GITHUB_API_VERSION = "2026-03-10"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ResetError(RuntimeError):
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
        raise ResetError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise ResetError(f"top-level JSON value in {path} must be an object")
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
                raise ResetError(f"file already exists: {path}") from error
            temporary_path.unlink()
        else:
            os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ResetError(f"{field} must be a non-empty string")
    return value.strip()


def validate_repository(repository: str) -> str:
    value = require_string(repository, "repository")
    if not REPOSITORY_PATTERN.fullmatch(value):
        raise ResetError("repository must use owner/repo format")
    return value


def run_command(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or f"command failed: {' '.join(command[:3])}"
        raise ResetError(message)
    return result.stdout


def gh_api(method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
    if shutil.which("gh") is None:
        raise ResetError("GitHub CLI is not installed")
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
            input=json.dumps(body),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise ResetError(result.stderr.strip() or f"{method} {endpoint} failed")
        output = result.stdout
    else:
        output = run_command(command)
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise ResetError(f"{method} {endpoint}: invalid JSON response") from error


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
    instance = alert.get("most_recent_instance")
    if isinstance(instance, dict) and isinstance(instance.get("state"), str):
        return instance["state"]
    return None


def receipt_alerts(
    receipt: dict[str, Any], repository: str, branch: str
) -> list[dict[str, Any]]:
    if receipt.get("repository") != repository or receipt.get("branch") != branch:
        raise ResetError("writeback receipt repository or branch does not match")
    if receipt.get("complete") is not True:
        raise ResetError("writeback receipt is incomplete")
    results = receipt.get("results")
    if not isinstance(results, list):
        raise ResetError("writeback receipt results must be an array")
    alerts = []
    numbers: set[int] = set()
    for result in results:
        if not isinstance(result, dict) or result.get("outcome") != "dismissed":
            continue
        number = result.get("alert_number")
        if not isinstance(number, int) or number < 1 or number in numbers:
            raise ResetError("writeback receipt has an invalid alert number")
        reason = require_string(
            result.get("dismissed_reason_after"), f"alert {number} dismissal reason"
        )
        comment = require_string(
            result.get("dismissed_comment_after"), f"alert {number} dismissal comment"
        )
        numbers.add(number)
        alerts.append(
            {
                "alert_number": number,
                "expected_state": "dismissed",
                "expected_reason": reason,
                "expected_comment": comment,
            }
        )
    if not alerts:
        raise ResetError("writeback receipt contains no dismissed alerts to reopen")
    return alerts


def codeql_analyses(repository: str, branch: str) -> list[dict[str, Any]]:
    endpoint = (
        f"repos/{repository}/code-scanning/analyses"
        f"?ref={normalized_ref(branch)}&tool_name=CodeQL&per_page=100"
    )
    analyses = gh_api("GET", endpoint)
    if not isinstance(analyses, list) or not all(
        isinstance(analysis, dict) for analysis in analyses
    ):
        raise ResetError("invalid CodeQL analyses response")
    return analyses


def matching_workflow_run(
    repository: str, branch: str, workflow: str, commit_sha: str
) -> dict[str, Any]:
    output = run_command(
        [
            "gh",
            "run",
            "list",
            "--repo",
            repository,
            "--workflow",
            workflow,
            "--branch",
            branch,
            "--limit",
            "50",
            "--json",
            "databaseId,event,headBranch,headSha,status,conclusion,createdAt,url",
        ]
    )
    try:
        runs = json.loads(output)
    except json.JSONDecodeError as error:
        raise ResetError("invalid GitHub workflow runs response") from error
    for run in runs:
        if (
            isinstance(run, dict)
            and run.get("headSha") == commit_sha
            and run.get("status") == "completed"
        ):
            return run
    raise ResetError(f"no completed {workflow} run found for commit {commit_sha}")


def validate_live_alert(
    repository: str, expected: dict[str, Any], required_state: str
) -> dict[str, Any]:
    number = expected["alert_number"]
    alert = gh_api("GET", f"repos/{repository}/code-scanning/alerts/{number}")
    if not isinstance(alert, dict) or alert.get("number") != number:
        raise ResetError(f"alert {number}: identity check failed")
    state = normalized_alert_state(alert)
    if state != required_state:
        raise ResetError(
            f"alert {number}: expected {required_state}, found {state!r}"
        )
    if required_state == "dismissed":
        if alert.get("dismissed_reason") != expected["expected_reason"]:
            raise ResetError(f"alert {number}: dismissal reason changed")
        if alert.get("dismissed_comment") != expected["expected_comment"]:
            raise ResetError(f"alert {number}: dismissal comment changed")
    return alert


def preflight_reset_alert(
    repository: str, expected: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    number = expected["alert_number"]
    alert = gh_api("GET", f"repos/{repository}/code-scanning/alerts/{number}")
    if not isinstance(alert, dict) or alert.get("number") != number:
        raise ResetError(f"alert {number}: identity check failed")
    state = normalized_alert_state(alert)
    if state == "dismissed":
        if alert.get("dismissed_reason") != expected["expected_reason"]:
            raise ResetError(f"alert {number}: dismissal reason changed")
        if alert.get("dismissed_comment") != expected["expected_comment"]:
            raise ResetError(f"alert {number}: dismissal comment changed")
        return state, alert
    if (
        state == "open"
        and alert.get("dismissed_at") is None
        and alert.get("dismissed_reason") is None
        and alert.get("dismissed_comment") is None
    ):
        return state, alert
    raise ResetError(f"alert {number}: unexpected reset state {state!r}")


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise ResetError(f'plan schema_version must be "{PLAN_SCHEMA}"')
    validate_repository(plan.get("repository"))
    require_string(plan.get("branch"), "plan.branch")
    require_string(plan.get("workflow"), "plan.workflow")
    digest = require_string(plan.get("source_receipt_sha256"), "receipt digest")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ResetError("source receipt digest is invalid")
    analysis = plan.get("analysis")
    if not isinstance(analysis, dict) or not isinstance(analysis.get("id"), int):
        raise ResetError("plan analysis is invalid")
    if analysis.get("deletable") is not True:
        raise ResetError("plan analysis is not deletable")
    run = plan.get("workflow_run")
    if not isinstance(run, dict) or not isinstance(run.get("databaseId"), int):
        raise ResetError("plan workflow run is invalid")
    alerts = plan.get("alerts")
    if not isinstance(alerts, list) or not alerts:
        raise ResetError("plan alerts must be a non-empty array")
    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("current_state") not in {
            "dismissed",
            "open",
        }:
            raise ResetError("plan alert current_state must be dismissed or open")


def build_plan(args: argparse.Namespace) -> int:
    repository = validate_repository(args.repository)
    branch = require_string(args.branch, "branch")
    workflow = require_string(args.workflow, "workflow")
    receipt_path = Path(args.receipt)
    receipt, receipt_raw = read_json(receipt_path)
    alerts = receipt_alerts(receipt, repository, branch)

    analyses = codeql_analyses(repository, branch)
    if len(analyses) != 1:
        raise ResetError(
            f"expected exactly one CodeQL analysis for a clean reset, found {len(analyses)}"
        )
    analysis = analyses[0]
    if analysis.get("deletable") is not True:
        raise ResetError("the branch CodeQL analysis is not deletable")
    analysis_id = analysis.get("id")
    commit_sha = require_string(analysis.get("commit_sha"), "analysis.commit_sha")
    if not isinstance(analysis_id, int):
        raise ResetError("analysis.id must be an integer")

    for expected in alerts:
        state, _ = preflight_reset_alert(repository, expected)
        expected["current_state"] = state

    workflow_run = matching_workflow_run(
        repository, branch, workflow, commit_sha
    )
    plan = {
        "schema_version": PLAN_SCHEMA,
        "repository": repository,
        "branch": branch,
        "workflow": workflow,
        "created_at": utc_timestamp(),
        "source_receipt_path": str(receipt_path),
        "source_receipt_sha256": sha256(receipt_raw),
        "alerts": alerts,
        "analysis": {
            "id": analysis_id,
            "ref": analysis.get("ref"),
            "commit_sha": commit_sha,
            "analysis_key": analysis.get("analysis_key"),
            "category": analysis.get("category"),
            "created_at": analysis.get("created_at"),
            "results_count": analysis.get("results_count"),
            "deletable": True,
        },
        "workflow_run": workflow_run,
    }
    validate_plan(plan)
    output_path = Path(args.output)
    atomic_write(output_path, json_bytes(plan))
    print(
        json.dumps(
            {
                "plan_path": str(output_path),
                "repository": repository,
                "branch": branch,
                "scope_count": len(alerts),
                "reopen_count": sum(
                    alert["current_state"] == "dismissed" for alert in alerts
                ),
                "already_open_count": sum(
                    alert["current_state"] == "open" for alert in alerts
                ),
                "analysis_id": analysis_id,
                "workflow_run_id": workflow_run["databaseId"],
                "github_modified": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def preview_plan(args: argparse.Namespace) -> int:
    plan, raw = read_json(Path(args.plan))
    validate_plan(plan)
    preview = {
        "schema_version": PLAN_SCHEMA,
        "repository": plan["repository"],
        "branch": plan["branch"],
        "approval_token": sha256(raw),
        "reopen_requests": [
            {
                "method": "PATCH",
                "endpoint": (
                    f"/repos/{plan['repository']}/code-scanning/alerts/"
                    f"{alert['alert_number']}"
                ),
                "body": {"state": "open"},
            }
            for alert in plan["alerts"]
            if alert["current_state"] == "dismissed"
        ],
        "already_open_alerts": [
            alert["alert_number"]
            for alert in plan["alerts"]
            if alert["current_state"] == "open"
        ],
        "delete_request": {
            "method": "DELETE",
            "endpoint": (
                f"/repos/{plan['repository']}/code-scanning/analyses/"
                f"{plan['analysis']['id']}?confirm_delete=true"
            ),
            "warning": "Deletes the final branch analysis and may remove history.",
        },
        "rerun": {
            "command": "gh run rerun",
            "run_id": plan["workflow_run"]["databaseId"],
            "workflow": plan["workflow"],
            "commit_sha": plan["analysis"]["commit_sha"],
        },
        "github_modified": False,
    }
    print(json.dumps(preview, indent=2, sort_keys=True))
    return 0


def receipt_paths(plan_path: Path, receipt_root: str | None) -> tuple[Path, Path]:
    root = Path(receipt_root) if receipt_root else plan_path.parent / "receipts"
    timestamp = utc_timestamp()
    return root / "current.json", root / "history" / f"{timestamp}.json"


def persist_receipt(receipt: dict[str, Any], current: Path, history: Path) -> None:
    content = json_bytes(receipt)
    atomic_write(history, content, exclusive=True)
    atomic_write(current, content)


def apply_plan(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    plan, raw = read_json(plan_path)
    validate_plan(plan)
    token = sha256(raw)
    if args.approval_token != token:
        raise ResetError("approval token does not match; preview the plan again")

    analyses = codeql_analyses(plan["repository"], plan["branch"])
    if len(analyses) != 1 or analyses[0].get("id") != plan["analysis"]["id"]:
        raise ResetError("CodeQL analysis changed after planning; generate a new plan")
    alert_states = {}
    for expected in plan["alerts"]:
        state, _ = preflight_reset_alert(plan["repository"], expected)
        alert_states[expected["alert_number"]] = state

    current, history = receipt_paths(plan_path, args.receipt_root)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "repository": plan["repository"],
        "branch": plan["branch"],
        "plan_sha256": token,
        "started_at": utc_timestamp(),
        "completed_at": None,
        "complete": False,
        "reopened_alerts": [],
        "deleted_analysis": None,
        "rerun": None,
    }
    try:
        for expected in plan["alerts"]:
            number = expected["alert_number"]
            endpoint = f"repos/{plan['repository']}/code-scanning/alerts/{number}"
            if alert_states[number] == "dismissed":
                gh_api("PATCH", endpoint, {"state": "open"})
            readback = validate_live_alert(plan["repository"], expected, "open")
            receipt["reopened_alerts"].append(
                {
                    "alert_number": number,
                    "outcome": (
                        "reopened"
                        if alert_states[number] == "dismissed"
                        else "already_open"
                    ),
                    "state_after": normalized_alert_state(readback),
                }
            )

        analysis_id = plan["analysis"]["id"]
        delete_endpoint = (
            f"repos/{plan['repository']}/code-scanning/analyses/"
            f"{analysis_id}?confirm_delete=true"
        )
        delete_response = gh_api("DELETE", delete_endpoint)
        receipt["deleted_analysis"] = {
            "id": analysis_id,
            "response": delete_response,
        }

        run_id = plan["workflow_run"]["databaseId"]
        run_command(
            ["gh", "run", "rerun", str(run_id), "--repo", plan["repository"]]
        )
        receipt["rerun"] = {"run_id": run_id, "status": "requested"}
        receipt["complete"] = True
        receipt["completed_at"] = utc_timestamp()
        persist_receipt(receipt, current, history)
    except ResetError as error:
        receipt["error"] = str(error)
        receipt["completed_at"] = utc_timestamp()
        persist_receipt(receipt, current, history)
        raise

    print(
        json.dumps(
            {
                "receipt_path": str(current),
                "history_receipt_path": str(history),
                "reopened_count": len(receipt["reopened_alerts"]),
                "deleted_analysis_id": receipt["deleted_analysis"]["id"],
                "rerun_id": receipt["rerun"]["run_id"],
                "complete": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def verify_reset(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    plan, _ = read_json(plan_path)
    validate_plan(plan)
    run_id = plan["workflow_run"]["databaseId"]
    output = run_command(
        [
            "gh",
            "run",
            "view",
            str(run_id),
            "--repo",
            plan["repository"],
            "--json",
            "attempt,conclusion,status,headBranch,headSha,url",
        ]
    )
    try:
        run = json.loads(output)
    except json.JSONDecodeError as error:
        raise ResetError("invalid workflow run verification response") from error
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ResetError(
            f"workflow rerun is not successful: status={run.get('status')!r}, "
            f"conclusion={run.get('conclusion')!r}"
        )

    analyses = codeql_analyses(plan["repository"], plan["branch"])
    replacements = [
        analysis
        for analysis in analyses
        if analysis.get("id") != plan["analysis"]["id"]
        and analysis.get("commit_sha") == plan["analysis"]["commit_sha"]
    ]
    if not replacements:
        raise ResetError("no replacement CodeQL analysis found for the reset commit")

    alerts = []
    for expected in plan["alerts"]:
        readback = validate_live_alert(plan["repository"], expected, "open")
        alerts.append(
            {"alert_number": expected["alert_number"], "state": readback.get("state")}
        )

    verification = {
        "schema_version": RECEIPT_SCHEMA,
        "repository": plan["repository"],
        "branch": plan["branch"],
        "verified_at": utc_timestamp(),
        "workflow_run": run,
        "replacement_analyses": replacements,
        "alerts": alerts,
        "all_reopened": True,
    }
    root = Path(args.output_root) if args.output_root else plan_path.parent / "verification"
    timestamp = utc_timestamp()
    history = root / "history" / f"{timestamp}.json"
    current = root / "current.json"
    content = json_bytes(verification)
    atomic_write(history, content, exclusive=True)
    atomic_write(current, content)
    print(
        json.dumps(
            {
                "verification_path": str(current),
                "history_path": str(history),
                "workflow_run_id": run_id,
                "replacement_analysis_count": len(replacements),
                "open_alert_count": len(alerts),
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Approval-gated CodeQL branch clean reset."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--receipt", required=True)
    plan_parser.add_argument("--repository", required=True)
    plan_parser.add_argument("--branch", required=True)
    plan_parser.add_argument("--workflow", default="codeql-analysis.yml")
    plan_parser.add_argument("--output", required=True)
    plan_parser.set_defaults(handler=build_plan)

    preview_parser = subparsers.add_parser("preview")
    preview_parser.add_argument("--plan", required=True)
    preview_parser.set_defaults(handler=preview_plan)

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--plan", required=True)
    apply_parser.add_argument("--approval-token", required=True)
    apply_parser.add_argument("--receipt-root")
    apply_parser.set_defaults(handler=apply_plan)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--plan", required=True)
    verify_parser.add_argument("--output-root")
    verify_parser.set_defaults(handler=verify_reset)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return args.handler(args)
    except ResetError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
