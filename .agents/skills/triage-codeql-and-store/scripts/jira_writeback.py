#!/usr/bin/env python3
"""Plan and apply approval-gated Jira tracking for persisted CodeQL triage."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
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
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen


PREVIEW_SCHEMA = "codeql-triage-jira-preview/v1"
RECEIPT_SCHEMA = "codeql-triage-jira-receipt/v1"
TRIAGE_SCHEMA = "triage-finding/v0"
VERDICTS = ("confirmed", "needs_review", "not_actionable")
TRIAGE_LABELS = {f"triage-{verdict.replace('_', '-')}" for verdict in VERDICTS}
MAX_TECHNICAL_BATCH = 25
JIRA_PERMISSIONS = (
    "BROWSE_PROJECTS",
    "CREATE_ISSUES",
    "EDIT_ISSUES",
    "ADD_COMMENTS",
)
PR_PATTERN = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([0-9]+)(?:/)?$"
)
ALERT_PATTERN = re.compile(
    r"(?:/security/code-scanning/|/code-scanning/alerts/)([0-9]+)(?:$|[/?#])"
)
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SEVERITY_PATTERNS = (
    re.compile(r"^(?:codeql-)?security[_-]severity(?:[_-]level)?:\s*(critical|high|medium|low)$", re.I),
    re.compile(r"^security[_-]severity[_-]level:\s*(critical|high|medium|low)$", re.I),
)


class JiraWritebackError(RuntimeError):
    pass


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


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
                raise JiraWritebackError(f"file already exists: {path}") from error
            temporary_path.unlink()
        else:
            os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise JiraWritebackError(f"{field} must be a non-empty string")
    return value.strip()


def require_identifier(value: Any, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise JiraWritebackError(f"{field} must be a non-empty identifier")
    identifier = str(value).strip()
    if not identifier:
        raise JiraWritebackError(f"{field} must be a non-empty identifier")
    return identifier


def clean_line(value: Any) -> str:
    return " ".join(str(value).split())


def canonical_site(value: str) -> str:
    parsed = urlparse(require_string(value, "Jira site"))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
        or parsed.path not in {"", "/"}
        or not parsed.hostname.endswith(".atlassian.net")
    ):
        raise JiraWritebackError(
            "Jira site must be an HTTPS *.atlassian.net origin without a path"
        )
    return f"https://{parsed.hostname.lower()}"


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise JiraWritebackError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise JiraWritebackError(f"top-level JSON value in {path} must be an object")
    return value, raw


def subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("JIRA_BASE_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN"):
        environment.pop(name, None)
    return environment


def run_command(command: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        env=subprocess_environment(),
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise JiraWritebackError(f"{' '.join(command[:3])}: {message}")
    return result.stdout.strip()


def repo_root() -> Path:
    return Path(run_command(["git", "rev-parse", "--show-toplevel"])).resolve()


def git_value(root: Path, *args: str) -> str:
    return run_command(["git", *args], root)


def relative_file(path: Path, root: Path, field: str) -> tuple[str, bytes]:
    resolved = path.resolve()
    if not resolved.is_file():
        raise JiraWritebackError(f"{field} does not exist: {path}")
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as error:
        raise JiraWritebackError(f"{field} must be inside the repository") from error
    return relative, resolved.read_bytes()


def verified_report_url(
    root: Path,
    repository: str,
    revision: str,
    report_path: str,
    report_raw: bytes,
) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{revision}:{report_path}"],
        cwd=root,
        capture_output=True,
        check=False,
        env=subprocess_environment(),
    )
    if result.returncode != 0 or result.stdout != report_raw:
        return None
    encoded_path = quote(report_path, safe="/")
    return f"https://github.com/{repository}/blob/{revision}/{encoded_path}"


class JiraClient:
    def __init__(self, site: str, email: str, token: str):
        self.site = canonical_site(site)
        self._email = require_string(email, "JIRA_USER_EMAIL")
        self._token = require_string(token, "JIRA_API_TOKEN")
        credential = f"{self._email}:{self._token}".encode("utf-8")
        self._authorization = "Basic " + base64.b64encode(credential).decode("ascii")

    def _redact(self, value: str) -> str:
        return value.replace(self._token, "***").replace(self._email, "***")

    @classmethod
    def from_environment(cls, expected_site: str) -> "JiraClient":
        configured_site = os.environ.get("JIRA_BASE_URL")
        email = os.environ.get("JIRA_USER_EMAIL")
        token = os.environ.get("JIRA_API_TOKEN")
        missing = [
            name
            for name, value in (
                ("JIRA_BASE_URL", configured_site),
                ("JIRA_USER_EMAIL", email),
                ("JIRA_API_TOKEN", token),
            )
            if not value
        ]
        if missing:
            raise JiraWritebackError(
                "missing Jira environment variables: " + ", ".join(missing)
            )
        if canonical_site(configured_site) != canonical_site(expected_site):
            raise JiraWritebackError("JIRA_BASE_URL does not match the selected Jira site")
        return cls(configured_site, email, token)

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        if not path.startswith("/rest/api/3/"):
            raise JiraWritebackError("refusing a non-Jira-v3 API path")
        url = self.site + path
        request_body = json.dumps(body).encode("utf-8") if body is not None else None
        request = Request(
            url,
            data=request_body,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": self._authorization,
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as error:
            raw = error.read(4096)
            detail = ""
            try:
                value = json.loads(raw)
                messages = value.get("errorMessages", []) if isinstance(value, dict) else []
                detail = ": " + "; ".join(clean_line(item) for item in messages[:3])
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            raise JiraWritebackError(
                self._redact(
                    f"Jira {method} {path.split('?')[0]} returned HTTP {error.code}{detail}"
                )
            ) from error
        except URLError as error:
            raise JiraWritebackError(
                f"Jira {method} {path.split('?')[0]} failed"
            ) from error
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise JiraWritebackError(
                f"Jira {method} {path.split('?')[0]} returned invalid JSON"
            ) from error


def validate_triage(value: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    if value.get("schema_version") != TRIAGE_SCHEMA:
        raise JiraWritebackError(f'triage schema_version must be "{TRIAGE_SCHEMA}"')
    repository = value.get("repository")
    if not isinstance(repository, dict):
        raise JiraWritebackError("triage.repository must be an object")
    revision = require_string(repository.get("revision"), "triage.repository.revision")
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise JiraWritebackError("triage.findings must be an array")
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        field = f"triage.findings[{index}]"
        if not isinstance(finding, dict):
            raise JiraWritebackError(f"{field} must be an object")
        finding_id = require_string(finding.get("input_id"), f"{field}.input_id")
        if finding_id in seen:
            raise JiraWritebackError(f"duplicate finding id: {finding_id}")
        seen.add(finding_id)
        if finding.get("verdict") not in VERDICTS:
            raise JiraWritebackError(f"{field}.verdict is invalid")
        require_string(finding.get("triage_item_id"), f"{field}.triage_item_id")
        if finding.get("verdict") == "confirmed":
            require_string(
                finding.get("fix_finding_handoff"), f"{field}.fix_finding_handoff"
            )
    return revision, findings


def references(finding: dict[str, Any]) -> list[str]:
    normalized = finding.get("normalized_input")
    values = normalized.get("references") if isinstance(normalized, dict) else None
    return [value for value in values or [] if isinstance(value, str)]


def alert_number(finding: dict[str, Any]) -> int:
    for reference in references(finding):
        match = ALERT_PATTERN.search(reference)
        if match:
            return int(match.group(1))
    match = re.search(r"([0-9]+)$", str(finding.get("input_id", "")))
    if not match:
        raise JiraWritebackError(f"cannot resolve alert number for {finding.get('input_id')}")
    return int(match.group(1))


def alert_url(finding: dict[str, Any], repository: str, number: int) -> str:
    for reference in references(finding):
        if "github.com/" in reference and ALERT_PATTERN.search(reference):
            return reference
    return f"https://github.com/{repository}/security/code-scanning/{number}"


def codeql_security_severity(finding: dict[str, Any]) -> str | None:
    for reference in references(finding):
        for pattern in SEVERITY_PATTERNS:
            match = pattern.fullmatch(reference.strip())
            if match:
                return match.group(1).lower()
    value = finding.get("codeql_security_severity")
    if isinstance(value, str) and value.lower() in {"critical", "high", "medium", "low"}:
        return value.lower()
    return None


def finding_fingerprint(repository: str, number: int, finding_id: str) -> str:
    return sha256(f"{repository}\n{number}\n{finding_id}\n".encode("utf-8"))


def list_values(value: Any, fallback: str) -> list[str]:
    if not isinstance(value, list):
        return [fallback]
    result = [clean_line(item) for item in value if clean_line(item)]
    return result or [fallback]


def locations(finding: dict[str, Any]) -> list[str]:
    result = []
    for location in finding.get("affected_locations", []):
        if not isinstance(location, dict):
            continue
        label = clean_line(location.get("label", "location"))
        path = clean_line(location.get("path", "unknown"))
        lines = clean_line(location.get("lines", "unknown"))
        result.append(f"{label}: {path}:{lines}")
    return result or ["unavailable"]


def validate_pr(
    pr_url: str | None, repository: str, branch: str, revision: str
) -> dict[str, Any] | None:
    if not pr_url:
        return None
    match = PR_PATTERN.fullmatch(pr_url.strip())
    if not match or f"{match.group(1)}/{match.group(2)}".lower() != repository.lower():
        raise JiraWritebackError("PR URL must identify a pull request in the source repository")
    if shutil.which("gh") is None:
        raise JiraWritebackError("GitHub CLI is required to verify the supplied PR URL")
    number = int(match.group(3))
    raw = run_command(["gh", "api", f"repos/{repository}/pulls/{number}"])
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise JiraWritebackError("GitHub returned invalid PR metadata") from error
    head = value.get("head") if isinstance(value, dict) else None
    base = value.get("base") if isinstance(value, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    if (
        not isinstance(head, dict)
        or not isinstance(base, dict)
        or not isinstance(head_repo, dict)
        or str(head_repo.get("full_name", "")).lower() != repository.lower()
        or head.get("ref") != branch
        or head.get("sha") != revision
    ):
        raise JiraWritebackError("supplied PR does not match the triaged repository, branch, and revision")
    state = "merged" if value.get("merged_at") else value.get("state")
    return {
        "number": number,
        "url": require_string(value.get("html_url"), "PR URL"),
        "state": clean_line(state),
        "base_branch": clean_line(base.get("ref")),
        "head_branch": clean_line(head.get("ref")),
        "head_revision": clean_line(head.get("sha")),
    }


def jira_context(
    client: JiraClient, project_key: str, issue_type_name: str
) -> dict[str, Any]:
    myself = client.request("GET", "/rest/api/3/myself")
    project = client.request("GET", f"/rest/api/3/project/{quote(project_key)}")
    query = urlencode(
        {"projectKey": project_key, "permissions": ",".join(JIRA_PERMISSIONS)}
    )
    permissions = client.request("GET", f"/rest/api/3/mypermissions?{query}")
    permission_values = permissions.get("permissions") if isinstance(permissions, dict) else None
    if not isinstance(permission_values, dict):
        raise JiraWritebackError("Jira returned invalid permission metadata")
    missing_permissions = [
        key
        for key in JIRA_PERMISSIONS
        if not isinstance(permission_values.get(key), dict)
        or permission_values[key].get("havePermission") is not True
    ]
    if missing_permissions:
        raise JiraWritebackError(
            "Jira account lacks required project permissions: "
            + ", ".join(missing_permissions)
        )

    issue_types: list[dict[str, Any]] = []
    start_at = 0
    while True:
        page = client.request(
            "GET",
            f"/rest/api/3/issue/createmeta/{quote(project_key)}/issuetypes"
            f"?startAt={start_at}&maxResults=50",
        )
        values = (
            page.get("issueTypes", page.get("values"))
            if isinstance(page, dict)
            else None
        )
        if not isinstance(values, list):
            raise JiraWritebackError("Jira returned invalid issue type metadata")
        issue_types.extend(item for item in values if isinstance(item, dict))
        total = page.get("total", len(issue_types))
        if len(issue_types) >= total or not values:
            break
        start_at += len(values)
    matches = [item for item in issue_types if item.get("name") == issue_type_name]
    if len(matches) != 1:
        raise JiraWritebackError(
            f"Jira issue type {issue_type_name!r} is missing or ambiguous"
        )
    issue_type = matches[0]

    fields: list[dict[str, Any]] = []
    start_at = 0
    while True:
        page = client.request(
            "GET",
            f"/rest/api/3/issue/createmeta/{quote(project_key)}/issuetypes/"
            f"{quote(str(issue_type['id']))}?startAt={start_at}&maxResults=50",
        )
        values = page.get("fields") if isinstance(page, dict) else None
        if not isinstance(values, list):
            raise JiraWritebackError("Jira returned invalid create-field metadata")
        fields.extend(item for item in values if isinstance(item, dict))
        total = page.get("total", len(fields))
        if len(fields) >= total or not values:
            break
        start_at += len(values)
    by_key = {str(item.get("key") or item.get("fieldId")): item for item in fields}
    for required in ("summary", "description", "labels"):
        if required not in by_key:
            raise JiraWritebackError(f"Jira Task create screen is missing {required!r}")
    supported = {"project", "issuetype", "summary", "description", "labels", "priority"}
    unsupported_required = sorted(
        key
        for key, metadata in by_key.items()
        if metadata.get("required") is True
        and metadata.get("hasDefaultValue") is not True
        and key not in supported
    )
    if unsupported_required:
        raise JiraWritebackError(
            "Jira Task has unsupported required fields: " + ", ".join(unsupported_required)
        )
    priority_metadata = by_key.get("priority", {})
    priorities = [
        {"id": str(item.get("id")), "name": str(item.get("name"))}
        for item in priority_metadata.get("allowedValues", [])
        if isinstance(item, dict) and item.get("id") and item.get("name")
    ]
    return {
        "site": client.site,
        "account_id": require_string(myself.get("accountId"), "Jira accountId"),
        "display_name": require_string(myself.get("displayName"), "Jira displayName"),
        "project_key": require_string(project.get("key"), "Jira project key"),
        "project_id": require_identifier(project.get("id"), "Jira project id"),
        "project_name": require_string(project.get("name"), "Jira project name"),
        "issue_type_id": require_identifier(issue_type.get("id"), "Jira issue type id"),
        "issue_type_name": issue_type_name,
        "priorities": priorities,
        "permissions": list(JIRA_PERMISSIONS),
    }


def mapped_priority(
    severity: str | None, priorities: list[dict[str, str]]
) -> tuple[dict[str, str] | None, str]:
    if severity is None:
        return None, "jira_default"
    by_name = {item["name"].lower(): item for item in priorities}
    target = severity
    if severity == "critical" and "critical" not in by_name:
        target = "highest"
    priority = by_name.get(target)
    if priority is None:
        raise JiraWritebackError(
            f"Jira project has no priority for CodeQL severity {severity!r}"
        )
    source = "codeql_security_severity"
    if severity == "critical" and priority["name"].lower() == "highest":
        source = "codeql_security_severity_critical_fallback"
    return priority, source


def adf_document(text: str) -> dict[str, Any]:
    content = []
    for line in text.splitlines():
        if line.startswith("### "):
            content.append(
                {"type": "heading", "attrs": {"level": 3}, "content": [{"type": "text", "text": line[4:]}]}
            )
        elif line.startswith("## "):
            content.append(
                {"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": line[3:]}]}
            )
        elif line.startswith("- "):
            content.append(
                {
                    "type": "bulletList",
                    "content": [
                        {
                            "type": "listItem",
                            "content": [
                                {"type": "paragraph", "content": [{"type": "text", "text": line[2:]}]}
                            ],
                        }
                    ],
                }
            )
        elif line:
            content.append({"type": "paragraph", "content": [{"type": "text", "text": line}]})
    return {"type": "doc", "version": 1, "content": content}


def adf_text(value: Any) -> str:
    parts: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "text" and isinstance(node.get("text"), str):
                parts.append(node["text"])
            for child in node.get("content", []):
                visit(child)
            if node.get("type") in {"paragraph", "heading", "listItem"}:
                parts.append("\n")
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return "\n".join(line.strip() for line in "".join(parts).splitlines() if line.strip())


def build_description(
    finding: dict[str, Any],
    repository: str,
    branch: str,
    revision: str,
    report_path: str,
    report_digest: str,
    report_url: str | None,
    number: int,
    url: str,
    fingerprint: str,
    severity: str | None,
    priority: dict[str, str] | None,
    priority_source: str,
    pr: dict[str, Any] | None,
) -> str:
    handoff = finding.get("fix_finding_handoff")
    handoff_text = handoff.strip() if isinstance(handoff, str) and handoff.strip() else "Not applicable."
    parts = [
        "## CodeQL finding",
        f"Status: {finding['verdict']}",
        f"Finding ID: {finding['input_id']}",
        f"Triage item ID: {finding['triage_item_id']}",
        f"Finding fingerprint: {fingerprint}",
        f"CodeQL security severity: {severity or 'not provided'}",
        f"Jira priority: {priority['name'] if priority else 'Jira default'}",
        f"Priority source: {priority_source}",
        f"Report path: {report_path}",
        f"Report SHA-256: {report_digest}",
    ]
    if report_url:
        parts.append(f"Report URL: {report_url}")
    parts.extend(
        [
            f"Code scanning alert: {url}",
            f"Repository: {repository}",
            f"Branch: {branch}",
            f"Revision: {revision}",
            f"Confidence: {clean_line(finding.get('confidence', 'unknown'))}",
        ]
    )
    if pr:
        parts.extend(
            [
                "### Pull request",
                f"PR: {repository}#{pr['number']}",
                f"URL: {pr['url']}",
                f"Base branch: {pr['base_branch']}",
                f"Head branch: {pr['head_branch']}",
                f"Head revision: {pr['head_revision']}",
                f"State: {pr['state']}",
            ]
        )
    parts.extend(["### Affected locations", *[f"- {item}" for item in locations(finding)]])
    for heading, values, fallback in (
        ("Evidence", finding.get("evidence"), "No affirmative evidence recorded."),
        ("Counterevidence", finding.get("counterevidence"), "No counterevidence recorded."),
        ("Proof gaps", finding.get("proof_gaps"), "None recorded."),
    ):
        parts.extend([f"### {heading}", *[f"- {item}" for item in list_values(values, fallback)]])
    parts.extend(
        [
            "### Recommended next step",
            clean_line(finding.get("recommended_next_step", "unspecified")),
            "### Fix-finding handoff",
            handoff_text,
            "### Tracking information",
            f"This Jira Task tracks Code Scanning alert #{number} without changing or dismissing the alert.",
        ]
    )
    return "\n\n".join(parts).strip() + "\n"


def snapshot(
    finding: dict[str, Any],
    severity: str | None,
    priority: dict[str, str] | None,
    priority_source: str,
    pr: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "status": finding["verdict"],
        "codeql_security_severity": severity,
        "jira_priority": priority["name"] if priority else None,
        "priority_source": priority_source,
        "confidence": finding.get("confidence"),
        "affected_locations": locations(finding),
        "evidence": list_values(finding.get("evidence"), "No affirmative evidence recorded."),
        "counterevidence": list_values(finding.get("counterevidence"), "No counterevidence recorded."),
        "proof_gaps": list_values(finding.get("proof_gaps"), "None recorded."),
        "recommended_next_step": clean_line(finding.get("recommended_next_step", "unspecified")),
        "fix_finding_handoff": finding.get("fix_finding_handoff"),
        "pull_request": pr,
    }


def changed_fields(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    return {
        key: {"previous": previous.get(key), "current": current.get(key)}
        for key in current
        if previous.get(key) != current.get(key)
    }


def display_value(value: Any) -> str:
    if value is None:
        return "not provided"
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def build_update_comment(
    finding_id: str,
    revision: str,
    report_path: str,
    previous_status: str,
    current_status: str,
    changes: dict[str, Any],
) -> tuple[str, str]:
    fingerprint_payload = {
        "finding_id": finding_id,
        "revision": revision,
        "report_path": report_path,
        "changes": changes,
    }
    update_fingerprint = sha256(json_bytes(fingerprint_payload))
    parts = [
        "## [Update]",
        f"Finding ID: {finding_id}",
        f"Update fingerprint: {update_fingerprint}",
        f"Revision: {revision}",
        f"Report path: {report_path}",
        f"Previous status: {previous_status}",
        f"Current status: {current_status}",
        "### Changed fields",
    ]
    for field, values in changes.items():
        parts.extend(
            [
                f"- {field}",
                f"Previous: {display_value(values['previous'])}",
                f"Current: {display_value(values['current'])}",
            ]
        )
    return "\n\n".join(parts).strip() + "\n", update_fingerprint


def jql_literal(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def search_candidates(client: JiraClient, project_key: str, value: str) -> list[str]:
    jql = f"project = {jql_literal(project_key)} AND text ~ {jql_literal(value)}"
    keys: list[str] = []
    next_page_token: str | None = None
    while True:
        body: dict[str, Any] = {
            "jql": jql,
            "fields": ["summary", "description", "labels", "priority", "issuetype", "project"],
            "maxResults": 100,
        }
        if next_page_token:
            body["nextPageToken"] = next_page_token
        response = client.request("POST", "/rest/api/3/search/jql", body)
        issues = response.get("issues") if isinstance(response, dict) else None
        if not isinstance(issues, list):
            raise JiraWritebackError("Jira returned invalid JQL search results")
        keys.extend(
            require_string(issue.get("key"), "Jira issue key")
            for issue in issues
            if isinstance(issue, dict)
        )
        next_page_token = response.get("nextPageToken")
        if not next_page_token:
            return list(dict.fromkeys(keys))


def get_issue(client: JiraClient, key: str) -> dict[str, Any]:
    fields = "summary,description,labels,priority,issuetype,project,comment"
    value = client.request(
        "GET", f"/rest/api/3/issue/{quote(key)}?fields={quote(fields)}"
    )
    if not isinstance(value, dict):
        raise JiraWritebackError(f"Jira returned invalid issue {key}")
    return value


def get_comments(client: JiraClient, key: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    start_at = 0
    while True:
        value = client.request(
            "GET",
            f"/rest/api/3/issue/{quote(key)}/comment?startAt={start_at}&maxResults=100",
        )
        page = value.get("comments") if isinstance(value, dict) else None
        if not isinstance(page, list):
            raise JiraWritebackError(f"Jira returned invalid comments for {key}")
        comments.extend(item for item in page if isinstance(item, dict))
        total = value.get("total", len(comments))
        if len(comments) >= total or not page:
            return comments
        start_at += len(page)


def find_issue(
    client: JiraClient, project_key: str, finding_id: str, fingerprint: str
) -> dict[str, Any] | None:
    keys = set(search_candidates(client, project_key, finding_id))
    keys.update(search_candidates(client, project_key, fingerprint))
    matches = []
    partial_matches = []
    for key in sorted(keys):
        issue = get_issue(client, key)
        fields = issue.get("fields")
        description = fields.get("description") if isinstance(fields, dict) else None
        text = adf_text(description)
        has_id = f"Finding ID: {finding_id}" in text
        has_fingerprint = f"Finding fingerprint: {fingerprint}" in text
        if has_id and has_fingerprint:
            matches.append(issue)
        elif has_id or has_fingerprint:
            partial_matches.append(key)
    if len(matches) > 1:
        raise JiraWritebackError(
            f"finding {finding_id}: multiple Jira Tasks carry the exact bindings"
        )
    if not matches and partial_matches:
        raise JiraWritebackError(
            f"finding {finding_id}: Jira bindings are split or incomplete in {partial_matches}"
        )
    return matches[0] if matches else None


def issue_url(site: str, key: str) -> str:
    return f"{site}/browse/{quote(key)}"


def load_previous_receipt(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.exists():
        return {}, None
    receipt, raw = read_json(path)
    if receipt.get("schema_version") != RECEIPT_SCHEMA or receipt.get("complete") is not True:
        raise JiraWritebackError("previous Jira receipt is incomplete")
    results = receipt.get("results")
    if not isinstance(results, list):
        raise JiraWritebackError("previous Jira receipt has invalid results")
    return {
        result["finding_id"]: result
        for result in results
        if isinstance(result, dict) and isinstance(result.get("finding_id"), str)
    }, sha256(raw)


def labels_for(status: str, existing: list[str] | None = None) -> list[str]:
    retained = {
        value
        for value in existing or []
        if isinstance(value, str) and value not in TRIAGE_LABELS and value != "codex-codeql"
    }
    retained.update({"codex-codeql", f"triage-{status.replace('_', '-')}"})
    return sorted(retained)


def current_issue_state(issue: dict[str, Any]) -> dict[str, Any]:
    fields = issue.get("fields")
    if not isinstance(fields, dict):
        raise JiraWritebackError("Jira issue fields are missing")
    priority = fields.get("priority")
    return {
        "summary": fields.get("summary"),
        "labels": sorted(value for value in fields.get("labels", []) if isinstance(value, str)),
        "priority": priority.get("name") if isinstance(priority, dict) else None,
        "description_text": adf_text(fields.get("description")),
    }


def build_plan(
    *,
    triage_path: Path,
    report_path: Path,
    repository: str,
    branch: str,
    site: str,
    project_key: str,
    issue_type: str,
    pr_url: str | None,
    preview_path: Path,
    audience_approved: bool,
    client: JiraClient,
) -> dict[str, Any]:
    if audience_approved is not True:
        raise JiraWritebackError("the Jira project audience must be explicitly approved")
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise JiraWritebackError("repository must use owner/repo format")
    root = repo_root()
    triage_relative, triage_raw = relative_file(triage_path, root, "triage artifact")
    report_relative, report_raw = relative_file(report_path, root, "HTML report")
    triage = json.loads(triage_raw)
    revision, findings = validate_triage(triage)
    if git_value(root, "symbolic-ref", "--quiet", "--short", "HEAD") != branch:
        raise JiraWritebackError("requested branch is not the current checkout")
    if git_value(root, "rev-parse", "HEAD") != revision:
        raise JiraWritebackError("triage revision is not the current checkout revision")
    context = jira_context(client, project_key, issue_type)
    if context["site"] != canonical_site(site) or context["project_key"] != project_key:
        raise JiraWritebackError("live Jira destination does not match the selected destination")
    pr = validate_pr(pr_url, repository, branch, revision)
    previous_path = preview_path.parent / "receipts" / "current.json"
    previous, previous_receipt_sha256 = load_previous_receipt(previous_path)
    report_digest = sha256(report_raw)
    report_url = verified_report_url(
        root, repository, revision, report_relative, report_raw
    )

    items = []
    for finding in sorted(findings, key=alert_number):
        number = alert_number(finding)
        finding_id = finding["input_id"]
        fingerprint = finding_fingerprint(repository, number, finding_id)
        severity = codeql_security_severity(finding)
        priority, priority_source = mapped_priority(severity, context["priorities"])
        summary = f"[CodeQL][#{number}] {clean_line(finding.get('title', 'CodeQL finding'))}"[:255]
        url = alert_url(finding, repository, number)
        current_snapshot = snapshot(finding, severity, priority, priority_source, pr)
        description = build_description(
            finding,
            repository,
            branch,
            revision,
            report_relative,
            report_digest,
            report_url,
            number,
            url,
            fingerprint,
            severity,
            priority,
            priority_source,
            pr,
        )
        duplicate = find_issue(client, project_key, finding_id, fingerprint)
        action = "create"
        key = None
        url_value = None
        comment = None
        update_fingerprint = None
        last_update_fingerprint = None
        field_updates: dict[str, Any] = {}
        baseline = previous.get(finding_id)
        if duplicate:
            key = require_string(duplicate.get("key"), "Jira issue key")
            url_value = issue_url(context["site"], key)
            live = current_issue_state(duplicate)
            if live["summary"] != summary or not all(
                binding in live["description_text"]
                for binding in (
                    f"Finding ID: {finding_id}",
                    f"Finding fingerprint: {fingerprint}",
                )
            ):
                raise JiraWritebackError(
                    f"finding {finding_id}: live Jira Task identity or summary changed"
                )
            if baseline is None:
                expected_text = adf_text(adf_document(description))
                if live["summary"] == summary and live["description_text"] == expected_text:
                    action = "reuse"
                else:
                    raise JiraWritebackError(
                        f"finding {finding_id}: existing Jira Task has no verified local baseline"
                    )
            else:
                if baseline.get("issue_key") != key or not isinstance(baseline.get("snapshot"), dict):
                    raise JiraWritebackError(
                        f"finding {finding_id}: previous receipt does not match the live Jira Task"
                    )
                last_update_fingerprint = baseline.get("last_update_fingerprint")
                if last_update_fingerprint:
                    live_comments = get_comments(client, key)
                    if not any(
                        last_update_fingerprint in adf_text(comment.get("body"))
                        for comment in live_comments
                    ):
                        raise JiraWritebackError(
                            f"finding {finding_id}: live Jira comments disagree with the previous receipt"
                        )
                changes = changed_fields(baseline["snapshot"], current_snapshot)
                desired_labels = labels_for(finding["verdict"], live["labels"])
                if desired_labels != live["labels"]:
                    changes["jira_labels"] = {
                        "previous": live["labels"],
                        "current": desired_labels,
                    }
                    field_updates["labels"] = desired_labels
                if priority and priority["name"] != live["priority"]:
                    changes["jira_priority_field"] = {
                        "previous": live["priority"],
                        "current": priority["name"],
                    }
                    field_updates["priority"] = {"id": priority["id"]}
                if changes:
                    action = "comment"
                    comment, update_fingerprint = build_update_comment(
                        finding_id,
                        revision,
                        report_relative,
                        str(baseline["snapshot"].get("status")),
                        finding["verdict"],
                        changes,
                    )
                    last_update_fingerprint = update_fingerprint
                else:
                    action = "reuse"
        create_fields: dict[str, Any] = {
            "project": {"key": project_key},
            "issuetype": {"id": context["issue_type_id"]},
            "summary": summary,
            "description": adf_document(description),
            "labels": labels_for(finding["verdict"]),
        }
        if priority:
            create_fields["priority"] = {"id": priority["id"]}
        items.append(
            {
                "sequence": len(items) + 1,
                "technical_batch": len(items) // MAX_TECHNICAL_BATCH + 1,
                "finding_id": finding_id,
                "triage_item_id": finding["triage_item_id"],
                "finding_fingerprint": fingerprint,
                "alert_number": number,
                "alert_url": url,
                "verdict": finding["verdict"],
                "summary": summary,
                "description": description,
                "snapshot": current_snapshot,
                "action": action,
                "issue_key": key,
                "issue_url": url_value,
                "create_fields": create_fields,
                "field_updates": field_updates,
                "update_comment": comment,
                "update_fingerprint": update_fingerprint,
                "last_update_fingerprint": last_update_fingerprint,
            }
        )
    return {
        "schema_version": PREVIEW_SCHEMA,
        "repository": repository,
        "branch": branch,
        "revision": revision,
        "triage_path": triage_relative,
        "triage_sha256": sha256(triage_raw),
        "report_path": report_relative,
        "report_sha256": report_digest,
        "report_url": report_url,
        "pull_request": pr,
        "jira": context,
        "audience_approved": True,
        "previous_receipt_sha256": previous_receipt_sha256,
        "technical_batch_size": MAX_TECHNICAL_BATCH,
        "technical_batch_count": (len(items) + MAX_TECHNICAL_BATCH - 1) // MAX_TECHNICAL_BATCH,
        "finding_count": len(items),
        "items": items,
    }


def embedded_plan(raw: bytes) -> str:
    return raw.decode("utf-8").replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_preview(plan: dict[str, Any]) -> tuple[bytes, str]:
    raw = json_bytes(plan)
    token = sha256(raw)
    cards = []
    for item in plan["items"]:
        comment = item["update_comment"] or "No update comment."
        create_metadata = {
            key: value
            for key, value in item["create_fields"].items()
            if key != "description"
        }
        cards.append(
            f'''<article class="finding" data-status="{html.escape(item['verdict'])}" data-action="{html.escape(item['action'])}">
<h2>{html.escape(item['summary'])}</h2>
<p><strong>Finding ID:</strong> <code>{html.escape(item['finding_id'])}</code></p>
<p><strong>Action:</strong> {html.escape(item['action'])} · <strong>Technical batch:</strong> {item['technical_batch']}</p>
<h3>Exact create metadata</h3><pre>{html.escape(json.dumps(create_metadata, indent=2, sort_keys=True))}</pre>
<h3>Exact Jira description</h3><pre>{html.escape(item['description'])}</pre>
<h3>Exact Jira update comment</h3><pre>{html.escape(comment)}</pre>
<h3>Exact field updates</h3><pre>{html.escape(json.dumps(item['field_updates'], indent=2, sort_keys=True))}</pre>
</article>'''
        )
    actions = sorted({item["action"] for item in plan["items"]})
    action_options = "".join(f'<option value="{html.escape(value)}">{html.escape(value)}</option>' for value in actions)
    document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeQL Jira approval preview</title>
<style>body{{font:15px system-ui;margin:2rem;max-width:1200px}}.controls{{position:sticky;top:0;background:#fff;padding:1rem 0}}article{{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}}pre{{white-space:pre-wrap;background:#f6f8fa;padding:1rem;overflow:auto}}code{{font-family:ui-monospace,monospace}}.warning{{background:#fff4ce;padding:1rem;border-left:4px solid #d29922}}</style>
</head><body><h1>CodeQL Jira approval preview</h1>
<p class="warning">This preview authorizes Jira writes for every visible finding. Credentials are not embedded.</p>
<p><strong>Jira:</strong> {html.escape(plan['jira']['site'])} / {html.escape(plan['jira']['project_key'])} / {html.escape(plan['jira']['issue_type_name'])}</p>
<p><strong>Identity:</strong> {html.escape(plan['jira']['display_name'])} (<code>{html.escape(plan['jira']['account_id'])}</code>)</p>
<p><strong>Findings:</strong> {plan['finding_count']} · <strong>Technical batches:</strong> {plan['technical_batch_count']} · <strong>Approval token:</strong> <code>{token}</code></p>
<div class="controls"><label>Status <select id="status"><option value="">all</option><option>confirmed</option><option>needs_review</option><option>not_actionable</option></select></label> <label>Action <select id="action"><option value="">all</option>{action_options}</select></label></div>
{''.join(cards)}
<script id="jira-plan" type="application/json">{embedded_plan(raw)}</script>
<script>const s=document.querySelector('#status'),a=document.querySelector('#action');function f(){{document.querySelectorAll('.finding').forEach(x=>x.hidden=(s.value&&x.dataset.status!==s.value)||(a.value&&x.dataset.action!==a.value))}}s.onchange=f;a.onchange=f;</script>
</body></html>'''
    return document.encode("utf-8"), token


def read_preview(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise JiraWritebackError(f"cannot read Jira preview: {error}") from error
    match = re.search(
        r'<script id="jira-plan" type="application/json">(.*?)</script>', value, re.S
    )
    if not match:
        raise JiraWritebackError("Jira preview does not contain an embedded plan")
    try:
        plan = json.loads(match.group(1))
    except json.JSONDecodeError as error:
        raise JiraWritebackError("Jira preview contains invalid plan JSON") from error
    if not isinstance(plan, dict) or plan.get("schema_version") != PREVIEW_SCHEMA:
        raise JiraWritebackError("Jira preview has an invalid schema")
    expected_preview, token = render_preview(plan)
    if raw != expected_preview:
        raise JiraWritebackError(
            "Jira preview visible content does not match its embedded plan"
        )
    return plan, token


def action_counts(plan: dict[str, Any]) -> dict[str, int]:
    return {
        action: sum(item["action"] == action for item in plan["items"])
        for action in ("create", "comment", "reuse")
    }


def plan_command(args: argparse.Namespace) -> int:
    client = JiraClient.from_environment(args.site)
    plan = build_plan(
        triage_path=Path(args.triage),
        report_path=Path(args.report),
        repository=args.repository,
        branch=args.branch,
        site=args.site,
        project_key=args.project,
        issue_type=args.issue_type,
        pr_url=args.pr_url,
        preview_path=Path(args.output),
        audience_approved=args.audience_approved,
        client=client,
    )
    content, token = render_preview(plan)
    atomic_write(Path(args.output), content)
    print(
        json.dumps(
            {
                "preview_path": args.output,
                "approval_token": token,
                "finding_count": plan["finding_count"],
                "technical_batch_count": plan["technical_batch_count"],
                "action_counts": action_counts(plan),
                "jira_site": plan["jira"]["site"],
                "jira_project": plan["jira"]["project_key"],
                "jira_issue_type": plan["jira"]["issue_type_name"],
                "jira_identity": plan["jira"]["display_name"],
                "jira_modified": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def verify_issue_readback(
    issue: dict[str, Any], item: dict[str, Any], expect_description: bool
) -> None:
    state = current_issue_state(issue)
    if state["summary"] != item["summary"]:
        raise JiraWritebackError(f"finding {item['finding_id']}: Jira summary readback failed")
    if expect_description:
        for binding in (
            f"Finding ID: {item['finding_id']}",
            f"Finding fingerprint: {item['finding_fingerprint']}",
            f"Report path: ",
        ):
            if binding not in state["description_text"]:
                raise JiraWritebackError(
                    f"finding {item['finding_id']}: Jira description readback failed"
                )
        expected_labels = sorted(item["create_fields"]["labels"])
        if state["labels"] != expected_labels:
            raise JiraWritebackError(
                f"finding {item['finding_id']}: Jira labels readback failed"
            )
        expected_priority = item["snapshot"]["jira_priority"]
        if expected_priority is not None and state["priority"] != expected_priority:
            raise JiraWritebackError(
                f"finding {item['finding_id']}: Jira priority readback failed"
            )
    elif item["field_updates"]:
        if "labels" in item["field_updates"] and state["labels"] != sorted(
            item["field_updates"]["labels"]
        ):
            raise JiraWritebackError(
                f"finding {item['finding_id']}: Jira label update readback failed"
            )
        expected_priority = item["snapshot"]["jira_priority"]
        if "priority" in item["field_updates"] and state["priority"] != expected_priority:
            raise JiraWritebackError(
                f"finding {item['finding_id']}: Jira priority update readback failed"
            )


def receipt_paths(preview_path: Path) -> tuple[Path, Path]:
    root = preview_path.parent / "receipts"
    return root / "current.json", root / "history" / f"{utc_timestamp()}.json"


def persist_receipt(receipt: dict[str, Any], current: Path, history: Path) -> None:
    content = json_bytes(receipt)
    atomic_write(history, content, exclusive=True)
    atomic_write(current, content)


def apply_command(args: argparse.Namespace) -> int:
    preview_path = Path(args.preview)
    approved, token = read_preview(preview_path)
    if args.approval_token != token:
        raise JiraWritebackError("approval token does not match the Jira preview")
    client = JiraClient.from_environment(approved["jira"]["site"])
    rebuilt = build_plan(
        triage_path=repo_root() / approved["triage_path"],
        report_path=repo_root() / approved["report_path"],
        repository=approved["repository"],
        branch=approved["branch"],
        site=approved["jira"]["site"],
        project_key=approved["jira"]["project_key"],
        issue_type=approved["jira"]["issue_type_name"],
        pr_url=approved["pull_request"]["url"] if approved.get("pull_request") else None,
        preview_path=preview_path,
        audience_approved=True,
        client=client,
    )
    if json_bytes(rebuilt) != json_bytes(approved):
        raise JiraWritebackError("Jira plan changed after preview; generate a new preview")

    current_receipt, history_receipt = receipt_paths(preview_path)
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "site": approved["jira"]["site"],
        "project_key": approved["jira"]["project_key"],
        "issue_type": approved["jira"]["issue_type_name"],
        "account_id": approved["jira"]["account_id"],
        "repository": approved["repository"],
        "branch": approved["branch"],
        "revision": approved["revision"],
        "triage_sha256": approved["triage_sha256"],
        "report_path": approved["report_path"],
        "report_sha256": approved["report_sha256"],
        "report_url": approved.get("report_url"),
        "preview_sha256": token,
        "started_at": utc_timestamp(),
        "completed_at": None,
        "complete": False,
        "results": [],
    }
    for item in approved["items"]:
        result = {
            "finding_id": item["finding_id"],
            "action": item["action"],
            "issue_key": item["issue_key"],
            "issue_url": item["issue_url"],
            "snapshot": item["snapshot"],
            "priority_source": item["snapshot"]["priority_source"],
            "comment_id": None,
            "update_fingerprint": item["update_fingerprint"],
            "last_update_fingerprint": item["last_update_fingerprint"],
            "outcome": None,
        }
        try:
            if item["action"] == "create":
                response = client.request("POST", "/rest/api/3/issue", {"fields": item["create_fields"]})
                if not isinstance(response, dict):
                    raise JiraWritebackError("Jira returned an invalid create response")
                key = require_string(response.get("key"), "created Jira issue key")
                result["issue_key"] = key
                result["issue_url"] = issue_url(approved["jira"]["site"], key)
                issue = get_issue(client, key)
                verify_issue_readback(issue, item, True)
                result["outcome"] = "created"
            elif item["action"] == "comment":
                key = require_string(item.get("issue_key"), "existing Jira issue key")
                if item["field_updates"]:
                    client.request(
                        "PUT",
                        f"/rest/api/3/issue/{quote(key)}?returnIssue=true",
                        {"fields": item["field_updates"]},
                    )
                response = client.request(
                    "POST",
                    f"/rest/api/3/issue/{quote(key)}/comment",
                    {"body": adf_document(item["update_comment"])},
                )
                if not isinstance(response, dict):
                    raise JiraWritebackError("Jira returned an invalid comment response")
                result["comment_id"] = require_string(response.get("id"), "Jira comment id")
                issue = get_issue(client, key)
                verify_issue_readback(issue, item, False)
                comments = get_comments(client, key)
                if not any(
                    item["update_fingerprint"] in adf_text(comment.get("body"))
                    for comment in comments
                    if isinstance(comment, dict)
                ):
                    raise JiraWritebackError(
                        f"finding {item['finding_id']}: Jira comment readback failed"
                    )
                result["outcome"] = "commented"
            else:
                result["outcome"] = "reused"
        except (JiraWritebackError, OSError) as error:
            result["outcome"] = "uncertain"
            result["error"] = str(error)
            receipt["results"].append(result)
            receipt["completed_at"] = utc_timestamp()
            persist_receipt(receipt, current_receipt, history_receipt)
            raise JiraWritebackError(
                f"finding {item['finding_id']}: Jira write or readback failed; inspect the partial receipt"
            ) from error
        receipt["results"].append(result)
    receipt["complete"] = True
    receipt["completed_at"] = utc_timestamp()
    persist_receipt(receipt, current_receipt, history_receipt)
    print(
        json.dumps(
            {
                "complete": True,
                "finding_count": len(receipt["results"]),
                "receipt_path": str(current_receipt),
                "history_receipt_path": str(history_receipt),
                "jira_modified": any(result["outcome"] != "reused" for result in receipt["results"]),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan and apply approval-gated Jira tracking for CodeQL triage."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="Create an authoritative HTML Jira preview.")
    plan.add_argument("--triage", required=True)
    plan.add_argument("--report", required=True)
    plan.add_argument("--repository", required=True)
    plan.add_argument("--branch", required=True)
    plan.add_argument("--site", required=True)
    plan.add_argument("--project", required=True)
    plan.add_argument("--issue-type", default="Task")
    plan.add_argument("--pr-url")
    plan.add_argument("--audience-approved", action="store_true")
    plan.add_argument("--output", required=True)
    plan.set_defaults(handler=plan_command)
    apply = subparsers.add_parser("apply", help="Apply one exactly approved Jira preview.")
    apply.add_argument("--preview", required=True)
    apply.add_argument("--approval-token", required=True)
    apply.set_defaults(handler=apply_command)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return args.handler(args)
    except (JiraWritebackError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
