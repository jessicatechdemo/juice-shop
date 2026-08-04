#!/usr/bin/env python3
"""Render a bounded Markdown summary from validated CodeQL triage JSON."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


MAX_SUMMARY_LENGTH = 60_000
ALERT_PATTERN = re.compile(
    r"(?:/security/code-scanning/|/code-scanning/alerts/)([0-9]+)(?:$|[/?#])"
)


class SummaryError(ValueError):
    pass


def clean(value: Any, fallback: str = "unknown") -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    escaped = html.escape(" ".join(value.split()), quote=False)
    escaped = re.sub(r"([\\`*_{}\[\]()#+|])", r"\\\1", escaped)
    return escaped.replace("@", "&#64;")


def code_text(value: Any, fallback: str = "unknown") -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    return (
        html.escape(" ".join(value.split()), quote=False)
        .replace("@", "&#64;")
        .replace("`", "&#96;")
    )


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [clean(item, "") for item in value if isinstance(item, str) and item.strip()]


def alert_reference(finding: dict[str, Any]) -> tuple[str, str] | None:
    normalized = finding.get("normalized_input")
    references = normalized.get("references") if isinstance(normalized, dict) else []
    for reference in references or []:
        if not isinstance(reference, str):
            continue
        parsed = urlparse(reference)
        match = ALERT_PATTERN.search(parsed.path)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "github.com"
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and match
            and match.end() == len(parsed.path)
        ):
            return match.group(1), reference
    return None


def list_section(title: str, values: Any) -> list[str]:
    items = string_list(values)
    if not items:
        return [f"**{title}:** None recorded"]
    return [f"**{title}:**", *[f"- {item}" for item in items]]


def render(payload: dict[str, Any]) -> str:
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise SummaryError("triage.findings must be an array")
    sections = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise SummaryError("every triage finding must be an object")
        reference = alert_reference(finding)
        alert_label = (
            f"[Alert #{reference[0]}]({reference[1]})" if reference else "CodeQL alert"
        )
        lines = [
            f"### {alert_label}: {clean(finding.get('title'), 'Untitled finding')}",
            "",
            f"- **Verdict:** `{code_text(finding.get('verdict'))}`",
            f"- **Confidence:** `{code_text(finding.get('confidence'))}`",
            f"- **Finding ID:** `{code_text(finding.get('input_id'))}`",
            "",
            *list_section("Evidence", finding.get("evidence")),
            "",
            *list_section("Counterevidence", finding.get("counterevidence")),
            "",
            *list_section("Proof gaps", finding.get("proof_gaps")),
            "",
            f"**Recommended next step:** {clean(finding.get('recommended_next_step'))}",
        ]
        sections.append("\n".join(lines))
    result = "\n\n".join(sections) or "No CodeQL findings were triaged."
    if len(result) > MAX_SUMMARY_LENGTH:
        result = result[: MAX_SUMMARY_LENGTH - 80].rstrip() + (
            "\n\n_Summary truncated; download the workflow report for complete details._"
        )
    return result + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Render a CodeQL triage Markdown summary.")
    parser.add_argument("--triage", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        payload = json.loads(Path(args.triage).read_text(encoding="utf-8"))
        content = render(payload)
        Path(args.output).write_text(content, encoding="utf-8")
        return 0
    except (OSError, json.JSONDecodeError, SummaryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
