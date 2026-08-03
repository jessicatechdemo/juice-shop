#!/usr/bin/env python3
"""Render a self-contained HTML report from a triage-finding/v0 artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA_VERSION = "triage-finding/v0"
VERDICTS = ("confirmed", "needs_review", "not_actionable")
VERDICT_LABELS = {
    "confirmed": "Confirmed",
    "needs_review": "Needs review",
    "not_actionable": "Not actionable",
}


class ReportError(ValueError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a filterable HTML report from CodeQL triage JSON."
    )
    parser.add_argument("--triage", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def load_triage(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReportError(f"cannot read triage JSON from {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ReportError("triage JSON must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ReportError(f'triage schema_version must be "{SCHEMA_VERSION}"')
    repository = payload.get("repository")
    if not isinstance(repository, dict):
        raise ReportError("triage.repository must be an object")
    for field in ("path", "revision"):
        if not isinstance(repository.get(field), str) or not repository[field].strip():
            raise ReportError(f"triage.repository.{field} must be a non-empty string")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise ReportError("triage.findings must be an array")
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ReportError(f"triage.findings[{index}] must be an object")
        if finding.get("verdict") not in VERDICTS:
            raise ReportError(f"triage.findings[{index}].verdict is invalid")
    return payload


def text(value: Any, fallback: str = "unknown") -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def html_text(value: Any, fallback: str = "unknown") -> str:
    return escape(text(value, fallback), quote=True)


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def list_html(values: Any, empty: str = "None recorded") -> str:
    items = string_list(values)
    if not items:
        return f'<p class="empty">{escape(empty)}</p>'
    return "<ul>" + "".join(f"<li>{escape(item)}</li>" for item in items) + "</ul>"


def github_alert_url(finding: dict[str, Any]) -> str | None:
    normalized = finding.get("normalized_input")
    if not isinstance(normalized, dict):
        return None
    for reference in string_list(normalized.get("references")):
        parsed = urlparse(reference)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "github.com"
            and "/code-scanning/" in parsed.path
        ):
            return reference
    return None


def alert_number(finding: dict[str, Any]) -> str:
    url = github_alert_url(finding)
    if url:
        candidate = url.rstrip("/").rsplit("/", 1)[-1]
        if candidate.isdigit():
            return candidate
    input_id = text(finding.get("input_id"), "")
    candidate = input_id.rsplit("-", 1)[-1]
    return candidate if candidate.isdigit() else "—"


def locations_html(finding: dict[str, Any]) -> str:
    locations = finding.get("affected_locations")
    if not isinstance(locations, list) or not locations:
        return '<p class="empty">No affected location recorded</p>'
    rendered = []
    for location in locations:
        if not isinstance(location, dict):
            continue
        path = html_text(location.get("path"))
        lines = html_text(location.get("lines"), "")
        label = html_text(location.get("label"), "location")
        detail = html_text(location.get("detail"), "")
        suffix = f":{lines}" if lines else ""
        rendered.append(
            f'<li><code>{path}{suffix}</code> <span class="muted">{label}</span>'
            f'<div>{detail}</div></li>'
        )
    return "<ul>" + "".join(rendered) + "</ul>" if rendered else (
        '<p class="empty">No affected location recorded</p>'
    )


def searchable_text(finding: dict[str, Any]) -> str:
    normalized = finding.get("normalized_input")
    normalized = normalized if isinstance(normalized, dict) else {}
    locations = finding.get("affected_locations")
    location_paths = []
    if isinstance(locations, list):
        location_paths = [
            text(location.get("path"), "")
            for location in locations
            if isinstance(location, dict)
        ]
    values = [
        text(finding.get("title"), ""),
        text(finding.get("input_id"), ""),
        text(finding.get("triage_item_id"), ""),
        text(normalized.get("vulnerable_component"), ""),
        *location_paths,
        *string_list(normalized.get("references")),
        *string_list(finding.get("evidence")),
        *string_list(finding.get("counterevidence")),
        *string_list(finding.get("proof_gaps")),
    ]
    return " ".join(values).lower()


def finding_html(finding: dict[str, Any]) -> str:
    verdict = finding["verdict"]
    normalized = finding.get("normalized_input")
    normalized = normalized if isinstance(normalized, dict) else {}
    boundary = finding.get("boundary_assessment")
    boundary = boundary if isinstance(boundary, dict) else {}
    rank = finding.get("exploitability_stack_rank")
    rank = rank if isinstance(rank, dict) else {}
    url = github_alert_url(finding)
    number = alert_number(finding)
    alert_link = (
        f'<a href="{escape(url, quote=True)}" target="_blank" '
        f'rel="noopener noreferrer">Open GitHub alert #{escape(number)}</a>'
        if url
        else f"Alert #{escape(number)}"
    )
    rank_value = rank.get("rank")
    rank_text = str(rank_value) if isinstance(rank_value, int) else "—"
    boundary_crossed = boundary.get("boundary_crossed")
    boundary_text = (
        "Yes" if boundary_crossed is True else "No" if boundary_crossed is False else "Unknown"
    )
    search = escape(searchable_text(finding), quote=True)
    return f"""
      <article class="finding" data-verdict="{verdict}" data-search="{search}">
        <header>
          <div>
            <p class="eyebrow">{html_text(finding.get('triage_item_id'))} · {alert_link}</p>
            <h2>{html_text(finding.get('title'))}</h2>
          </div>
          <span class="badge {verdict}">{VERDICT_LABELS[verdict]}</span>
        </header>
        <div class="metadata">
          <span><strong>Confidence</strong> {html_text(finding.get('confidence'))}</span>
          <span><strong>Queue rank</strong> {escape(rank_text)}</span>
          <span><strong>Boundary crossed</strong> {boundary_text}</span>
          <span><strong>Component</strong> {html_text(normalized.get('vulnerable_component'))}</span>
        </div>
        <section>
          <h3>Affected locations</h3>
          {locations_html(finding)}
        </section>
        <details open>
          <summary>Evidence</summary>
          {list_html(finding.get('evidence'))}
        </details>
        <details>
          <summary>Counterevidence</summary>
          {list_html(finding.get('counterevidence'))}
        </details>
        <details>
          <summary>Proof gaps</summary>
          {list_html(finding.get('proof_gaps'))}
        </details>
        <details>
          <summary>Boundary assessment</summary>
          <dl>
            <dt>Surface</dt><dd>{html_text(boundary.get('product_surface'))}</dd>
            <dt>Source trust</dt><dd>{html_text(boundary.get('source_trust'))}</dd>
            <dt>Policy basis</dt><dd>{html_text(boundary.get('policy_basis'))}</dd>
          </dl>
        </details>
        <p class="next-step"><strong>Next step:</strong> {html_text(finding.get('recommended_next_step'))}</p>
      </article>
    """


def build_report(payload: dict[str, Any], branch: str) -> tuple[str, Counter[str]]:
    findings = payload["findings"]
    counts = Counter(finding["verdict"] for finding in findings)
    repository = payload["repository"]
    generated_at = datetime.now(timezone.utc).isoformat()
    cards = "".join(finding_html(finding) for finding in findings)
    if not cards:
        cards = '<p id="empty-state" class="empty-state">No CodeQL findings were imported.</p>'
    total = len(findings)
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
  <title>CodeQL triage report · {escape(branch)}</title>
  <style>
    :root {{ color-scheme: light dark; --bg:#f5f7fb; --panel:#fff; --ink:#172033; --muted:#637083; --line:#dbe1ea; --confirmed:#b42318; --review:#b54708; --clear:#027a48; }}
    @media (prefers-color-scheme:dark) {{ :root {{ --bg:#111827; --panel:#1f2937; --ink:#f3f4f6; --muted:#aeb8c8; --line:#3b4658; }} }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ width:min(1180px,calc(100% - 32px)); margin:32px auto 64px; }}
    h1 {{ margin:.2rem 0; font-size:clamp(1.8rem,4vw,3rem); }}
    h2 {{ margin:.2rem 0 0; font-size:1.18rem; }}
    h3 {{ margin:0 0 .35rem; font-size:.92rem; }}
    a {{ color:#2563eb; }}
    .intro,.muted,.empty {{ color:var(--muted); }}
    .summary {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:24px 0; }}
    .summary button {{ text-align:left; border:1px solid var(--line); border-radius:14px; padding:16px; background:var(--panel); color:var(--ink); cursor:pointer; }}
    .summary button[aria-pressed="true"] {{ outline:3px solid #5b8def; outline-offset:1px; }}
    .summary strong {{ display:block; font-size:1.8rem; }}
    .controls {{ display:flex; gap:12px; align-items:center; margin:0 0 18px; }}
    input {{ flex:1; border:1px solid var(--line); border-radius:10px; padding:11px 13px; background:var(--panel); color:var(--ink); }}
    .finding {{ background:var(--panel); border:1px solid var(--line); border-radius:16px; padding:20px; margin:0 0 14px; box-shadow:0 8px 20px rgb(15 23 42 / 6%); }}
    .finding header {{ display:flex; justify-content:space-between; gap:16px; align-items:flex-start; }}
    .eyebrow {{ margin:0; color:var(--muted); font-size:.83rem; }}
    .badge {{ white-space:nowrap; border-radius:999px; padding:5px 10px; font-weight:700; font-size:.78rem; }}
    .badge.confirmed {{ color:var(--confirmed); background:#fee4e2; }}
    .badge.needs_review {{ color:var(--review); background:#fef0c7; }}
    .badge.not_actionable {{ color:var(--clear); background:#d1fadf; }}
    .metadata {{ display:flex; flex-wrap:wrap; gap:8px 18px; margin:14px 0; color:var(--muted); }}
    section,details {{ border-top:1px solid var(--line); padding-top:12px; margin-top:12px; }}
    summary {{ cursor:pointer; font-weight:700; }}
    ul {{ margin:.4rem 0 0; padding-left:1.25rem; }}
    dl {{ display:grid; grid-template-columns:max-content 1fr; gap:6px 12px; }}
    dt {{ font-weight:700; }} dd {{ margin:0; }}
    code {{ overflow-wrap:anywhere; }}
    .next-step {{ margin-bottom:0; }}
    .empty-state {{ text-align:center; padding:56px; background:var(--panel); border:1px dashed var(--line); border-radius:16px; color:var(--muted); }}
    [hidden] {{ display:none !important; }}
    @media (max-width:760px) {{ .summary {{ grid-template-columns:repeat(2,1fr); }} .finding header {{ display:block; }} .badge {{ display:inline-block; margin-top:10px; }} }}
  </style>
</head>
<body>
  <main>
    <p class="eyebrow">OWASP Juice Shop · CodeQL backlog</p>
    <h1>Triage report</h1>
    <p class="intro">Branch <code>{escape(branch)}</code> · Revision <code>{escape(repository['revision'])}</code><br>
      Repository <code>{escape(repository['path'])}</code> · Generated {escape(generated_at)}</p>
    <div class="summary" role="group" aria-label="Filter findings by verdict">
      <button type="button" data-filter="all" aria-pressed="true"><strong>{total}</strong>All findings</button>
      <button type="button" data-filter="confirmed" aria-pressed="false"><strong>{counts['confirmed']}</strong>Confirmed</button>
      <button type="button" data-filter="needs_review" aria-pressed="false"><strong>{counts['needs_review']}</strong>Needs review</button>
      <button type="button" data-filter="not_actionable" aria-pressed="false"><strong>{counts['not_actionable']}</strong>Not actionable</button>
    </div>
    <div class="controls">
      <label for="search"><strong>Search</strong></label>
      <input id="search" type="search" placeholder="Alert number, rule, path, title, or evidence">
      <span id="visible-count" aria-live="polite">{total} shown</span>
    </div>
    <div id="findings">{cards}</div>
  </main>
  <script>
    (() => {{
      const buttons = [...document.querySelectorAll('[data-filter]')];
      const findings = [...document.querySelectorAll('.finding')];
      const search = document.querySelector('#search');
      const visibleCount = document.querySelector('#visible-count');
      let verdict = 'all';
      const apply = () => {{
        const query = search.value.trim().toLowerCase();
        let shown = 0;
        findings.forEach((finding) => {{
          const matchesVerdict = verdict === 'all' || finding.dataset.verdict === verdict;
          const matchesSearch = !query || finding.dataset.search.includes(query);
          finding.hidden = !(matchesVerdict && matchesSearch);
          if (!finding.hidden) shown += 1;
        }});
        visibleCount.textContent = `${{shown}} shown`;
      }};
      buttons.forEach((button) => button.addEventListener('click', () => {{
        verdict = button.dataset.filter;
        buttons.forEach((candidate) => candidate.setAttribute('aria-pressed', String(candidate === button)));
        apply();
      }}));
      search.addEventListener('input', apply);
    }})();
  </script>
</body>
</html>
"""
    return html, counts


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
        triage_path = Path(args.triage)
        output_path = Path(args.output)
        payload = load_triage(triage_path)
        report, counts = build_report(payload, args.branch)
        content = report.encode("utf-8")
        atomic_write(output_path, content)
        if output_path.read_bytes() != content:
            raise ReportError(f"written content mismatch: {output_path}")
        result = {
            "schema_version": SCHEMA_VERSION,
            "triage_path": str(triage_path),
            "report_path": str(output_path),
            "finding_count": len(payload["findings"]),
            "verdict_counts": {verdict: counts[verdict] for verdict in VERDICTS},
            "sha256": hashlib.sha256(content).hexdigest(),
            "github_modified": False,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ReportError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
