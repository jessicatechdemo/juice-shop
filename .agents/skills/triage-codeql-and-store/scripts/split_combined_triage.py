#!/usr/bin/env python3
"""Validate and split combined CodeQL triage and Codex relationship output."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

import persist_triage


COMBINED_SCHEMA = "combined-security-triage/v1"
RELATIONSHIP_SCHEMA = "security-relationships/v1"
CODEX_DOCUMENT_TYPE = "codex-security.findings"
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CLASSIFICATIONS = {
    "exact_overlap",
    "related_distinct",
    "no_candidate",
    "needs_further_review",
}
MATCHING_CLASSIFICATIONS = {"exact_overlap", "related_distinct", "needs_further_review"}


class CombinedTriageError(ValueError):
    pass


def read_object(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise CombinedTriageError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise CombinedTriageError(f"{path} must contain a JSON object")
    return value, raw


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CombinedTriageError(f"{field} must be a non-empty string")
    return value.strip()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def validate_codex_findings(value: dict[str, Any]) -> set[str]:
    if value.get("documentType") != CODEX_DOCUMENT_TYPE:
        raise CombinedTriageError(
            f'Codex findings documentType must be "{CODEX_DOCUMENT_TYPE}"'
        )
    require_string(value.get("scanId"), "codex.scanId")
    findings = value.get("findings")
    if not isinstance(findings, list):
        raise CombinedTriageError("codex.findings must be an array")
    identifiers: set[str] = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise CombinedTriageError(f"codex.findings[{index}] must be an object")
        identifier = require_string(
            finding.get("findingId"), f"codex.findings[{index}].findingId"
        )
        if identifier in identifiers:
            raise CombinedTriageError(f"duplicate Codex finding ID: {identifier}")
        identifiers.add(identifier)
    return identifiers


def validate_metadata(
    value: dict[str, Any],
    revision: str,
    findings_raw: bytes,
    scan_id: str,
    finding_count: int,
) -> None:
    if value.get("schema_version") != "codex-security-scan-metadata/v1":
        raise CombinedTriageError("Codex scan metadata schema is invalid")
    if value.get("revision") != revision:
        raise CombinedTriageError("Codex scan revision does not match combined triage")
    if value.get("scan_id") != scan_id:
        raise CombinedTriageError("Codex scan ID does not match its findings")
    if value.get("findings_sha256") != sha256(findings_raw):
        raise CombinedTriageError("Codex findings digest does not match scan metadata")
    if value.get("status") != "complete":
        raise CombinedTriageError("Codex Security scan is not complete")
    if value.get("finding_count") != finding_count:
        raise CombinedTriageError("Codex finding count does not match scan metadata")


def validate_relationships(
    combined: dict[str, Any], codeql_ids: set[str], codex_ids: set[str], revision: str
) -> dict[str, Any]:
    relationships = combined.get("relationships")
    if not isinstance(relationships, list):
        raise CombinedTriageError("combined.relationships must be an array")
    relationship_ids: set[str] = set()
    accounted_codeql: set[str] = set()
    normalized_relationships: list[dict[str, Any]] = []
    for index, relationship in enumerate(relationships):
        field = f"combined.relationships[{index}]"
        if not isinstance(relationship, dict):
            raise CombinedTriageError(f"{field} must be an object")
        relationship_id = require_string(
            relationship.get("relationship_id"), f"{field}.relationship_id"
        )
        if relationship_id in relationship_ids:
            raise CombinedTriageError(f"duplicate relationship ID: {relationship_id}")
        relationship_ids.add(relationship_id)
        if relationship.get("status") != "proposed":
            raise CombinedTriageError(f'{field}.status must be "proposed"')
        classification = relationship.get("classification")
        if classification not in CLASSIFICATIONS:
            raise CombinedTriageError(f"{field}.classification is invalid")
        codeql_id = require_string(
            relationship.get("codeql_finding_id"), f"{field}.codeql_finding_id"
        )
        if codeql_id not in codeql_ids:
            raise CombinedTriageError(f"{field} references an unknown CodeQL finding")
        if codeql_id in accounted_codeql:
            raise CombinedTriageError(f"CodeQL finding is accounted more than once: {codeql_id}")
        accounted_codeql.add(codeql_id)
        related = relationship.get("codex_finding_ids")
        if not isinstance(related, list) or any(
            not isinstance(item, str) or item not in codex_ids for item in related
        ):
            raise CombinedTriageError(f"{field}.codex_finding_ids is invalid")
        if len(set(related)) != len(related):
            raise CombinedTriageError(f"{field}.codex_finding_ids contains duplicates")
        if classification == "no_candidate" and related:
            raise CombinedTriageError(f"{field} no_candidate must not reference Codex findings")
        if classification in MATCHING_CLASSIFICATIONS and not related:
            raise CombinedTriageError(f"{field} must reference at least one Codex finding")
        criteria = (
            "same_source",
            "same_failed_control",
            "same_sink",
            "same_precondition",
            "same_impact",
        )
        for criterion in criteria:
            if relationship.get(criterion) not in {True, False, None}:
                raise CombinedTriageError(f"{field}.{criterion} is invalid")
        if classification == "exact_overlap" and any(
            relationship.get(criterion) is not True for criterion in criteria
        ):
            raise CombinedTriageError(
                f"{field} exact_overlap requires all identity criteria to match"
            )
        require_string(relationship.get("rationale"), f"{field}.rationale")
        if relationship.get("human_review_required") is not True:
            raise CombinedTriageError(f"{field}.human_review_required must be true")
        evidence = relationship.get("evidence")
        if not isinstance(evidence, list) or any(
            not isinstance(item, str) for item in evidence
        ):
            raise CombinedTriageError(f"{field}.evidence must be an array of strings")
        normalized_relationships.append(relationship)
    missing_codeql = sorted(codeql_ids - accounted_codeql)
    if missing_codeql:
        raise CombinedTriageError(
            f"combined relationships do not account for CodeQL findings: {missing_codeql}"
        )

    accounting = combined.get("codex_finding_accounting")
    if not isinstance(accounting, list):
        raise CombinedTriageError("combined.codex_finding_accounting must be an array")
    accounted_codex: set[str] = set()
    normalized_accounting: list[dict[str, Any]] = []
    for index, item in enumerate(accounting):
        field = f"combined.codex_finding_accounting[{index}]"
        if not isinstance(item, dict):
            raise CombinedTriageError(f"{field} must be an object")
        codex_id = require_string(item.get("codex_finding_id"), f"{field}.codex_finding_id")
        if codex_id not in codex_ids or codex_id in accounted_codex:
            raise CombinedTriageError(f"{field} has an unknown or duplicate Codex finding ID")
        accounted_codex.add(codex_id)
        ids = item.get("relationship_ids")
        if not isinstance(ids, list) or any(
            not isinstance(identifier, str) or identifier not in relationship_ids
            for identifier in ids
        ):
            raise CombinedTriageError(f"{field}.relationship_ids is invalid")
        if len(set(ids)) != len(ids):
            raise CombinedTriageError(f"{field}.relationship_ids contains duplicates")
        status = item.get("status")
        if status not in {"candidate", "no_candidate"}:
            raise CombinedTriageError(f"{field}.status is invalid")
        if (status == "candidate") != bool(ids):
            raise CombinedTriageError(f"{field}.status does not match relationship IDs")
        normalized_accounting.append(item)
    missing_codex = sorted(codex_ids - accounted_codex)
    if missing_codex:
        raise CombinedTriageError(
            f"combined accounting does not cover Codex findings: {missing_codex}"
        )

    return {
        "schema_version": RELATIONSHIP_SCHEMA,
        "repository": {"revision": revision},
        "relationships": normalized_relationships,
        "codex_finding_accounting": normalized_accounting,
    }


def split(
    combined_path: Path,
    intake_path: Path,
    codex_path: Path,
    metadata_path: Path,
    expected_revision: str,
    triage_output: Path,
    relationships_output: Path,
) -> dict[str, Any]:
    if not REVISION_PATTERN.fullmatch(expected_revision):
        raise CombinedTriageError("expected revision must be a full lowercase commit SHA")
    combined, combined_raw = read_object(combined_path)
    if combined.get("schema_version") != COMBINED_SCHEMA:
        raise CombinedTriageError(f'combined schema must be "{COMBINED_SCHEMA}"')
    intake, _ = read_object(intake_path)
    codex, codex_raw = read_object(codex_path)
    metadata, _ = read_object(metadata_path)
    codex_ids = validate_codex_findings(codex)
    validate_metadata(
        metadata,
        expected_revision,
        codex_raw,
        str(codex.get("scanId")),
        len(codex_ids),
    )
    triage = combined.get("codeql_triage")
    if not isinstance(triage, dict):
        raise CombinedTriageError("combined.codeql_triage must be an object")
    expected_count, intake_ref, commits = persist_triage.validate_intake(
        intake, triage, "master"
    )
    persist_triage.validate_payload(triage, expected_count)
    persist_triage.validate_payload_against_intake(triage, intake_ref, commits, intake)
    repository = triage.get("repository")
    if not isinstance(repository, dict) or repository.get("revision") != expected_revision:
        raise CombinedTriageError("CodeQL triage revision does not match expected revision")
    codeql_ids = {
        require_string(finding.get("input_id"), "codeql finding input_id")
        for finding in triage["findings"]
    }
    relationships = validate_relationships(
        combined, codeql_ids, codex_ids, expected_revision
    )
    atomic_write(triage_output, triage)
    atomic_write(relationships_output, relationships)
    return {
        "schema_version": COMBINED_SCHEMA,
        "revision": expected_revision,
        "codeql_finding_count": len(codeql_ids),
        "codex_finding_count": len(codex_ids),
        "relationship_count": len(relationships["relationships"]),
        "combined_sha256": sha256(combined_raw),
        "triage_sha256": sha256(triage_output.read_bytes()),
        "relationships_sha256": sha256(relationships_output.read_bytes()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and split combined CodeQL and Codex Security triage."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--intake", required=True)
    parser.add_argument("--codex-findings", required=True)
    parser.add_argument("--codex-metadata", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--triage-output", required=True)
    parser.add_argument("--relationships-output", required=True)
    args = parser.parse_args()
    try:
        result = split(
            Path(args.input),
            Path(args.intake),
            Path(args.codex_findings),
            Path(args.codex_metadata),
            args.expected_revision,
            Path(args.triage_output),
            Path(args.relationships_output),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (CombinedTriageError, persist_triage.ValidationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
