Use $codex-security:security-diff-scan to scan the security-relevant changes between refs/heads/master (base) and refs/heads/{branch_name} (target).
  
Complete every required security-diff-scan phase and finalize the scan. Do not change repository source files, run application tests, publish findings, or interact with Jira or GitHub issues.
  
Return only the codex-security.findings-output JSON selected by the output schema. Put the complete canonical codex-security.findings JSON document in codex_findings_json as a JSON-encoded string. Preserve the authoritative scanId, findingId, fingerprints,locations, validation, attack-path, severity, remediation, and evidence fields. Return a valid canonical document with an empty findings array when the completed scan finds nothing.