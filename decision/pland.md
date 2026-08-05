# Plan: Combined CodeQL and Codex Security Triage

## Objective

Run CodeQL and Codex Security independently against the same exact `master`
revision, then use one joint triage pass to evaluate the CodeQL findings and
their relationship to the completed Codex Security findings.

Every finding retains its scanner identity and receives its own Jira Task.
Overlapping findings are not merged. A human confirms the proposed
relationship by approving the exact Jira preview, after which both Jira Tasks
receive a reciprocal link and the same rationale.

## Constraints

- Minimize end-to-end workflow time.
- Run both scanners on every scheduled execution, even when either scanner has
  zero findings.
- Do not spend tokens triaging CodeQL once and then triaging the same finding a
  second time for correlation.
- Bind all scanner, triage, report, and Jira artifacts to one full commit SHA.
- Keep one independent Jira Task per CodeQL finding and per Codex Security
  finding.
- Do not publish a proposed relationship to Jira without human approval.
- Preserve approval-gated Jira writes and verify all writes by readback.

## Selected Workflow

```text
Resolve exact master commit
          |
          +--------------------------+
          |                          |
          v                          v
   CodeQL analysis          Codex Security scan
          |                          |
          +-------------+------------+
                        |
                        v
            One combined triage pass
             - triage every CodeQL alert
             - compare against Codex findings
             - propose relationship rationale
                        |
                        v
             Validate and split artifacts
                        |
              +---------+---------+
              |                   |
              v                   v
      Combined HTML report   Hashed Jira handoff
                                      |
                                      v
                            Exact approval preview
                                      |
                               human approval
                                      |
                                      v
                         Create/reuse separate Tasks
                         Link and comment both Tasks
```

The two scanners run in parallel. The joint triage waits for both results and
reasons about CodeQL validity and cross-scanner correlation together, reducing
latency and token use compared with two separate triage passes.

## Artifact Contracts

The scheduled workflow produces:

- `intake.json`: open CodeQL alerts for `refs/heads/master` at the resolved
  revision;
- `current.json`: validated `triage-finding/v0` CodeQL triage;
- `codex-findings.json`: completed canonical `codex-security.findings` output;
- `codex-scan-metadata.json`: completion status, scan ID, revision, count, and
  findings digest;
- `relationships.json`: `security-relationships/v1` proposals and complete
  Codex finding accounting;
- `report.html`: CodeQL, Codex Security, and relationship evidence;
- existing summary and persistence/render receipts; and
- `metadata.json`: hashes for every handoff file.

The combined model response is validated as
`combined-security-triage/v1`, then split into the existing CodeQL triage
contract and the new relationship contract. Invalid IDs, incomplete finding
accounting, revision drift, scan incompleteness, digest mismatches, duplicate
records, and invalid exact-overlap criteria stop the workflow.

## Relationship Rules

Allowed proposal classifications are:

- `exact_overlap`: source, failed control, sink, precondition, and impact all
  match;
- `related_distinct`: a meaningful relationship exists, but the findings need
  separate remediation or validation;
- `no_candidate`: no Codex Security counterpart is supported; and
- `needs_further_review`: the static evidence cannot settle the relationship.

Filenames, titles, CWE labels, severity, or a shared vulnerability category are
not sufficient to establish an exact overlap. Every CodeQL finding must have
exactly one relationship record, including an explicit `no_candidate` record,
and every Codex Security finding must be accounted for.

Relationships remain proposals in the report and handoff. For
`exact_overlap` and `related_distinct`, applying the SHA-256-bound Jira preview
is the human confirmation step. `needs_further_review` never authorizes a Jira
issue link.

## Jira Behavior

- CodeQL summary: `[CodeQL][#<alert-number>] <title>`
- Codex Security summary: `[Codex Security][<finding-id>] <title>`
- Stable scanner IDs and fingerprints are used to find and reuse Tasks.
- Exact overlaps still result in two Tasks.
- The preview shows every create/reuse/update operation, relationship pair,
  classification, and rationale before approval.
- Approved `exact_overlap` and `related_distinct` pairs receive a reciprocal
  Jira `relates to` link and matching comments on both Tasks.
- The apply step reads back both links and both comments and records partial
  state if either side cannot be verified.
- No Task is resolved, closed, or transitioned as a side effect of correlation.

## Security and Trust Boundaries

- The scheduled workflow checks out and verifies one exact `master` SHA in
  every job.
- CodeQL and Codex Security run independently; neither is conditional on the
  other's finding count.
- Scanner and repository text is treated as untrusted data.
- The scan workflow has no Jira credentials.
- The Jira workflow checks out trusted default-branch tooling, validates every
  artifact and hash, checks out the exact triaged revision on the named branch,
  and requires an exact approval token before writes.
- Jira issue-link permission is requested only when an approved preview
  contains an overlap or related-distinct operation.

## Implementation Status

- [x] Resolve and enforce an exact scheduled `master` revision.
- [x] Run CodeQL and Codex Security independently in parallel.
- [x] Run one combined CodeQL triage and correlation pass.
- [x] Support zero-CodeQL and zero-Codex result paths.
- [x] Validate and persist complete relationship accounting.
- [x] Render both scanners and relationship rationale in `report.html`.
- [x] Package and validate the expanded hashed handoff.
- [x] Create or reuse a separate Jira Task for every scanner finding.
- [x] Require preview approval before reciprocal links and comments.
- [x] Read back Jira links/comments and preserve partial-failure receipts.
- [x] Add focused unit tests for contracts, reporting, handoff, and Jira logic.

## Verification

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s .agents/skills/triage-codeql-and-store/tests -p 'test_*.py'
npm run lint
git diff --check
```

The GitHub-hosted scan and Jira publication remain intentionally untriggered
until the branch is reviewed and the workflow changes are merged into trusted
default-branch tooling.
