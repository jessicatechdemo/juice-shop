# Scheduled CodeQL, Codex Triage, and Jira Handoff Plan

Status: Implemented locally; workflow execution pending  
Last verified: 2026-08-04

## Decision

Extend the weekly `CodeQL Scheduled Scan` workflow so that it analyzes only `main`, after which Codex triages every open CodeQL alert associated with that exact branch and revision. Package the validated branch triage as a Jira handoff artifact that the trusted Jira workflow can turn into an approval preview and, after explicit manual approval, Jira Tasks.

The scheduled workflow will not receive Jira credentials and will not create Jira tickets directly. Ticket creation remains approval-gated through the trusted default-branch Jira workflow.

## Scheduled Processing Flow

1. Change the scheduled workflow checkout from `master` to `main`, fetch full history, attach `main` as the current branch, and record its full revision.
2. Run the existing scheduled CodeQL `security-extended` analysis and upload its SARIF results to GitHub Code Scanning.
3. After analysis completes, run `codeql_branch_intake.py` with `GH_TOKEN` to retrieve every open CodeQL alert for exactly `refs/heads/main` and its matching instances.
4. Bind the intake to the repository, branch, ref, checked-out revision, CodeQL alert numbers, and matching instance commits using `codeql-branch-intake/v1`.
5. When the intake is non-empty, install the pinned Codex Security plugin and run the same schema-constrained Codex triage used by the PR workflow.
6. Require one `triage-finding/v0` result per imported alert, with `source_type: "sarif"`, a stable `github-codeql-alert-<number>` input ID, and CodeQL security severity copied from the original alert metadata.
7. Validate and persist the triage with `persist_triage.py`, then render the HTML report and bounded Markdown summary.
8. Package the intake, triage, report, summary, validation receipts, and SHA-256 metadata as one `codeql-jira-handoff` artifact.
9. Let the trusted Jira workflow validate the handoff, build a duplicate-checked approval preview, and expose its run ID and approval token.
10. Create, update, or reuse Jira Tasks only after a manual `workflow_dispatch` supplies the reviewed run ID and exact approval token.

If no open alerts exist, report that result and do not upload a Jira handoff. If intake, Codex triage, validation, or packaging fails, fail the scheduled workflow and produce no consumable handoff.

## Branch Handoff Contract

Add `codeql-jira-branch-handoff/v1` alongside the existing PR-specific `codeql-jira-handoff/v1` contract. The branch contract will contain:

- `scope: "branch"`
- Repository, branch, exact ref, and full scanned revision
- Intake schema and expected finding count
- SHA-256 digests for `intake.json`, `current.json`, `report.html`, `summary.md`, `persist-receipt.json`, and `report-receipt.json`
- The scheduled workflow run identity needed for audit, without credentials or secret values

The branch contract must omit pull-request number, URL, and base revision. Update `validate_codeql_handoff.py` to accept both contracts without weakening the current PR checks:

- PR handoffs retain all existing repository, PR, base/head revision, URL, digest, and intake validations.
- Branch handoffs require `codeql-branch-intake/v1`, an exact branch/ref/revision match, matching branch instances, complete result coverage, and matching report/persistence receipts.
- Validator outputs include an explicit `scope`. Pull-request outputs include the existing PR fields; branch outputs omit them.

Keep the existing PR handoff schema unchanged to avoid migrating or invalidating current PR artifacts.

## Trusted Jira Workflow

Extend `Publish CodeQL triage to Jira` so its `workflow_run` trigger accepts both `CodeQL Scan` and `CodeQL Scheduled Scan`.

- Continue accepting `pull_request` completions from `CodeQL Scan`.
- Accept `schedule` and manual `workflow_dispatch` completions only from `CodeQL Scheduled Scan`.
- Require the source workflow conclusion to be `success` and exactly one unexpired `codeql-jira-handoff` artifact.
- Check out all Jira tooling from the default branch, then validate the downloaded artifact before checking out the triaged revision.
- For branch scope, call `jira_writeback.py plan` without `--pr-url`; Jira descriptions therefore omit the pull-request section.
- Use the skill's fixed Jira destination: site `https://jesssg50mail.atlassian.net`, project `KAN`, issue type `Task`. Align the workflow's current project value with `KAN` before enabling the scheduled path.
- Preserve the existing `codeql-jira-preview` artifact, SHA-256 approval token, `jira-security` environment, manual apply job, serial writes, readback, and receipt generation.

The automatic `workflow_run` job may read Jira metadata, search for duplicates, and build the preview. It must not call `jira_writeback.py apply` or create tickets. Only the manually dispatched apply job may perform Jira writes.

## Jira Ticket Behavior

Create one Jira Task for each persisted `confirmed`, `needs_review`, or `not_actionable` finding when no matching Task exists. Use the existing stable identity and duplicate handling:

- Summary: `[CodeQL][#<alert-number>] <finding title>`
- Fingerprint: repository, CodeQL alert number, and stable finding ID
- Labels: `codex-codeql` plus the Codex verdict label
- Priority: map CodeQL security severity only; never derive it from verdict or confidence
- Existing identical Task: reuse without a write
- Existing changed Task with a verified receipt: update approved fields and add one changed-fields comment
- Ambiguous duplicate or missing baseline: block the plan or apply instead of guessing

Because PR and scheduled triage use the same alert number and finding fingerprint, a scheduled run must reuse the Jira Task already created for that finding rather than create a duplicate.

## Security and Failure Controls

- Keep `JIRA_API_TOKEN`, Jira user identity, and Jira base URL out of the scheduled scan workflow and its artifacts.
- Keep Codex read-only and treat alert, SARIF-derived, repository, and report text as untrusted data.
- Never execute code or workflow content from a scanned non-default revision in the trusted Jira workflow; Jira planning and application use tooling checked out from the default branch.
- Validate every artifact digest and branch/revision binding before Jira planning and again before approved application.
- Never create Jira tickets automatically after a scheduled scan; require the reviewed preview and exact approval token.
- Never mutate or dismiss GitHub Code Scanning alerts as part of Jira tracking.
- Retain Jira receipts so reruns can distinguish `create`, `reuse`, and `comment` without duplicate Tasks.

## Test Plan

Add focused tests covering:

- Scheduled intake queries only the exact `refs/heads/main` alert scope and retains matching branch instances.
- Branch handoff validation accepts a complete, digest-bound `codeql-branch-intake/v1` bundle.
- Branch handoff validation rejects wrong repository, branch, ref, revision, instance commit, result count, schema, or digest.
- Existing PR handoff validation remains unchanged and passing.
- The Jira planning workflow routes PR, schedule, and scheduled manual runs correctly while rejecting unrelated push workflow completions.
- Branch-scope previews omit PR metadata and do not pass `--pr-url`.
- An empty scheduled alert set creates no handoff and no Jira preview.
- Invalid or incomplete triage creates no consumable handoff.
- The automatic planning job performs no Jira issue-create request.
- Manual application with a valid reviewed token can create a missing Task, reuse an identical Task, or comment on a verified changed Task.
- Repeated PR and scheduled handoffs for the same CodeQL alert do not create duplicate Jira Tasks.
- Jira credentials and secret values never appear in handoffs, previews, summaries, logs, or receipts.

Run the complete triage skill unit suite, workflow YAML validation, JSON/schema checks, and `npm run lint`. The change does not modify challenge code, so RSN is not required.

## Acceptance Criteria

- Every successful scheduled CodeQL scan of `main` is followed by branch-bound Codex triage when open alerts exist.
- Every imported alert receives exactly one validated Codex verdict and retains its SARIF origin and CodeQL security severity.
- A successful non-empty scheduled triage publishes one validated Jira handoff artifact.
- The trusted workflow creates a complete Jira approval preview for that handoff without creating a ticket automatically.
- Jira Tasks can be created only by the manual approval-token apply path.
- Existing PR Jira handoffs continue to work.
- Scheduled and PR processing reuse the same Jira Task for the same CodeQL alert.
- Failed, incomplete, stale, mismatched, or ambiguous handoffs cannot reach Jira application.

## Assumptions

- The scheduled scan remains weekly on Monday at 02:00 UTC and can also be run manually.
- `main` is the only scheduled scan and scheduled triage target; no other branch is accepted as a fallback.
- Scheduled triage covers the full open CodeQL backlog for `main`, not only alerts introduced since the previous scheduled run.
- All three Codex verdicts are eligible for Jira tracking under the existing skill contract.
- Jira creation remains explicitly approval-gated; this plan does not authorize automatic ticket creation.
- Existing uncommitted work in `.github/workflows/codeql-scheduled.yml` and the triage/Jira tooling must be preserved.
