---
name: triage-codeql-and-store
description: Import open GitHub CodeQL alerts for the exact checked-out branch, triage every alert as `confirmed`, `needs_review`, or `not_actionable`, persist the triage-finding/v0 contract, generate a filterable HTML report, and track every persisted finding as an approval-gated Jira Task. Use for complete CodeQL triage, durable reporting, fix-finding handoff, and audited Jira coverage. Put the full finding record, stable Finding ID, report path, CodeQL severity, and optional user-supplied PR in Jira. Use the fixed Jira destination and environment-supplied API credentials, generate one consolidated HTML approval preview, and never create GitHub tracking issues or mutate Code Scanning alerts.
---

# Triage CodeQL, Store, and Track in Jira

Run this workflow:

1. import every open CodeQL alert for the current branch
2. statically triage every imported alert
3. persist the exact triage contract and render the HTML report
4. ask the user for an optional PR URL; omit PR data when none is supplied
5. build one duplicate-checked HTML Jira preview for every persisted finding
6. pause for one exact approval token covering the complete preview
7. execute Jira operations serially in technical groups of at most 25
8. verify each Task or comment by readback and persist JSON receipts

## Fixed destination and credentials

Use only:

```text
Jira site: https://jesssg50mail.atlassian.net
Project key: KAN
Issue type: Task
```

Read credentials from the process environment:

```text
JIRA_BASE_URL
JIRA_USER_EMAIL
JIRA_API_TOKEN
```

Never ask the user to paste a token into chat. Never put the email or token in
repository files, HTML previews, approval hashes, receipts, commands, logs, or
errors. Send credentials only to the exact configured HTTPS `*.atlassian.net`
origin. Do not use Jira passwords, browser automation, CLI credentials, or an
unreviewed alternate site.

Before planning, verify the authenticated account, project, Task type, create
metadata, allowed priorities, and these project permissions:

```text
BROWSE_PROJECTS
CREATE_ISSUES
EDIT_ISSUES
ADD_COMMENTS
```

Stop before preview when any capability, required field, destination identity,
or metadata is missing or ambiguous. The project audience is approved to see
the complete finding details; pass that approval explicitly to the helper.

## GitHub constraints

Use GitHub only for current-branch CodeQL intake and optional PR verification.
Never create GitHub issues, bridge issues, alert comments, dismissal requests,
labels, or tracking relationships. Never PATCH a Code Scanning alert or change
its state, dismissal fields, or assignees.

GitHub exposes no supported API for linking a Jira Task to a Code Scanning
alert. Complete automation therefore produces a one-way link from Jira to the
Code Scanning alert. Do not claim that the alert contains a Jira backlink.

## Phase 1: Current-branch intake and triage

Resolve the canonical repository, current attached branch,
`refs/heads/<branch>`, and full revision. Never accept another branch, guess a
ref, check out another revision, or fall back to the default branch.

Create a temporary path outside the repository and run:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/codeql_branch_intake.py \
  --repository <owner/repo> \
  --repo-root <canonical-repository> \
  --output <temporary-intake-json>
```

Require the intake branch, ref, revision, and URL-encoded exact-ref endpoint to
match the checkout. Invoke `$codex-security:triage-finding` for every imported
alert and matching branch instance. Produce one `triage-finding/v0` result per
alert without merging duplicates.

Preserve alert number, URL, rule, tool, exact ref, instance commit, locations,
generic CodeQL severity, and CodeQL `security_severity_level`. Put the security
severity in `normalized_input.references` as exactly one of:

```text
codeql-security-severity:critical
codeql-security-severity:high
codeql-security-severity:medium
codeql-security-severity:low
```

Omit that reference when CodeQL supplies no security severity. Never derive
security severity from the Codex verdict or confidence. Retain the exact JSON
passed to the triage results app. Do not edit source, run application code, or
mutate GitHub or Jira during triage.

### Pull request CI intake

The PR workflow uses `codeql-pr-intake/v1` instead of importing the complete
branch backlog. After GitHub filters open CodeQL alerts by pull request, run
`scripts/codeql_pr_intake.py` to bind that alert set to the PR number, base
revision, checked-out head branch, and head revision. Persistence accepts both
the branch and PR intake contracts but never mixes their scopes.

Keep Jira credentials out of the PR workflow. Upload the validated triage,
report, intake, receipts, and metadata as `codeql-jira-handoff`. The
default-branch Jira workflow must revalidate this handoff with
`scripts/validate_codeql_handoff.py`. It may publish only the exact
`codeql-jira-preview` artifact and SHA-256 token reviewed by the user.

After validation, run `scripts/evaluate_codeql_gate.py` against the PR intake
and persisted triage. Block when CodeQL `security_severity_level` is `critical`
or `high` and the Codex verdict is `confirmed` or `needs_review`. Pass all other
evaluated combinations. The workflow's explicit fail-open policy reports an
indeterminate warning and passes when triage or gate evaluation is unavailable.
The required check name is `Codex + CodeQL SAST gate`.

### Scheduled main-branch intake

The `CodeQL Scheduled Scan` workflow scans only `main`. After analysis, use
`scripts/codeql_branch_intake.py` to import every open alert for exactly
`refs/heads/main`, then run the same schema-constrained Codex triage and
persistence flow used for current-branch intake.

Package a successful non-empty scheduled result as
`codeql-jira-branch-handoff/v1`, including the exact branch, ref, revision,
source workflow run identity, artifact hashes, and validation receipts. Keep
Jira credentials out of the scheduled workflow. The trusted default-branch
Jira workflow validates the handoff and builds an approval preview; only its
manual approval-token apply job may create or update Jira Tasks.

## Phase 2: Persist and report

Persist the validated result:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/persist_triage.py \
  --input <temporary-triage-json> \
  --intake <temporary-intake-json> \
  --branch <current-branch> \
  --expected-count <intake-count>
```

This writes:

```text
security-results/triage/codeql/<branch-slug>/current.json
security-results/triage/codeql/<branch-slug>/history/<timestamp>-<revision>.json
```

Render the exact persisted result:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/render_triage_report.py \
  --triage security-results/triage/codeql/<branch-slug>/current.json \
  --branch <branch> \
  --output security-results/triage/codeql/<branch-slug>/report.html
```

Require matching finding and verdict counts. The report must label `input_id`
as `Finding ID`, separately label `triage_item_id`, escape imported text, link
each alert, and filter all three verdicts.

## Phase 3: Optional PR input

Ask once:

```text
Provide the GitHub PR URL for this triaged branch, or leave it blank to omit PR information.
```

Do not infer or search for a PR. When blank, omit the entire PR section. When
provided, require a canonical GitHub PR URL in the source repository and verify
that its head repository, branch, and full SHA match the triaged checkout. Stop
instead of including mismatched PR data.

## Phase 4: Plan every Jira Task

Create one Jira Task for every persisted `confirmed`, `needs_review`, and
`not_actionable` finding. Use stable summary:

```text
[CodeQL][#<alert-number>] <finding title>
```

The description must include:

```text
Status
Finding ID
Triage item ID
Finding fingerprint
CodeQL security severity
Jira priority and priority source
Report path and SHA-256
Verified report URL only when the exact revision contains the report
Code scanning alert URL
Repository, branch, and revision
Confidence
Optional verified PR metadata
Affected locations
Evidence and counterevidence
Proof gaps
Recommended next step
Fix-finding handoff
```

Use these labels:

```text
codex-codeql
triage-confirmed | triage-needs-review | triage-not-actionable
```

Leave assignee unset. Do not transition or resolve Tasks.

Map CodeQL security severity to a live allowed Jira priority:

```text
critical -> Critical, or Highest when Critical is unavailable
high     -> High
medium   -> Medium
low      -> Low
missing  -> omit priority and record priority_source: jira_default
```

Do not map generic CodeQL `error`, `warning`, or `note`. Do not derive priority
from verdict or confidence.

Search the exact project across all Jira statuses for Finding ID and fingerprint
separately. Read every plausible candidate and compare exact labeled bindings.
Choose one outcome:

- `create`: no matching Task exists
- `reuse`: one matching Task exists and no substantive field changed
- `comment`: one matching Task exists and substantive fields changed
- `blocked`: duplicate identity or live/local baseline is ambiguous

Preserve an existing Task description. For a changed finding, update only the
approved Priority and triage labels when needed, then add one normal-visibility
Jira comment containing only changed fields:

```markdown
## [Update]

Finding ID: <finding-id>
Update fingerprint: <SHA-256>
Revision: <current revision>
Report path: <report path>
Previous status: <old status>
Current status: <new status>

### Changed fields

- <field>
Previous: <old value>
Current: <new value>
```

Treat status, CodeQL security severity, mapped priority, confidence, locations,
evidence, counterevidence, proof gaps, recommended next step, fix handoff, and
PR association as substantive. A revision or regenerated report alone must not
create a comment.

Store the last verified snapshot in the receipt. On rerun, compare the current
finding to that snapshot and read the live Task and comments. Stop instead of
guessing when the receipt and live Jira history disagree.

Run:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/jira_writeback.py plan \
  --triage security-results/triage/codeql/<branch-slug>/current.json \
  --report security-results/triage/codeql/<branch-slug>/report.html \
  --repository <owner/repo> \
  --branch <branch> \
  --site https://jesssg50mail.atlassian.net \
  --project KAN \
  --issue-type Task \
  --audience-approved \
  --output security-results/triage/codeql/<branch-slug>/jira-tracking/preview.html
```

Add `--pr-url <URL>` only when the user supplied one.

## Phase 5: Preview and pause

The self-contained `preview.html` is the only plan artifact. It embeds the
canonical payload without credentials and filters by verdict and Jira action.
Show its path, Jira identity and destination, finding and technical-batch
counts, action counts, and one approval token.

Require the user to review every exact Task description, Priority, label edit,
and update comment in the HTML. One token covers the complete manifest even
when execution uses several technical groups of at most 25. Any change to the
payload, triage/report hashes, PR, credentials identity, Jira metadata,
destination, duplicate results, or live state invalidates approval.

## Phase 6: Apply, verify, and receipt

Only after the user approves the exact token, run:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/jira_writeback.py apply \
  --preview security-results/triage/codeql/<branch-slug>/jira-tracking/preview.html \
  --approval-token <token>
```

Immediately before writing, rebuild the plan and require an exact match. Process
findings serially and stop on the first failed or uncertain result. Never retry
a create that may have succeeded. Read back every created/reused Task and every
added comment before reporting success.

Write receipts under:

```text
security-results/triage/codeql/<branch-slug>/jira-tracking/receipts/current.json
security-results/triage/codeql/<branch-slug>/jira-tracking/receipts/history/<timestamp>.json
```

Require one verified Jira key and URL per persisted Finding ID. Do not report
complete coverage when any result is missing, blocked, failed, uncertain, or
unprocessed. Preserve existing `github-tracking` artifacts as historical data;
never rewrite or delete them.

## Hard rules

- Never expose or persist Jira credentials.
- Never change Jira before one exact consolidated HTML preview and approval.
- Never create more than one Jira Task per finding.
- Never omit any persisted finding from a complete run.
- Never infer a PR, assignee, priority, Jira field, or destination.
- Never overwrite an existing Jira description or add unchanged-field comments.
- Never transition, resolve, delete, link, attach, or log work on Jira Tasks.
- Never mutate GitHub alerts or create GitHub tracking issues.
- Never continue after branch, revision, artifact, identity, permission,
  metadata, duplicate, or destination drift.

## Final output

Report the exact branch ref and revision, intake and triage paths, report path
and hash, optional verified PR, verdict counts, Jira identity/site/project/type,
priority mappings, preview/token, action counts, receipt paths, and every
verified Jira key and URL. Clearly identify pending approval, partial or
uncertain results, and the accepted absence of Jira backlinks on GitHub alerts.
