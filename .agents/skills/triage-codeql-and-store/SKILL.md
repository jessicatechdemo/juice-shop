---
name: triage-codeql-and-store
description: Import open GitHub CodeQL code-scanning alerts, triage them against the current repository, persist the exact triage-finding/v0 result, and submit approved dismissal requests for eligible `not_actionable` findings without directly dismissing alerts. Use when the user explicitly requests end-to-end CodeQL triage, durable local storage, and reviewer-gated GitHub writeback. Always preview GitHub mutations and obtain explicit approval before applying them. Never request dismissal of `confirmed` or `needs_review` alerts.
---

# Triage CodeQL, Store, and Request GitHub Dismissal

Run one end-to-end workflow with a mandatory approval pause before GitHub
writeback:

1. triage CodeQL alerts read-only
2. persist and verify the exact triage contract
3. prepare and preview GitHub dismissal requests
4. pause for explicit user approval
5. submit approved requests and verify pending state by readback

## Inputs

Resolve:

- GitHub repository as `owner/repo`
- target branch or ref
- canonical local repository and current revision
- output root, defaulting to `security-results/triage/codeql`

If the repository or branch cannot be resolved, ask for it. Do not guess a
different repository or revision.

## Phase 1: Read-only triage

1. Invoke `$codex-security:triage-finding` for the repository's open GitHub
   code-scanning alerts on the requested branch.
2. Follow its GitHub REST intake, static-only assessment, security policy gate,
   verdict rules, ranking rules, and `triage-finding/v0` output contract.
3. Preserve alert number, alert URL, rule ID, tool, ref, commit SHA, and
   instance locations in each input's identifiers or references.
4. Produce exactly one result per imported alert. Do not merge or drop
   duplicate-looking inputs.
5. Retain the exact complete JSON payload passed to the triage results app.
   Do not reconstruct it from the Markdown summary.
6. Record the successfully imported alert count as `expected_count`.

Do not edit files, run code, change revisions, or mutate GitHub during this
phase. Stop if intake or triage is incomplete.

## Phase 2: Persist and verify

After read-only triage completes, materialize the exact retained payload as a
temporary input outside the repository and run:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/persist_triage.py \
  --input <temporary-json-path> \
  --branch <branch> \
  --expected-count <imported-alert-count>
```

The script writes and reads back:

```text
security-results/triage/codeql/<branch-slug>/current.json
security-results/triage/codeql/<branch-slug>/history/<timestamp>-<revision>.json
```

Stop if persistence validation fails. Use `current.json` as immutable input to
the following plan; do not add GitHub state to the triage contract.

## Phase 3: Plan GitHub status updates

Apply this fixed mapping:

- `confirmed`: keep the CodeQL alert open; do not issue a PATCH request.
- `needs_review`: keep the CodeQL alert open; do not issue a PATCH request.
- `not_actionable`: make the alert eligible for an approved dismissal request.

Generate a dismissal-request plan so an independent GitHub reviewer controls
the final alert status:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/codeql_writeback.py plan \
  --triage security-results/triage/codeql/<branch-slug>/current.json \
  --repository <owner/repo> \
  --branch <branch> \
  --write-mode dismissal_request \
  --output security-results/triage/codeql/<branch-slug>/github-writeback/plan.json
```

Every finding remains in the plan. `confirmed` and `needs_review` use
`keep_open`; `not_actionable` begins as `pending`. Direct dismissal is disabled.

## Phase 4: Select justified dismissal requests

Select a requested GitHub dismissal reason from evidence, not verdict alone:

- `false positive`: the scanner's technical claim is incorrect.
- `used in tests`: the finding is limited to test or fixture code.
- `won't fix`: the behavior is valid but explicitly accepted, including a
  documented intentional Juice Shop training vulnerability.

Do not infer accepted risk merely because this repository is Juice Shop.
Require repository evidence or an explicit maintainer decision for
`won't fix`.

Select candidates locally:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/codeql_writeback.py select \
  --plan <plan-path> \
  --alert <alert-number> \
  --reason "won't fix"
```

Repeat `--alert` for alerts sharing the same reason. Leave uncertain candidates
as `pending`.

## Phase 5: Preview and pause

Run:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/codeql_writeback.py preview \
  --plan <plan-path>
```

Show the complete preview: repository, branch, revision, alert URLs, exact
PATCH bodies including `create_request: true`, keep-open count, pending count,
and approval token.

Pause and ask the user to approve the exact alert numbers and approval token.
Do not treat the original request to run this skill as approval of the rendered
writeback plan. Approval from a different plan or token is invalid.

## Phase 6: Apply and verify

Only after explicit approval, run:

```bash
python3 .agents/skills/triage-codeql-and-store/scripts/codeql_writeback.py apply \
  --plan <plan-path> \
  --approval-token <token-from-preview>
```

The script performs read-only preflight for all selected alerts before its
first write. It verifies that delegated dismissal requests are enabled and
readable, checks alert identity and open state, and confirms an instance on the
requested branch. It submits requests only for selected `not_actionable`
alerts. For each submission, it reads back both the alert and the dismissal
request and requires:

- the CodeQL alert remains `open`
- the dismissal request has status `open`
- the requested reason and comment match the approved plan

An identical existing open request is treated as `already_pending`. A
conflicting request or unverifiable request stops the workflow. Receipts are
written to:

```text
security-results/triage/codeql/<branch-slug>/github-writeback/receipts/current.json
security-results/triage/codeql/<branch-slug>/github-writeback/receipts/history/<timestamp>.json
```

If preflight fails, make no GitHub changes. If submission or readback fails,
stop and report the partial receipt rather than retrying blindly.

## Hard rules

- Never update GitHub before the explicit approval pause.
- Never request dismissal of `confirmed` or `needs_review` findings.
- Never use direct dismissal; every PATCH must include `create_request: true`.
- Never approve or deny a dismissal request in this workflow.
- Never select a dismissal reason without supporting evidence.
- Never upload SARIF or create GitHub issues in this workflow.
- Never expose GitHub tokens in commands, output, plans, or receipts.
- Never bypass the approval token, preflight, or readback checks.

## Final output

Report local artifact paths and counts before the approval pause. After an
approved writeback, report every alert's before/after state, requested reason,
request status, requester, timestamp, and receipt paths. State clearly that
the submitted requests remain pending until a GitHub reviewer approves or
denies them, and that all affected alerts remain open while pending.
