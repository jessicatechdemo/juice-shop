---
name: clean-reset-codeql-and-retriage
description: Reopen CodeQL alerts changed by an audited writeback receipt, delete the single final CodeQL analysis for a branch, rerun the matching GitHub Actions workflow, verify the replacement analysis and open alerts, and invoke fresh Codex triage. Use when a user explicitly requests a destructive clean reset of GitHub CodeQL results and alert state for one branch. Always generate an exact mutation preview and obtain approval for its token before reopening alerts, deleting analysis history, or rerunning GitHub Actions.
---

# Clean Reset CodeQL and Retriage

Perform an auditable branch reset in this fixed order:

1. derive alert scope from a completed writeback receipt
2. validate every affected alert and the final branch analysis read-only
3. preview every GitHub mutation and pause for approval
4. reopen alerts, delete the analysis, and request the workflow rerun
5. wait for CodeQL and verify the replacement analysis and open alerts
6. invoke `$triage-codeql-and-store` to create fresh local triage

## Inputs

Resolve the GitHub `owner/repo`, branch, CodeQL workflow filename, and original
writeback receipt. Default the workflow to `codeql-analysis.yml`. Store reset
artifacts under:

```text
security-results/triage/codeql/<branch-slug>/clean-reset/
```

Require the receipt to be complete and to match the repository and branch.
Reset only alerts whose receipt outcome is `dismissed`. Require exactly one
CodeQL analysis for the branch; stop instead of guessing across configurations.

## Plan read-only

Run:

```bash
python3 .agents/skills/clean-reset-codeql-and-retriage/scripts/codeql_clean_reset.py plan \
  --receipt security-results/triage/codeql/<branch-slug>/github-writeback/receipts/current.json \
  --repository <owner/repo> \
  --branch <branch> \
  --workflow codeql-analysis.yml \
  --output security-results/triage/codeql/<branch-slug>/clean-reset/plan.json
```

The plan command performs no writes. It accepts receipt-scoped alerts that are
still dismissed with the exact reason and comment or already open with cleared
dismissal metadata. Record already-open alerts without planning redundant
PATCHes. Require the branch's sole analysis to be deletable and bind a completed
workflow run for the analysis commit.

## Preview and pause

Run:

```bash
python3 .agents/skills/clean-reset-codeql-and-retriage/scripts/codeql_clean_reset.py preview \
  --plan security-results/triage/codeql/<branch-slug>/clean-reset/plan.json
```

Show the entire preview, including already-open alerts, all exact PATCH bodies,
the analysis ID and `confirm_delete=true` endpoint, workflow run ID, commit SHA,
and approval token. Warn that deleting the final analysis may remove historical
CodeQL alert data.

Pause for explicit approval of the exact token. The request to invoke this
skill is not approval of the rendered mutations. A changed plan invalidates the
token.

## Apply approved reset

After approval only, run:

```bash
python3 .agents/skills/clean-reset-codeql-and-retriage/scripts/codeql_clean_reset.py apply \
  --plan security-results/triage/codeql/<branch-slug>/clean-reset/plan.json \
  --approval-token <approved-token>
```

The script repeats all preflight checks before its first write. It then reopens
and reads back each alert, deletes the exact final analysis with
`confirm_delete=true`, and reruns the bound workflow. It stores current and
immutable historical receipts under `clean-reset/receipts/`. On partial failure,
stop and report the receipt; do not retry blindly or substitute another analysis
or workflow run.

## Wait and verify

Use the run ID from the receipt:

```bash
gh run watch <run-id> --repo <owner/repo> --exit-status
```

After a successful run, verify:

```bash
python3 .agents/skills/clean-reset-codeql-and-retriage/scripts/codeql_clean_reset.py verify \
  --plan security-results/triage/codeql/<branch-slug>/clean-reset/plan.json
```

Require a successful workflow rerun, a replacement CodeQL analysis for the same
commit with a different analysis ID, and every receipt-scoped alert to be open.
Store verification under `clean-reset/verification/`.

## Retriage

Invoke `$triage-codeql-and-store` against the same repository and branch only
after verification succeeds. This replaces branch-specific `current.json` and
appends history. Stop at that skill's independent approval preview before any
dismissal request writeback.

## Hard rules

- Never delete analysis history before the token-bound approval pause.
- Never delete more than the single planned branch analysis.
- Never use alert search results as the mutation source; use the audited receipt.
- Never delete local triage history or original writeback receipts.
- Never treat a successful workflow rerun as proof that all alerts are open;
  run verification.
- Never approve or submit dismissal requests during the clean-reset phase.
- Never expose GitHub credentials in plans, commands, receipts, or output.

## Final output

Before approval, report the plan path, reopen count, analysis ID, workflow run
ID, and token. After completion, report receipt and verification paths, old and
new analysis IDs, workflow URL, open-alert count, and fresh triage paths.
