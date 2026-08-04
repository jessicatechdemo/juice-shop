# Combined CodeQL and Codex SAST Gate Plan

Status: Implemented locally; GitHub ruleset activation pending  
Last verified: 2026-08-04

## Summary

Keep CodeQL scanning enabled and integrate Codex as a triage layer for CodeQL alerts associated with the current pull request. Replace the standalone CodeQL high-severity merge rule with one combined required status check named `Codex + CodeQL SAST gate`.

The separate Codex Security code-scanning ruleset remains disabled. Codex does not upload a second set of code-scanning alerts in this design; it evaluates the CodeQL findings and supplies the verdict used by the combined gate.

## SARIF Role

CodeQL produces SARIF and uploads it to GitHub Code Scanning. The combined gate does not download or parse the raw SARIF file again. It retrieves the PR-associated CodeQL alerts produced from that SARIF through GitHub's Code Scanning API, then evaluates those alerts against the Codex triage output.

Every validated Codex finding retains `source_type: "sarif"`. The gate evaluator rejects a triage record with another source type, preserving the finding's SARIF lineage while using GitHub's normalized alert metadata as the authoritative source for CodeQL security severity.

## Processing Flow

1. Run CodeQL against the complete pull request branch snapshot.
2. Wait for CodeQL analysis to complete.
3. Retrieve only open CodeQL alerts associated with the current pull request.
4. Bind the alert set to the pull request number, base revision, head revision, repository, and branch.
5. Run Codex triage against every alert in that bounded input.
6. Validate the Codex output against the original CodeQL intake, including alert number, revision, ref, and security severity.
7. Evaluate the combined gate and publish the stable `Codex + CodeQL SAST gate` check.

CodeQL's `security_severity_level` is the authoritative severity. The gate must not infer severity from the Codex verdict, confidence, explanation, or generic CodeQL levels such as `error`, `warning`, or `note`.

## Gate Decision Matrix

| CodeQL security severity | Codex verdict | Gate result |
| --- | --- | --- |
| Critical/high | `confirmed` | Block |
| Critical/high | `needs_review` | Block pending review |
| Critical/high | `not_actionable` | Pass |
| Medium/low/none | Any verdict | Pass |
| No PR-associated alerts | N/A | Pass |
| Triage or evaluation unavailable | N/A | Indeterminate warning; pass |

Codex confidence does not affect the decision. A high/critical `needs_review` result blocks because it has not yet been shown to be non-actionable.

## Gate Evaluator Contract

Add a deterministic evaluator that consumes the validated CodeQL intake and Codex triage JSON. It will:

- Join each triage result to its CodeQL alert number.
- Read severity from the original CodeQL intake.
- Read the verdict from the validated Codex triage result.
- Return `block` when at least one high/critical alert is `confirmed` or `needs_review`.
- Return `pass` when evaluation completes without a blocking alert.
- Return `indeterminate` when required inputs are unavailable, malformed, or cannot be evaluated.
- Include the decision, blocking count, and blocking alert numbers, severities, and verdicts in its machine-readable output and workflow summary.

The workflow will treat `block` as a failed required check. It will treat `pass` as successful and, by explicit policy choice, treat `indeterminate` as a successful check with a prominent warning.

## Workflow Integration

Add a final gate job to the existing CodeQL workflow with these properties:

- Use `always()` after PR intake, Codex triage, and triage packaging so the job can translate upstream results into a final gate decision.
- Download and evaluate the validated handoff when PR-associated alerts exist and packaging succeeded.
- Pass immediately when the PR-associated CodeQL alert count is zero.
- Fail only when the evaluator returns `block`.
- Emit an indeterminate warning and pass when CodeQL, Codex triage, validation, artifact retrieval, or evaluation is unavailable.
- Publish the same job/check name on every pull request so branch protection never waits for a missing check.

Codex evaluation remains limited to same-repository, non-bot pull requests. Fork pull requests cannot receive repository secrets such as `OPENAI_API_KEY`, and bot-authored pull requests are already excluded by the workflow. For those excluded pull requests, the final check reports success with a `not applicable` explanation and does not attempt Codex triage.

## Merge Protection

Disable or replace the direct CodeQL high-severity code-scanning rule. Leaving it active would continue to block every high/critical CodeQL alert regardless of the Codex verdict, defeating the combined decision matrix.

Configure the `master` branch ruleset to require the `Codex + CodeQL SAST gate` status check instead. Keep CodeQL analysis and alert publication enabled. Keep the separate Codex Security code-scanning ruleset disabled because Codex is providing triage rather than a separate SARIF/code-scanning result.

The JSON files under `.github/rulesets/` document the intended configuration but are not automatically deployed by the repository. A GitHub administrator must apply the corresponding ruleset change in repository settings or through the GitHub API.

## Test Plan

Add deterministic unit tests for the evaluator covering:

- Confirmed critical and high alerts block.
- Needs-review critical and high alerts block.
- Not-actionable critical and high alerts pass.
- All verdicts at medium and low severity pass.
- Alerts without a CodeQL security severity pass.
- Multiple findings block when any one finding meets the blocking condition.
- An empty PR alert set passes.
- Alert-number, severity, revision, or ref mismatches are rejected by validation before evaluation.
- Missing or malformed evaluator inputs produce `indeterminate` rather than an incorrect policy result.

Validate the workflow scenarios covering:

- A same-repository, non-bot pull request with a blocking finding fails the required check.
- A same-repository, non-bot pull request without a blocking finding passes.
- A triage or evaluation failure produces a visible warning but passes under the fail-open policy.
- Fork and bot-authored pull requests receive a successful `not applicable` check without accessing `OPENAI_API_KEY`.
- Branch-wide CodeQL alerts not associated with the pull request do not affect the gate.
- The final check name remains exactly `Codex + CodeQL SAST gate` for branch protection.

Run the evaluator unit tests, workflow syntax validation, and `npm run lint` after implementation. Preserve all existing uncommitted workflow and triage changes.

## Acceptance Criteria

- CodeQL scanning remains enabled.
- Codex triages only the pull request's associated CodeQL alerts.
- A confirmed or needs-review CodeQL high/critical finding blocks the pull request.
- A not-actionable CodeQL high/critical finding does not block the pull request.
- Medium, low, and unclassified CodeQL findings do not block the pull request.
- Infrastructure and triage failures fail open with a visible warning.
- The direct CodeQL severity rule no longer independently blocks the pull request.
- The separate Codex Security code-scanning ruleset remains disabled.
- `master` requires the stable combined status check.

## Assumptions

- The current PR-filtered CodeQL intake and validated Codex triage handoff remain the foundation of the implementation.
- `needs_review` high/critical findings block pending human review.
- Fail-open behavior for triage and evaluation failures is an explicit policy decision.
- Jira lifecycle automation and secret-scanning behavior remain covered by `decision/plan.md` and are outside this plan.

## References

- [GitHub: Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub: About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub: Using secrets in GitHub Actions](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets)
