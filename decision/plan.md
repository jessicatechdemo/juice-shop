# CodeQL and Secret-Scanning PR Gate Plan

Status: Proposed  
Last verified: 2026-08-04

## Decision

CodeQL will continue to analyze the complete checked-out branch snapshot. PR security triage, merge gating, and Jira automation will use only CodeQL alerts associated with the pull request, rather than every alert present on the branch.

Secret scanning will remain repository-wide because it scans Git history and all branches. If Jira tickets are required only for secrets introduced by a pull request, a separate correlation step will compare each secret location with the PR commits or changed files.

## Verified Current Behavior

For `feature01-newPages` and PR #4 on 2026-08-04:

| Scope | Open CodeQL alerts |
| --- | ---: |
| Complete branch | 58 |
| Associated with PR #4 | 1 |

The one PR-associated alert was medium severity. The existing high and critical branch alerts were not associated with PR #4 and therefore should not be treated as findings introduced by that PR.

The current workflow already separates the scopes:

- The CodeQL job checks out and analyzes the repository snapshot.
- The PR triage job requests CodeQL alerts using `pr=$PR_NUMBER`.
- Codex and Jira processing therefore receive PR-associated CodeQL alerts rather than the complete branch alert set.

## CodeQL Processing Plan

1. Run CodeQL against the complete PR branch snapshot.
2. Wait for CodeQL analysis to finish before starting Codex triage.
3. Retrieve open CodeQL alerts with all of these filters:
   - Repository: the current repository
   - Pull request: the current PR number
   - Tool: CodeQL
   - State: open
4. Triage only the alerts returned by the PR-filtered request.
5. Apply the agreed decision matrix to those alerts:

   | Codex result | Action | Jira priority |
   | --- | --- | --- |
   | Confirmed high/critical | Block; no Jira required | N/A |
   | Needs-review high/critical | Block pending review; allow an authorized team-lead/reviewer bypass | Highest if a Jira record is required |
   | Not-actionable high/critical | Do not block; create Jira for audit | High |
   | Confirmed medium/low | Do not block; create Jira | Medium |
   | Needs-review medium/low | Do not block; create backlog Jira | Low |
   | Not-actionable medium/low | Do not block; create and close Jira, and record the CodeQL dismissal | Closed |

6. Publish the gate as a GitHub status check suitable for a branch protection rule or ruleset:
   - Failure: confirmed high/critical or needs-review high/critical.
   - Success: no blocking PR-associated findings remain.
   - Bypass: performed through the GitHub ruleset by an explicitly authorized team lead or reviewer.
7. Keep the full branch alert list available for baseline remediation, but do not use it to decide whether the current PR introduced a blocking finding.

## Secret-Scanning Plan

Secret-scanning alerts shown in the repository Security area are expected to include findings outside the PR diff. They must not be interpreted as PR-only results.

For PR-specific secret handling:

1. Keep GitHub secret scanning and push protection enabled.
2. Treat push-protection failures or secrets detected in the PR's changed content as blocking.
3. If Jira automation is required, retrieve only alert metadata needed for correlation; never log or copy the secret value.
4. Correlate each alert location with the PR using its commit and file path:
   - If the location belongs to a PR commit or changed file, process it as a new PR finding.
   - Otherwise, treat it as an existing repository or history finding and handle it through the baseline-remediation process.
5. Rotate or revoke genuine exposed credentials even when they predate the PR.
6. Use secret-scanning path exclusions only for reviewed test fixtures, examples, or known fake values. Because this repository intentionally contains insecure training material, every exclusion must be narrow and explicitly approved.

## Automatic Jira Closure When a PR Closes

GitHub is the source of truth for the PR lifecycle. When GitHub reports that a PR was closed, an automated reconciliation process will find the Jira issues associated with that PR and transition them according to whether the PR was merged.

The preferred flow is:

```text
GitHub PR closed
        ↓
Check whether the PR was merged
        ↓
Closed without merge ──→ Close Jira as Abandoned
        │
        └── Merged ─────→ Wait for the default-branch CodeQL scan
```

### Trigger

Add a separate, trusted GitHub Actions workflow for PR lifecycle reconciliation:

```yaml
on:
  pull_request_target:
    types: [closed, reopened]
```

The existing general `pull_request` trigger does not receive `closed` events by default. The reconciliation workflow needs Jira credentials, so it may use `pull_request_target` only under these constraints:

- Never check out the PR branch or PR head SHA.
- Never execute code, scripts, actions, or configuration supplied by the PR.
- Run only trusted automation from the default branch.
- Give the Jira credential only the permissions required to search, comment on, and transition the relevant issues.

Use `github.event.pull_request.merged` to distinguish a PR closed without merging from a merged PR.

### Jira Correlation

When a Jira issue is created, store these non-sensitive fields so that it can be found reliably later:

- GitHub repository
- GitHub PR number
- GitHub PR URL
- CodeQL alert number
- PR head SHA
- Source, for example `Codex-CodeQL`

Use a stable idempotency key based on repository, scanner, alert number, and PR number. Do not depend only on a Jira key appearing in the PR title, branch name, or commit message.

An example Jira search is:

```text
project = SEC
AND "GitHub Repository" = "jessicatechdemo/juice-shop"
AND "GitHub PR Number" = "4"
AND statusCategory != Done
```

### Lifecycle Decisions

| GitHub event | Finding state | Jira action | CodeQL action |
| --- | --- | --- | --- |
| PR closed without merge | Relevant only to the abandoned PR | Close with resolution `Abandoned - PR closed without merge` | Do not dismiss solely because the PR closed |
| PR closed without merge | Human reviewer confirms false positive or not applicable | Close with the matching resolution | Dismiss only after explicit reviewer approval |
| PR merged | Finding absent from the completed default-branch scan | Close with resolution `Fixed` | Allow the scan to mark the alert fixed |
| PR merged | Finding remains on the default branch | Keep open for remediation | Keep the alert open |
| PR merged using bypass | Blocking finding remains | Keep or create a `Highest` priority exception/remediation Jira | Keep the alert open |
| PR reopened | Finding still applies | Reopen the same Jira issue | Re-run the security gate |
| Duplicate Jira | Canonical issue already tracks the finding | Close as `Duplicate` and link the canonical issue | Do not dismiss automatically |

A PR being closed does not prove that a CodeQL finding is invalid. `Abandoned` records that the proposed change was not merged; `False Positive`, `Not Applicable`, `Used in Tests`, or `Duplicate` records a decision about the finding itself.

If a confirmed or needs-review high/critical finding is merged through an authorized bypass, Jira becomes mandatory even though a successfully blocked confirmed high/critical finding normally requires no Jira ticket. The bypass ticket must record the actor, justification, approval, finding, remediation owner, and deadline.

### Jira Audit Comment

Before automatically closing a Jira issue, add an audit comment containing:

- The PR number and URL
- Whether the PR was closed without merge or merged
- The PR head SHA
- The CodeQL alert number
- The previous Codex verdict
- The resolution reason
- The automation actor and timestamp

No detected secret value may be included in the comment.

### Native Jira Alternative

If GitHub Cloud is connected to Jira and Jira recognizes the issue as linked development work, Jira Automation can use the `Pull request declined`, `Pull request merged`, and `Pull request reopened` triggers. The rule should apply the same lifecycle table above.

The GitHub reconciliation workflow remains the preferred option for scanner-generated Jira issues because those issues are created after the PR and their Jira keys might not appear in the PR title, branch name, or commit messages.

## Repository Changes

The following work can be implemented in this repository:

- Maintain the PR-filtered CodeQL API request in the workflow.
- Implement the Codex verdict-to-gate decision matrix.
- Add idempotent Jira creation and update logic.
- Add PR `closed` and `reopened` reconciliation using trusted default-branch automation.
- Add secret-alert-to-PR correlation without exposing secret values.
- Publish a stable, uniquely named security-gate check.
- Store non-sensitive audit metadata such as alert number, rule, severity, verdict, Jira key, timestamps, and PR commit SHA.
- Add tests for filtering, severity mapping, duplicate prevention, and gate outcomes.

## Configuration Outside the Repository

The following requires GitHub or Jira administration:

- Configure a GitHub branch ruleset for `master` that requires the security-gate check.
- Configure the ruleset bypass list for authorized team leads or reviewers.
- Decide whether bypasses require a reason and ensure bypass activity is retained in the GitHub audit log.
- Enable and configure GitHub secret scanning and push protection.
- Create Jira credentials with minimum necessary permissions and store them as GitHub Actions secrets.
- Configure Jira project fields, priorities, workflow states, resolution values, and automation permissions.
- Add Jira fields for GitHub repository, PR number, PR URL, head SHA, scanner source, and scanner alert number.
- Add Jira transitions and resolutions for `Abandoned`, `Fixed`, `False Positive`, `Not Applicable`, `Used in Tests`, and `Duplicate`.
- Ensure Jira webhooks or workflow automation can trigger an immediate gate re-evaluation if Jira decisions are allowed to affect a pending result.

## Acceptance Criteria

- A CodeQL high/critical alert that exists on the branch but is not associated with the PR does not block that PR and does not create a PR Jira ticket.
- A PR-associated, Codex-confirmed high/critical CodeQL alert blocks merging without creating Jira.
- A PR-associated, needs-review high/critical alert blocks until it is resolved or an authorized reviewer uses GitHub bypass.
- A PR-associated finding that meets a Jira condition creates no more than one Jira issue across reruns.
- Closing a PR without merging automatically closes its applicable Jira issues as `Abandoned - PR closed without merge`.
- Merging a PR does not close its Jira issues until the completed default-branch scan confirms that the findings are absent.
- Reopening a PR reopens the same applicable Jira issues rather than creating duplicates.
- Merging a blocking high/critical finding through bypass creates or retains a `Highest` priority Jira exception record.
- Closing or updating a non-blocking Jira issue does not incorrectly unblock an independent confirmed high/critical finding.
- Secret alerts outside the PR are visible to the baseline-remediation process but do not appear as newly introduced PR findings.
- No workflow output, artifact, Jira issue, or audit record contains a detected secret value.

## Operational Guidance

Use the PR checks, annotations, or the CodeQL API `pr=<number>` filter when evaluating a pull request. The GitHub **View all branch alerts** page intentionally shows the complete analyzed branch and is not the correct input for PR gating.

References:

- [GitHub: Code scanning alerts](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning-alerts)
- [GitHub: Triaging code scanning alerts in pull requests](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-code-scanning-alerts/triage-alerts-in-pull-requests)
- [GitHub: About secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning)
- [GitHub: Events that trigger workflows](https://docs.github.com/en/enterprise-cloud@latest/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [Atlassian: Jira automation triggers](https://support.atlassian.com/cloud-automation/docs/jira-automation-triggers/)
