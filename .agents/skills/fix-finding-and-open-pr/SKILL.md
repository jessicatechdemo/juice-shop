---
name: fix-finding-and-open-pr
description: Fix and verify one security finding with Codex Security, show red-to-green regression evidence, run the repository's existing focused unit tests, and request explicit permission before committing, pushing, or opening a pull request. Use when a user wants a validated security patch carried through local proof and optionally published as a PR, but does not want publication before reviewing the evidence and proposed PR scope.
---

# Fix Finding and Open PR

Take one supplied security finding through four gates: fix, regression proof,
repository testing, and approval-gated publication. A later passing gate never
compensates for an earlier failure.

## Required Skills

- Use `$codex-security:fix-finding` for finding validation, patching, and ordered
  verification. Read and follow that skill completely before changing source.
- After the user approves publication, use `$github:yeet` to confirm scope,
  commit intentionally, push, and open a draft PR. Read and follow that skill
  before performing publication actions.
- If either required skill is unavailable, stop and report the missing dependency.

## Gate 1: Fix and Verify Locally

1. Read repository instructions and preserve unrelated user changes.
2. Resolve the finding identifier, exact vulnerable path, source revision, and
   current patch state. Ask only when a material ambiguity cannot be discovered.
3. Run the complete `$codex-security:fix-finding` workflow.
4. Continue only when its outcome is `fixed` and every required verification gate
   passes. For `blocked` or `no_change`, report the result and do not ask to create
   a PR.

## Gate 2: Prove the Regression Test

Use the focused regression test already added or modified for the fix. Do not
replace it with a simplified harness that bypasses the vulnerable boundary.

Establish all of the following:

- **Red evidence:** The regression test fails against the exact vulnerable baseline
  for the intended security assertion.
- **Green evidence:** The same test command passes against the patched source with
  exit code `0`.
- **Sensitivity:** Explain which malicious input and assertion distinguish the
  vulnerable and patched states.
- **Legitimate control:** Show that supported behavior through the same boundary
  remains intact.
- **Nearby variant:** Exercise at least one alternate malicious input class when
  practical, as required by the fix-finding bypass review.

Prefer pre-fix output already captured by `$codex-security:fix-finding`. If the
patch was already applied and red evidence is missing, reproduce the baseline only
in an isolated temporary checkout or copy at the pinned vulnerable revision and
overlay the existing regression test there. Never stash, reset, reverse-apply, or
otherwise mutate the user's primary working tree merely to obtain red evidence.

Treat absent red evidence as an explicit proof gap. Do not describe code inspection
alone as regression proof.

## Gate 3: Run Existing Focused Tests

1. Identify the owning unit-test file and exact relevant test name from repository
   conventions, the finding, and the patch diff.
2. Run the repository-supported command for that existing focused test. Do not add
   a second test solely for this orchestration gate.
3. Run any integration test required to prove the real vulnerable boundary, plus
   applicable build, type, lint, formatting, safety-net, and owning-package checks
   required by repository instructions and `$codex-security:fix-finding`.
4. Record the exact command, runtime, exit code, pass/fail counts, and any skipped
   checks. A test process with exit code other than `0` is not a pass even if the
   target assertion printed as successful; rerun cleanly in a supported environment
   or return `blocked`.
5. Inspect the final scoped diff and `git status`. Keep unrelated dirty files out of
   the candidate patch and never stage with `git add .` or `git add -A`.

## Show the Evidence

Before requesting publication permission, show the user a concise verification
report containing:

- finding identifier and vulnerable source-to-sink path;
- security invariant and legitimate behavior preserved;
- patch files and regression-test files;
- regression-test name, malicious input, and decisive assertion;
- red command, failing assertion, and nonzero exit code;
- green command, pass count, and exit code `0`;
- focused unit/integration and repository-check results;
- bypass variants exercised;
- skipped checks, uncertainty, or environmental limitations.

Conclude explicitly whether the original issue no longer reproduces and why the
test would fail if the security change were removed.

## Gate 4: Preview and Request Permission

Unlock this gate only when Gates 1–3 pass without a relevant unknown. Prepare an
exact publication preview containing:

- base and head branches;
- exact files to stage;
- proposed signed-off commit message when the repository requires DCO;
- proposed PR title and short description;
- whether the PR will be draft;
- checks already run and any CI checks expected after push.

Then ask one direct question:

> May I stage only these files, create the signed-off commit, push the branch, and
> open the proposed draft PR?

End the turn and wait. Silence, earlier authorization to fix, or a request to prepare
the patch is not publication approval. Before explicit approval, do not stage,
commit, push, open a PR, modify GitHub alert state, or perform another external write.

## Publish Only After Approval

After an explicit yes:

1. Recheck that the branch, intended files, diff, and verification results still
   match the preview. If they changed materially, show a new preview and ask again.
2. Follow `$github:yeet`, repository contribution rules, and DCO requirements.
3. Stage only the previewed files, create the intentional commit, push, and open the
   draft PR.
4. Read back the commit and PR metadata. Report the PR URL, staged files, commit,
   base/head branches, and CI status or pending checks.

Do not manually dismiss or close the security alert. Let the repository's code
scanning workflow evaluate the pushed fix unless the user separately authorizes a
supported alert-state workflow.

## Terminal Outcomes

- `fixed_verified_waiting_for_approval`: All local gates passed and the exact PR
  preview is awaiting the user's decision.
- `published`: The approved draft PR was created and read back successfully.
- `blocked`: A relevant proof, test, environment, repository, or publication gate
  failed. State the failing gate and the smallest next action needed.
- `no_change`: The underlying fix workflow proved the current code was already safe;
  do not manufacture a patch or request a PR.
