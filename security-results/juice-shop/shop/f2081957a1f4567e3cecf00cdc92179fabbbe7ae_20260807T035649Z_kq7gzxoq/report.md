# Security Review: juice-shop

## Scope

Security diff review of refs/heads/master at 6b6637bc45042c25aef5b31daac0033043ddd5d1 against refs/heads/add-vul-back at f2081957a1f4567e3cecf00cdc92179fabbbe7ae.

- Scan mode: branch_diff
- Target kind: git_diff
- Target ID: target_sha256_942e4454c5a63661aa7378d57768341491657f4df9014a8cac1a157dd6f8ba9e
- Revision range: 6b6637bc45042c25aef5b31daac0033043ddd5d1...f2081957a1f4567e3cecf00cdc92179fabbbe7ae
- Snapshot digest: codex-security-snapshot/v1:sha256:efb7194dded32ab8de41ac0dea3259308f8b817e269da6e9d0b6c8a4cfaec63f
- Inventory strategy: diff
- Included paths: .
- Excluded paths: none
- Runtime or test status: Application tests and runtime reproduction were not run, as required by the user.
- Artifacts reviewed: routes/search.ts, .github/workflows/ci.yml, .github/workflows/codeql-scheduled.yml, server.ts, lib/utils.ts, SECURITY.md
- Scan context: The scan reviewed every security-relevant changed source or executable workflow file. The repository threat model was derived from repository SECURITY.md guidance and preserved as a scan artifact.

Limitations and exclusions:
- No application tests or dynamic reproduction were permitted.
- No live GitHub repository settings, Jira state, GitHub issues, or deployment state were queried.
- Only security-relevant changes between the selected refs were assessed; unchanged intentional vulnerabilities were not reported as diff findings.
- Excluded AGENTS.md: Documentation-only change with no executable security behavior.
- Excluded unchanged code outside the selected diff: This is a diff scan; unchanged repository vulnerabilities, including the intentional SQL interpolation in routes/search.ts, were not attributed to the target change.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 1 |
| Severity mix | low: 1 |
| Confidence mix | high: 1 |
| Coverage | complete |
| Validation mode | Static immutable-revision diff and source/control/sink analysis. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

OWASP Juice Shop is a publicly reachable Node.js/Express training application that intentionally contains vulnerabilities. Public routes, attacker-controlled query parameters, runtime availability, and privileged CI workflows are in scope; challenge intentionality does not by itself exclude a diff-introduced regression.

### Assets

- Application availability
- Application data and database integrity
- User credentials and sessions
- CI credentials and repository integrity

### Trust Boundaries

- Unauthenticated internet client to Express HTTP route
- Parsed HTTP query values to route-handler type assumptions
- Repository content to privileged CI workflow execution
- Application route to database query execution

### Attacker Capabilities

- Send unauthenticated HTTP requests with crafted and repeated query parameters
- Supply nested or structured query-string values accepted by Express parsing
- Submit repository changes only where a workflow trigger and repository policy permit

### Security Objectives

- Validate untrusted input types before string processing
- Prevent attacker input from causing practical service availability failures
- Keep CI secrets and write permissions isolated from untrusted pull-request code
- Distinguish intentional unchanged training vulnerabilities from diff-introduced regressions

### Assumptions

- The application is deployed with its normal public HTTP routes.
- Express 4 query parsing may represent query values as strings, arrays, or objects.
- Centralized Express error handling confines ordinary handler exceptions unless additional evidence shows broader failure.

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Search query type confusion bypasses input bounds and triggers request failures](#finding-1) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Search query type confusion bypasses input bounds and triggers request failures

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | The exact base/target diff, anonymous route registration, removed type guard, immediate string-only sink, error boundary, and repository fix history form a complete static trace with no material reachability gap. |
| Category | Query parameter type confusion / improper input validation |
| CWE | CWE-20, CWE-400, CWE-843 |
| Affected lines | server.ts:602, routes/search.ts:21, routes/search.ts:22, lib/utils.ts:229-230 |

#### Summary

The target removes runtime string narrowing for the anonymous `q` parameter in `searchProducts()`. Express query values can be arrays or objects, so a crafted value reaches `.length` and `.substring()` as `any`: object-shaped values deterministically fail the request, while duplicate-key arrays use element count rather than character count and bypass the intended 200-character bound. The raw SQL interpolation is unchanged between the refs and is not part of this diff finding.

#### Root Cause

The violated invariant is that `q` must be a string before string-length enforcement and substring truncation. The public route forwards parsed query values to `searchProducts()`, the target removes the base revision's `typeof` guard, and the next line assumes string behavior on an `any` value.

**Anonymous product-search route** — `server.ts:602`

An unauthenticated HTTP client controls the query string passed through `asyncHandler()` to `searchProducts()`.

```typescript
app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
```

**Structured query value accepted as any** — `routes/search.ts:21`

The changed assignment preserves any non-null parsed query value, including arrays and objects, instead of narrowing `q` to a string.

```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
```

**String-only bound and substring processing** — `routes/search.ts:22`

The handler treats the attacker-selected value as a string. An object lacks `substring()`, while an array's element count is not the intended character-length bound.

```typescript
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
```

**Route errors are forwarded to middleware** — `lib/utils.ts:229-230`

A synchronous type error becomes a rejected promise and is forwarded to Express error middleware, limiting the demonstrated consequence to request handling.

```typescript
export const asyncHandler = (fn: (req: any, res: any, next: any) => Promise<any> | any) => (req: any, res: any, next: any) => {
  void Promise.resolve(fn(req, res, next)).catch(next)
}
```

#### Validation

The exact diff proves that the base string guard is removed. Source review confirms the public route, immediate string-only operations, and request-level error boundary.

Validation method: Static immutable-revision source/control/sink trace; application execution and tests were prohibited.

**Anonymous product-search route** — `server.ts:602`

An unauthenticated HTTP client controls the query string passed through `asyncHandler()` to `searchProducts()`.

```typescript
app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
```

**Structured query value accepted as any** — `routes/search.ts:21`

The changed assignment preserves any non-null parsed query value, including arrays and objects, instead of narrowing `q` to a string.

```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
```

**String-only bound and substring processing** — `routes/search.ts:22`

The handler treats the attacker-selected value as a string. An object lacks `substring()`, while an array's element count is not the intended character-length bound.

```typescript
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
```

**Route errors are forwarded to middleware** — `lib/utils.ts:229-230`

A synchronous type error becomes a rejected promise and is forwarded to Express error middleware, limiting the demonstrated consequence to request handling.

```typescript
export const asyncHandler = (fn: (req: any, res: any, next: any) => Promise<any> | any) => (req: any, res: any, next: any) => {
  void Promise.resolve(fn(req, res, next)).catch(next)
}
```

#### Dataflow

HTTP query `q` -\> Express `req.query.q` -\> `criteria` as `any` -\> `.length`/`.substring()` -\> request error or bound bypass

- **Source:** anonymous attacker-controlled `q` query value

- **Sink:** string-only processing at `routes/search.ts:22`

- **Outcome:** repeatable request-level failure or bypass of the 200-character processing bound

**Anonymous product-search route** — `server.ts:602`

An unauthenticated HTTP client controls the query string passed through `asyncHandler()` to `searchProducts()`.

```typescript
app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
```

**Structured query value accepted as any** — `routes/search.ts:21`

The changed assignment preserves any non-null parsed query value, including arrays and objects, instead of narrowing `q` to a string.

```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
```

**String-only bound and substring processing** — `routes/search.ts:22`

The handler treats the attacker-selected value as a string. An object lacks `substring()`, while an array's element count is not the intended character-length bound.

```typescript
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
```

#### Reachability

The route is public and requires no authentication. Exploitation requires only encoding `q` as a structured query value supported by Express query parsing.

- **Attacker:** remote unauthenticated client

- **Entry point:** GET `/rest/products/search`

- **Outcome:** the crafted request fails or evades the intended character bound

#### Severity

**Low** — The route is public and exploitation requires only a crafted query, making likelihood high. The proven impact is limited to repeatable request-level failures and bypass of a processing bound because the wrapper forwards exceptions to error middleware; no process-wide crash, cross-user data impact, or material shared-service exhaustion was established. Low impact with high likelihood yields low severity.

Severity would increase if runtime evidence showed that repeated malformed queries terminate the process, cause material shared-service resource exhaustion, or create cross-user impact. It would decrease to informational or be suppressed if deployment evidence proved the route unreachable to untrusted users or an equivalent pre-handler type guard rejected structured query values.

#### Remediation

Restore runtime narrowing before all string operations: read `req.query.q` into a temporary value, accept it only when `typeof value === 'string'` and it is not the sentinel `'undefined'`, and otherwise use an empty string. Keep the intentional SQL-injection challenge behavior unchanged.

Tests:
- Add a focused API regression test asserting object-shaped `q` does not return an internal error.
- Add a duplicate-key `q` regression test proving the 200-character bound is applied to a string value rather than array element count.
- Retain existing challenge tests to confirm the intentional SQL-injection behavior remains available.

Preventive controls:
- Avoid `any` for Express query values and narrow `string | ParsedQs | string[] | ParsedQs[] | undefined` at route boundaries.
- Use a shared schema validator for public query parameters before business logic.
- Keep static-analysis checks for type confusion through parameter tampering enabled.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Product search query handling | Public input validation and runtime availability | Reported | Reviewed the complete target file and exact diff. The removed string guard produced one low-severity finding; unchanged intentional SQL injection was excluded from diff attribution. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/05_findings/candidate-ca51cfb4ceda98d6/candidate_ledger.jsonl |
| Primary CI workflow changes | CI supply chain and untrusted code execution | No issue found | The added RSN job uses pinned actions and introduces no new privileged or pull-request-secret execution path. Evidence: artifacts/02_discovery/work_ledger.jsonl |
| Scheduled CodeQL and Codex Security workflow | Scheduled privileged automation, secrets, artifact integrity, and supply chain | No issue found | Reviewed all 511 lines. The workflow resolves and checks out an exact master revision, limits job permissions, disables persisted checkout credentials, and is not triggered by untrusted pull requests. No actionable compromise path was established. Evidence: artifacts/02_discovery/work_ledger.jsonl |
