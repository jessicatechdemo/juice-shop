# Security Review: juice-shop

## Scope

Security diff review of refs/heads/master through refs/heads/add-vul-back, resolved to the exact base and head revisions recorded above. The deterministic diff inventory contained one source file and it was reviewed in full.

- Scan mode: branch_diff
- Target kind: git_diff
- Target ID: target_sha256_942e4454c5a63661aa7378d57768341491657f4df9014a8cac1a157dd6f8ba9e
- Revision range: c448bad38b57b017d2ad8bc6e1ea249ed178d6ca...9bcd758d0e53bfb5b7ce1d90df5f6b6c7c16d955
- Snapshot digest: codex-security-snapshot/v1:sha256:a99cbae551756e4f35a0ae4d69dbb6346930999083e7328a2a6de537f21bb94d
- Inventory strategy: diff
- Included paths: routes/search.ts
- Excluded paths: none
- Runtime or test status: Static review only; application tests and application execution were not run per user instruction.
- Artifacts reviewed: Exact Git revision diff, routes/search.ts in both revisions, supporting public route registration, Express/qs parsing behavior, error handling, focused test source, repository security guidance, and the omitted fix commit
- Scan context: Resolved SECURITY.md guidance and the repository-scoped threat model matching the target revision were used as the threat-model source of truth.

Limitations and exclusions:
- Application execution was forbidden, so operational resource amplification was not measured.
- Uncommitted working-tree changes were outside the requested revision range and were not scanned.
- Excluded working-tree-only changes: The user requested an exact comparison between two Git refs; unrelated staged, unstaged, and untracked workspace content was outside scope.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 1 |
| Severity mix | low: 1 |
| Confidence mix | high: 1 |
| Coverage | complete |
| Validation mode | Full-file diff review with static source/control/sink validation and attack-path analysis. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

A public OWASP Juice Shop deployment must preserve input-validation, availability, user, administrative, filesystem, network, credential, and source-integrity boundaries even for intentional challenge behavior.

### Assets

- Application availability and bounded server/database resource use
- User identities, credentials, tokens, private customer data, and privileged application capabilities
- Application and deployment secrets, host filesystem, and repository integrity

### Trust Boundaries

- Public HTTP query parameters crossing into Express route handlers and database operations
- Authenticated identity and object-ownership boundaries
- Untrusted repository content and privileged automation

### Attacker Capabilities

- Anonymous users can send arbitrary query-string syntax, including duplicate and structured parameters, to public routes
- Authenticated users can control request bodies, headers, files, and client-selected identifiers

### Security Objectives

- Validate and bound attacker-controlled input before type-dependent or resource-sensitive processing
- Enforce server-side identity, role, and object ownership
- Contain file, parser, network, database, and model-driven operations

### Assumptions

- The product-search route is publicly reachable under the application's default Express query-parser configuration
- Intentional challenge vulnerabilities remain reportable under repository policy

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Structured search parameters bypass string validation and input bounds](#finding-1) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Structured search parameters bypass string validation and input bounds

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Static source tracing and bounded inspection of the configured Express/qs parser establish anonymous reachability, non-string query values, removal of the exact type guard, deterministic incompatible string handling, and the character-limit bypass; only the wider operational magnitude remains unmeasured. |
| Category | Type confusion through parameter tampering |
| CWE | CWE-843 |
| Affected lines | routes/search.ts:21, routes/search.ts:22-23, server.ts:602 |

#### Summary

The target revision removes the base revision's runtime string check for the public `q` search parameter. Express extended parsing can therefore supply an object or array to string-specific processing: object-shaped values trigger a server-side request failure, while duplicate-key arrays use element count instead of character count and bypass the intended 200-character limit before SQL construction.

#### Root Cause

The security invariant is that `q` must be a string before the route performs string length enforcement or passes it onward. The base revision enforced that invariant with a runtime `typeof` check; the target replaces it with an `any` assignment. Because Express extended query parsing can produce objects and arrays, the target allows non-string values to reach string-specific processing and SQL-string construction.

**Public product-search route** — `server.ts:602`

The application registers `searchProducts()` on a GET route without authentication middleware, so an anonymous caller can control its query parameters.

```typescript
  app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
```

**Query value accepted without a string-type guard** — `routes/search.ts:20-22`

Attacker-controlled `req.query.q` is assigned as `any` and immediately processed with string-specific length and `substring()` assumptions, violating the invariant that the bounded value must first be a string.

```typescript
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
```

**Bounded value is consumed by SQL construction** — `routes/search.ts:23`

An array that passes the element-count check is string-coerced into the SQL text, so the removed type guard also defeats the intended 200-character bound. The SQL interpolation itself is unchanged between revisions and is supporting context, not a newly introduced injection finding.

```typescript
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
```

#### Validation

The review confirmed that the anonymous route accepts structured query values, the target removes the base string guard, object values reach incompatible `substring()` handling, and duplicate-key arrays bypass the intended character bound before SQL construction.

Validation method: Static source trace with bounded Express/qs parser inspection

**Public product-search route** — `server.ts:602`

The application registers `searchProducts()` on a GET route without authentication middleware, so an anonymous caller can control its query parameters.

```typescript
  app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
```

**Query value accepted without a string-type guard** — `routes/search.ts:20-22`

Attacker-controlled `req.query.q` is assigned as `any` and immediately processed with string-specific length and `substring()` assumptions, violating the invariant that the bounded value must first be a string.

```typescript
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
```

**Bounded value is consumed by SQL construction** — `routes/search.ts:23`

An array that passes the element-count check is string-coerced into the SQL text, so the removed type guard also defeats the intended 200-character bound. The SQL interpolation itself is unchanged between revisions and is supporting context, not a newly introduced injection finding.

```typescript
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
```

#### Dataflow

HTTP `q` parameter -\> Express extended query parser -\> `req.query.q` -\> untyped `criteria` -\> `length`/`substring()` -\> SQL text

- **Source:** Anonymous attacker-controlled `q` query parameter

- **Sink:** Type-dependent request processing and subsequent SQL-string construction

- **Outcome:** Request-level server error or bypass of the intended 200-character input bound

Transformations:
- Extended parsing can produce an object or array.
- Target line 21 assigns the parsed value as `any` without the base string check.
- Target line 22 treats object shape or array element count as string semantics.

**Public product-search route** — `server.ts:602`

The application registers `searchProducts()` on a GET route without authentication middleware, so an anonymous caller can control its query parameters.

```typescript
  app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
```

**Query value accepted without a string-type guard** — `routes/search.ts:20-22`

Attacker-controlled `req.query.q` is assigned as `any` and immediately processed with string-specific length and `substring()` assumptions, violating the invariant that the bounded value must first be a string.

```typescript
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
```

**Bounded value is consumed by SQL construction** — `routes/search.ts:23`

An array that passes the element-count check is string-coerced into the SQL text, so the removed type guard also defeats the intended 200-character bound. The SQL interpolation itself is unchanged between revisions and is supporting context, not a newly introduced injection finding.

```typescript
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
```

#### Reachability

The route is public and the trigger needs only crafted query syntax under the application's default extended parser configuration.

- **Attacker:** Anonymous remote caller

- **Entry point:** GET /rest/products/search

- **Outcome:** The server processes a non-string value through a removed validation boundary, producing a request failure or bounds bypass.

Preconditions:
- The public route is reachable.
- The default extended query parser remains active.
- The attacker supplies object-shaped or duplicate `q` parameters.

#### Severity

**Low** — An anonymous remote caller can trigger the flaw with ordinary query syntax, but repository evidence establishes only a request-level failure and a bounded length-control bypass. Express error handling and parser/request-size limits reduce amplification, and no process termination, persistent degradation, or cross-user impact was demonstrated.

Raise the severity if one crafted request can terminate or wedge the Node.js process, or if the length-cap bypass causes disproportionate CPU, memory, or database consumption that affects other users. Lower or reject it if an upstream parser or middleware is shown to coerce or reject every non-string `q` value before this route.

#### Remediation

Restore runtime string validation before length handling, or reject every non-string `q` value with HTTP 400. Apply the 200-character limit only after type validation. Keep any separate SQL parameterization work distinct from this diff-specific root cause.

Tests:
- Verify object-shaped `q` input is rejected or safely normalized without an HTTP 500.
- Verify duplicate `q` keys cannot bypass a 200-character aggregate input limit.
- Verify ordinary string, empty, and missing `q` values retain the intended search behavior.

Preventive controls:
- Validate and narrow Express query parameter types at route boundaries before business logic.
- Use a shared schema validator that rejects arrays and objects for scalar query fields.
- Keep focused regression coverage for structured parameter tampering on public routes.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Product search route diff | Query-parameter type validation and resource bounds | Reported | The sole changed source file was reviewed in full. The removed runtime string guard survived validation and attack-path analysis as a low-severity finding; the SQL interpolation at the next line is unchanged and was not reported as diff-introduced. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/02_discovery/finding_discovery_report.md, artifacts/05_findings/routes-search-q-type-confusion/candidate_ledger.jsonl, artifacts/05_findings/routes-search-q-type-confusion/validation_report.md, artifacts/05_findings/routes-search-q-type-confusion/attack_path_analysis_report.md |
