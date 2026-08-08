# Search query parameter type confusion bypasses input bounds and triggers request failures

- Candidate: `routes-search-q-type-confusion`
- Decision: reportable
- Impact: low
- Likelihood: high
- Severity: low
- Priority: P3

## Attack path

1. An anonymous remote caller sends object-shaped or duplicate `q` parameters to `GET /rest/products/search`.
2. Express extended query parsing produces an object or array instead of a string.
3. Target `routes/search.ts:21` accepts that value after the base revision's string guard was removed.
4. At line 22, an object reaches incompatible `substring()` handling and triggers a request failure, or an array's element count bypasses the intended 200-character bound.
5. An accepted array is coerced into the SQL string at line 23, defeating the intended character bound. The SQL injection itself is unchanged and is not used to elevate this finding.

## Attack-path facts

- Assumptions: the public route is reachable and the default extended query parser remains active.
- Context: remote input crosses the HTTP parsing boundary into a public Node.js/Express runtime API. The established impact is a deterministic server-side request failure and bypass of an input-length security control.
- In-scope status: in scope under the repository threat model; challenge-related runtime code is explicitly reviewable.
- Exposure: public application route registered at `server.ts:602` without authentication middleware.
- Identity: anonymous remote caller; no service identity or secrets are required.
- Cross-boundary behavior: attacker-controlled structured query data reaches server-side type-dependent processing and SQL construction.
- Vector: remote.
- Preconditions: plausible and low-friction; send structured or duplicate `q` parameters.
- Attacker input control: yes.
- Category: CWE-843 type confusion, CWE-20 improper input validation, CWE-400 uncontrolled resource consumption.
- Mitigations: Express error handling generally confines thrown errors to the request; `qs` parameter limits and HTTP request-size limits bound amplification.
- Auth scope: public.
- Impact surface: runtime, single service.
- Target reach: single service instance.
- Secrets: none.
- Counterevidence: repository evidence does not establish process termination, persistent degradation, cross-user impact, or disproportionate shared-resource consumption. This limits impact to low but does not negate the remote server-side failure and character-bound bypass.
- Blindspots: application execution was forbidden, so operational amplification was not measured.
- Confidence: high for reachability, type confusion, request failure, and bound bypass; low for wider availability impact.

## Severity and policy

Impact is low and likelihood is high because the route is public and exploitation is simple. The mechanical matrix yields low severity. Hard suppression for self-only behavior does not apply: the malformed input crosses into a server-side route and defeats a server-side validation control, even though the demonstrated effect is request-scoped and no broader outage is proven. The final decision is reportable at low severity (P3).

Restore the runtime string guard before length handling, or reject non-string `q` values with HTTP 400. Parameterizing the unchanged SQL query is separately advisable but is outside the diff-specific root cause.
