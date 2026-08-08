# Attack path: Search query parameter type confusion

- Candidate id: `candidate-ca51cfb4ceda98d6`
- Decision: reportable
- Severity: low (P3)

## Attacker path

1. A remote unauthenticated attacker sends `GET /rest/products/search` with `q` encoded as a structured query value.
2. Express exposes the parsed structured value as `req.query.q`.
3. The target's changed line assigns that value directly as `any`, where the base revision accepted only strings.
4. `routes/search.ts:22` applies string-only length/substring processing. An object value causes a request exception; a duplicate-key array uses element count and bypasses the intended character bound.
5. The wrapper forwards the exception to application error middleware, so the demonstrated consequence is repeated request-level failure rather than process termination.

## Attack-path facts

- Assumptions: standard Express 4 query parsing accepts structured values; the public HTTP route is deployed normally.
- Context: production runtime route in an intentionally vulnerable training application; the reliability effect crosses the remote request boundary but no other user's session or data boundary is shown.
- In scope: yes. Public Node/Express runtime routes and attacker-controlled query parameters are in scope under the repository security guidance; intentional challenge context does not exclude regressions.
- Exposure: public HTTP route registered at `server.ts:602`.
- Identity: no authentication or privileged identity is required.
- Cross-boundary behavior: verified remote input reaches the changed control and sink; only request-level availability impact is verified.
- Vector: remote.
- Preconditions: the attacker can send a crafted query string; this is plausible and low friction.
- Attacker input control: yes, over `q`.
- Category: CWE-843 type confusion / CWE-20 improper input validation / CWE-400 resource handling.
- Mitigations: `utils.asyncHandler` and Express error middleware contain synchronous failures; no process-wide crash or shared-state corruption is evidenced.
- Auth scope: public.
- Impact surface: runtime availability and input-bound enforcement, single service.
- Secrets: none.
- Counterevidence: centralized error handling strongly limits the observed effect to the initiating request. This is dispositive against medium/high availability impact, but not against the deterministic public failure and guard regression.
- Blindspots: no dynamic reproduction was permitted; multi-user degradation under request volume is unproven.
- Confidence: high for reachability and request failure; low/unknown for broader availability degradation.

## Severity calibration

Impact is low and likelihood is high because the route is public and exploitation requires only a crafted query. The mechanical matrix yields low severity. The finding remains reportable because repository guidance explicitly treats limited but practical remote availability failures as low severity rather than suppressing them.

## Remediation direction

Restore runtime narrowing before all string operations: accept `q` only when it is a string and use an empty string otherwise. Add a focused regression assertion for object-shaped and duplicate-key query values while preserving the intentional SQL-injection challenge behavior.
