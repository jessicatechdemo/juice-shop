# Search query parameter type confusion bypasses input bounds and triggers request failures

- Candidate: `routes-search-q-type-confusion`
- Confidence: high
- Method: static code understanding with bounded Express/qs parser inspection
- Disposition: reportable

## Rubric

- [x] Attacker-controlled input reaches the route: `server.ts:602` exposes anonymous `GET /rest/products/search`, with `q` sourced from `req.query`.
- [x] Framework parsing can produce non-string `q` values: the Express application uses extended query parsing; `qs` parses bracket syntax as objects and duplicate keys as arrays.
- [x] The diff removes the relevant runtime control: base lines 21-22 accept only string values, while target line 21 assigns `req.query.q` directly as `any`.
- [x] Malformed input reaches a concrete failure or bound bypass: object-shaped values lack a string `substring` method, and duplicate-key arrays use element count rather than character count before SQL construction.
- [x] The instance is distinct from the unchanged intentional SQL injection: interpolation at target line 23 exists in both revisions; the new regression is the removed type guard and resulting type-confusion/bounds behavior.

## Assessment

Source: anonymous `q` query parameter on `GET /rest/products/search`.

Control: the target removes the base revision's string-type guard at `routes/search.ts:21`.

Sink: type-dependent `length`/`substring` processing at `routes/search.ts:22`, followed by SQL-string construction at line 23.

Preconditions: the public endpoint is reachable; an attacker supplies object-shaped `q` syntax or duplicate `q` keys; the default extended query parser remains active.

Static evidence establishes the complete source/control/sink path. Commit `068a6b3396` independently identifies the omitted guard as a fix for type confusion through parameter tampering. Express error handling likely confines a thrown `TypeError` to an HTTP 500 for that request, and parser/request-size limits bound amplification. Application execution was forbidden, so process termination and sustained multi-user resource exhaustion were not established. The candidate nevertheless survives because the diff deterministically restores non-string handling and bypass of the intended 200-character control on a public route.
