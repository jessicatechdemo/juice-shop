# Validation: Search query parameter type confusion

- Candidate id: `candidate-ca51cfb4ceda98d6`
- Root control: `routes/search.ts:21`
- Entrypoint: `server.ts:602`
- Sink: `routes/search.ts:22`
- Confidence: high
- Method: static immutable-revision source/control/sink trace; application execution and tests were prohibited by the user

## Rubric

- [x] An anonymous HTTP input reaches the changed value.
- [x] The base revision has an effective runtime type guard that the target removes.
- [x] Structured query values can reach string-only processing in the target.
- [x] Synchronous failure is forwarded to the application's error middleware.
- [x] The impact and proof gap are distinguished from the unchanged intentional SQL injection.

## Evidence

The target registers `GET /rest/products/search` without authentication at `server.ts:602`. The base revision reads `req.query.q` into `rawCriteria` and accepts it only when `typeof rawCriteria === 'string'`; the target instead assigns `req.query.q` directly as `any` at `routes/search.ts:21`. Target line 22 immediately reads `.length` and invokes `.substring(0, 200)` when the length exceeds 200. Express 4 query values are not guaranteed to be strings, so nested object input deterministically reaches a missing-method exception and duplicate-key arrays use element count rather than character count for the intended bound. Repository history identifies commit `068a6b339` as the corresponding type-confusion fix, and the target reintroduces its vulnerable expression.

`utils.asyncHandler` at `lib/utils.ts:229-230` converts synchronous throws into rejected promises and forwards them with `next`; `server.ts:681-682` installs error middleware. This is strong counterevidence against process termination or demonstrated cross-user denial of service, but does not defeat the anonymous deterministic request failure or input-bound bypass.

## Disposition

Reportable. The exact changed guard, public route, and deterministic failure path are established statically with high confidence. The strongest repeatable proof artifact is the immutable Git diff and source trace because application tests and runtime execution were excluded by the scan request.

## Remaining uncertainty

No application execution was permitted. Material multi-user resource exhaustion or process-wide failure is not established, so availability impact is limited to repeated request-level failures and severity must remain low.
