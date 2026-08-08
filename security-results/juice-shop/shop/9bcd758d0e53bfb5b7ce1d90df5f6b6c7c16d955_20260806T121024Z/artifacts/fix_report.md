# Fix Report: csf_eada35b5dfdbdb57cb32be4e

## Outcome

`fixed`

The public `GET /rest/products/search` route accepted repeated `q` parameters as an array. `routes/search.ts` treated that array as a string: its element count could bypass the 200-character limit, it was coerced into the SQL text, and an array with more than 200 elements reached an invalid `substring()` call. The route now narrows `q` to a runtime string before applying the length limit. Non-string values retain the repository's established behavior of normalizing to an empty search.

## Patch contract

- Vulnerable path: anonymous HTTP `q` query parameter -> Express query parsing -> `req.query.q` -> array/object accepted as `criteria` -> type-dependent `length`/`substring()` -> SQL text.
- Security invariant: only a scalar string may reach string length enforcement and SQL construction.
- Enforcement boundary: the search route immediately after reading `req.query.q`.
- Preserved behavior: ordinary string searches, empty and missing searches, existing response semantics, and the documented SQL-injection challenge behavior.
- Strategy: restore the repository's prior runtime `typeof` guard from commit `068a6b3396`, normalize non-strings to the existing empty-search value, and leave SQL construction and challenge logic unchanged. This is the narrowest repository-native change that completely closes the reported type-confusion boundary.

## Files changed

- `routes/search.ts`: restored scalar runtime narrowing before the 200-character bound.
- `test/api/search.test.ts`: added a real HTTP regression covering a two-element array whose aggregate characters exceed 200 and a 201-element array that previously reached `substring()` on an array.
- `data/static/codefixes/dbSchemaChallenge_{1,2_correct,3}.ts`: synchronized the non-challenge-specific guard.
- `data/static/codefixes/unionSqlInjectionChallenge_{1,2_correct,3}.ts`: synchronized the non-challenge-specific guard.
- `rsn/cache.json`: updated the affected locked line offsets after manual codefix synchronization.
- `AGENTS.md`: separately requested guidance clarification that credible challenge vulnerabilities remain reportable vulnerabilities.

## Regression evidence

Before the source fix:

```text
node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit --test-name-pattern='repeated search parameters' test/api/search.test.ts
FAIL: AssertionError, 0 !== 46 at test/api/search.test.ts
```

This proved that repeated `q` keys crossed the real public HTTP boundary as a non-string and were processed as search criteria instead of normalized.

After the source fix, the same test passes. It checks both reported effects:

- `q=nomatcheswhatsoever&q=<201 characters>` no longer uses array element count to bypass the character bound.
- 201 repeated `q=x` keys no longer call `substring()` on an array or return HTTP 500.

Both inputs return HTTP 200 with the same result count as the established empty-search behavior.

## Ordered verification

### 1. Applicability and buildability

- `git diff --check -- routes/search.ts test/api/search.test.ts data/static/codefixes/dbSchemaChallenge_1.ts data/static/codefixes/dbSchemaChallenge_2_correct.ts data/static/codefixes/dbSchemaChallenge_3.ts data/static/codefixes/unionSqlInjectionChallenge_1.ts data/static/codefixes/unionSqlInjectionChallenge_2_correct.ts data/static/codefixes/unionSqlInjectionChallenge_3.ts rsn/cache.json` — PASS.
- `npm run build:server` — PASS.

### 2. Security closure

- `node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit --test-name-pattern='repeated search parameters' test/api/search.test.ts` — PASS outside the command sandbox: 1 test passed, 0 failed.
- Patched source trace — PASS: every non-string `req.query.q` value is converted to `''` before `.length`, `.substring()`, or SQL construction.

The original issue no longer reproduces: both the aggregate-character bypass and the incompatible-array-operation variant return the safe empty-search response.

### 3. Change-aware bypass review

- Alternate malicious input class in the focused regression (201 repeated keys) — PASS without HTTP 500.
- Direct-caller and equivalent-branch review — PASS: the only route consumer reads `rawCriteria`, narrows it once, and all subsequent branches operate on a string.
- The unchanged intentional SQL interpolation is outside this finding and was not weakened or represented as fixed.

### 4. Preserved behavior

- `node --import ./test/api/helpers/test-env.mjs --import tsx --test --test-force-exit test/api/search.test.ts` — PASS outside the command sandbox: 16 tests passed, 0 failed.
- This includes ordinary matching and non-matching strings, empty and missing `q`, SQL-error semantics, successful challenge payloads, and logically deleted product behavior.

Legitimate behavior remains intact: the complete owning API test file passed, including the documented challenge paths.

### 5. Repository checks

- `npm run lint` — PASS, including backend ESLint, config validation, Angular lint, and SCSS stylelint.
- `npm run rsn` — initially FAIL after the source edit, correctly identifying changed challenge snippets.
- Manual synchronization of all six affected codefix files — completed.
- `npm run rsn:update` — PASS; affected locked line offsets updated.
- `npm run rsn` — PASS: all codefix files match the locked state.
- `npm test` — PASS outside the command sandbox; frontend, server, and API stages completed with exit code 0. The API stage reported 550 passed, 6 pre-existing expected skips, and 0 failed.

## Remaining uncertainty

No proof gap remains for the reported type-confusion and input-bound bypass. Cypress E2E was not run because the changed control is entirely server-side and is exercised through the real Express/Sequelize API boundary by the focused integration test and full API suite. The full repository test command passed. The intentionally vulnerable SQL interpolation remains present by design and is outside this finding's root cause.
