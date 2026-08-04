# Unauthenticated polynomial-time regular expression in profile image URL handling

## Executive Summary

An unauthenticated attacker, Mallory, can submit a long `imageUrl` value that does not contain `solve/challenges/server-side` to `POST /profile/image/url`. Before the route checks for a valid login token, it applies a polynomial-time regular expression to the entire value on Node.js's main event-loop thread. The narrow demonstrated effect is attacker-controlled CPU consumption that grows approximately quadratically with input length and can delay other work handled by the same process. This does not require session theft, does not demonstrate SSRF, and has not been shown to cause a sustained outage in a running service.

I reviewed the exact assessed development revision `840220e9a18d` (11 commits after the public v20.1.1 release), traced the relevant source and release history, inspected the request-size controls in the installed dependency tree, and ran the exact regular expression in a local Node.js v25.8.2 microbenchmark. I did not send the trigger through the HTTP service or test any public or production system.

The vulnerable expression first entered the project while the server-side request forgery challenge was being added. It is absent from the inspected v7.5.1 snapshot, present in v8.0.0, and remains present in v20.1.1 and the assessed post-v20.1.1 revision. The repository history from its introduction through the assessed revision shows no removal of the expression. No released fix was identified. This supports an affected source range of v8.0.0 through v20.1.1; the intermediate releases were not individually executed.

## Background

OWASP Juice Shop lets an authenticated user set a profile image by submitting a URL. The application also watches for the substring `solve/challenges/server-side` so it can record use of an intentionally vulnerable server-side request forgery challenge. The substring check is bookkeeping for the training challenge; it should not make unauthenticated traffic consume disproportionate event-loop time.

At the assessed revision, `server.ts` installs URL-encoded body parsing and then registers the image URL endpoint without authentication middleware:

```ts
app.use(bodyParser.urlencoded({ extended: true }))
app.post('/profile/image/url', uploadToMemory.single('file'), utils.asyncHandler(profileImageUrlUpload()))
```

`server.ts`, `configureApp`, assessed post-v20.1.1 revision

This makes the handler reachable before it has established an authenticated user. Mallory controls `req.body.imageUrl`; she needs only network access to the route and does not need an account or a valid cookie.

Request parsing places finite but still security-relevant bounds on the value. The assessed `package.json` permits `body-parser` `^1.20.4` and Multer `^1.4.5-lts.1`, but the repository has no root lock file that pins their exact installed builds. In the inspected local dependency tree, `body-parser` 1.20.6 applies its default 100 KiB limit to URL-encoded bodies. For multipart requests, Multer 1.4.5-lts.2 passes only `fileSize: 200000` to Busboy 1.6.0; that file limit does not limit ordinary fields, and the inspected Busboy implementation defaults each field to 1 MiB. These bounds prevent unlimited input, but they do not make a polynomial algorithm safe. Deployment-specific proxy limits may reduce reachable input sizes, but their prevalence and values are unknown.

## Vulnerability Details

The route copies Mallory's body field into `url` and immediately evaluates the challenge-marker expression. Only afterward does it look up the authentication token:

```ts
if (req.body.imageUrl !== undefined) {
  const url = req.body.imageUrl
  if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
  const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
  if (loggedInUser) {
```

`routes/profileImageUrlUpload.ts`, `profileImageUrlUpload`, assessed post-v20.1.1 revision

The expected order is to reject an unauthenticated request before performing nontrivial work on its application data. Instead, the regular expression is the first substantive operation on `imageUrl`. An absent or invalid token therefore does not protect the regular-expression engine.

The expression is unanchored and begins with `(.)*`, followed by a fixed literal. When the literal is absent, the JavaScript engine repeatedly consumes and backtracks over overlapping candidate prefixes while also considering later starting positions. The amount of work grows approximately with the square of the nonmatching input length. The final `(.)*` is also unnecessary: the route only needs to know whether the fixed marker occurs anywhere in the string.

The expression was added in commit `29716bfe2` as part of the SSTI and SSRF challenge work, initially in `routes/fileUpload.js`. A subsequent refactor moved the same check into the new `routes/profileImageUrlUpload.js`; later TypeScript conversions preserved it. Inspection of v7.5.1 found no profile-image URL route or marker expression, while v8.0.0 contains the vulnerable expression in `routes/profileImageUrlUpload.js`. The same expression is present in v20.1.1 and in the assessed revision. The history identifies v8.0.0 as the first verified affected public release, but no claim is made about uninspected prerelease builds.

## Exploitability Analysis

The demonstrated primitive is unauthenticated consumption of the single Node.js event-loop thread. In a typical single-process deployment, work spent backtracking in this synchronous expression delays unrelated requests scheduled on that process. The experiment below establishes superlinear CPU cost for the exact expression; it does not by itself establish request throughput, timeout behaviour, the number of requests needed for disruption, or a sustained denial of service.

A nonmatching string is the meaningful positive control because it forces the engine to exhaust its candidate matches. A local run produced these timings:

| Input length | Exact-regex time |
| ---: | ---: |
| 1,000 | 1.082 ms |
| 2,000 | 4.111 ms |
| 4,000 | 17.394 ms |
| 8,000 | 66.072 ms |
| 16,000 | 265.416 ms |

Doubling the input caused close to four times the work across the measured range, which rules out ordinary linear scanning as an explanation for the result. The benchmark used only `a` characters and did not contact a URL, write an image, or exercise authentication.

The source ordering provides a second control: the authentication lookup is below the expression, so an invalid or missing token cannot prevent this CPU work. Conversely, a short `imageUrl` or one containing the fixed marker does not force the same exhaustive nonmatch path. Existing API tests confirm ordinary authenticated requests can reach the profile-image flow, while the anonymous-request test is currently skipped because of an unrelated socket-hang-up problem; neither test measures the regular expression's cost.

Finite parser limits constrain the maximum single-request input. URL-encoded requests are limited by the inspected parser's 100 KiB default, while multipart fields may be larger in the inspected dependency configuration. Reverse proxies may impose smaller limits. These constraints reduce the possible input space but do not remove the vulnerable asymptotic behaviour. No service-level test was performed, so concurrency, rate limiting, process clustering and operational recovery remain unmeasured. The evidence supports availability degradation, not a claim of reliable total outage, data access or code execution.

## Proof of Concept

No network PoC was created because the exact failure can be demonstrated safely without starting the application or risking service disruption. From the repository root, the following bounded command runs the exact regular expression against five nonmatching strings:

```sh
node -e 'const re=/(.)*solve\/challenges\/server-side(.)*/; for (const n of [1000,2000,4000,8000,16000]) { const s="a".repeat(n); const t=process.hrtime.bigint(); re.test(s); console.log(`${n} ${(Number(process.hrtime.bigint()-t)/1e6).toFixed(3)} ms`) }'
```

The observed Node.js v25.8.2 output was:

```text
1000 1.082 ms
2000 4.111 ms
4000 17.394 ms
8000 66.072 ms
16000 265.416 ms
```

Timing depends on the processor, Node.js version and system load; the scaling trend matters more than the absolute values. The command is intentionally capped at 16,000 characters. Increasing the lengths can consume substantial CPU and is not necessary to verify the polynomial trend. It creates no files and requires no cleanup.

This is an executed microbenchmark of the exact expression, not an HTTP exploit. An expected service-level demonstration would send a body containing a long nonmatching `imageUrl` without a valid token and measure delayed event-loop progress, with a short nonmatching value as a negative control. That experiment was not run, so no HTTP status, latency or outage result is claimed.

## Remediation

Replace the regular expression with the linear-time string operation that expresses the actual requirement, and authenticate before inspecting the user-controlled URL. For example:

```ts
const url = req.body.imageUrl
const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
if (!loggedInUser) {
  next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
  return
}
if (typeof url !== 'string') {
  res.status(400)
  next(new Error('Invalid profile image URL'))
  return
}
if (url.includes('solve/challenges/server-side')) req.app.locals.abused_ssrf_bug = true
```

`String.prototype.includes` preserves the marker's intended substring semantics without regex backtracking. Moving authentication first prevents anonymous requests from reaching even that linear scan. The type check makes the subsequent `includes`, `fetch` and `split` operations explicit rather than assuming the parser always produced a string. This is a proposed source-compatible remediation; no shipped upstream fix or fixed release was verified.

As defence in depth, configure explicit and suitably small limits for the `imageUrl` field in every accepted content type. The existing Multer `fileSize` limit should not be treated as a field-size limit. Rate limiting can reduce repeated abuse but is not a substitute for removing the polynomial operation.

Regression coverage should include:

- an unauthenticated request with a long nonmatching `imageUrl`, confirming rejection occurs before challenge-marker inspection;
- long LF-free and newline-containing nonmatching values, confirming processing remains linear and does not depend on dot-matching details;
- authenticated values with the marker at the beginning, middle and end, confirming challenge bookkeeping still works;
- an authenticated benign URL served by the existing local mock server, confirming the normal upload and redirect path remains intact;
- non-string `imageUrl` values and requests exceeding each configured parser limit, confirming deterministic 4xx rejection.

A bounded performance regression test can compare doubling input sizes across several iterations with a generous ratio threshold, but it should avoid brittle absolute-time assertions. Static analysis should also be rerun to confirm the polynomial regular-expression path is gone.

## Summary

From v8.0.0 through the inspected v20.1.1 release and assessed post-v20.1.1 revision, `POST /profile/image/url` evaluates an attacker-controlled, polynomial-time regular expression before checking authentication. A safe local run of the exact expression showed approximately fourfold CPU growth when input length doubled. Parser limits cap individual inputs but do not remove that growth, and the Multer file-size setting does not cap multipart text fields in the inspected dependency configuration.

The demonstrated impact is unauthenticated event-loop CPU consumption and plausible service availability degradation. A sustained outage was not reproduced. Reordering authentication and replacing the challenge-marker expression with `includes` removes the demonstrated mechanism while preserving the intended substring check; no released fix has yet been verified.
