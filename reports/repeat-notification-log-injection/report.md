# Log injection through repeat-notification challenge lookup

## Executive Summary

An unauthenticated attacker, Mallory, can place carriage-return or line-feed characters in the `challenge` query parameter of `GET /rest/repeat-notification`. When the decoded name does not match a known challenge, OWASP Juice Shop passes Mallory's value directly to its warning logger. The logging boundary should keep one request in one warning record, but the assessed source allows Mallory to inject line breaks into the message sent to the console transport. This can make attacker-controlled text appear as a separate physical log line and can mislead operators or downstream line-oriented log processing. It does not provide authentication bypass, code execution, access to another user's data, or control over the logger's metadata fields.

I inspected the exact assessed branch revision, which advertises version `20.1.1` in `package.json` but contains commits after the `v20.1.1` tag. I also inspected the relevant release snapshots and the uncommitted proposed fix and regression tests. The vulnerable endpoint and dynamic logging statement first appear in the verified `v2.26.0` release, are absent from `v2.25.0`, and remain present in the verified `v20.1.1` release and assessed post-`v20.1.1` revision. No released fix was verified. A supplied local validation record shows that the malicious unit case failed before the proposed patch, while the focused unit suite passed 3 of 3 tests and the isolated route-level suite passed 4 of 4 after the patch; I did not test any public or production system.

## Background

The repeat-notification endpoint lets a client name a challenge and asks the server to resend the notification if that challenge has already been solved. The assessed server registers the endpoint as a plain `GET` route without authentication middleware in `server.ts`:

```ts
app.get('/rest/repeat-notification', utils.asyncHandler(repeatNotification()))
```

Mallory needs only network access to the Juice Shop HTTP service. She does not need an account, a solved challenge, CTF credentials, or access to the host. Her controlled value is `query.challenge`; the protected resource is the integrity of the server's line-oriented warning output. The relevant logger uses a Winston console transport with `winston.format.simple()` in `lib/logger.ts`.

For an ordinary unknown name such as `not-a-challenge`, the intended behaviour is to return HTTP 200 and emit one warning describing the missing challenge. Newline characters within the untrusted name should be removed or represented as inert escaped text before the value reaches the logger. Challenge lookup itself must continue to use the original name so that the mitigation does not change matching behaviour.

## Vulnerability Details

At the assessed source revision, `repeatNotification` in `routes/repeatNotification.ts` decodes the query parameter and passes the resulting string to the challenge lookup:

```ts
export function repeatNotification () {
  return ({ query }: Request, res: Response) => {
    const challengeName: string = decodeURIComponent(query.challenge as string)
    const challenge = challengeUtils.findChallengeByName(challengeName)

    if (challenge?.solved) {
      challengeUtils.sendNotification(challenge, true)
    }

    res.sendStatus(200)
  }
}
```

For example, `%0D%0A` becomes a carriage return followed by a line feed. The route performs no validation or neutralisation after decoding. A solved challenge is not required: an unmatched name takes the path to the vulnerable warning.

The same revision's `findChallengeByName` function in `lib/challengeUtils.ts` compares the original string against known challenge names. When none matches, it concatenates that string directly into the message passed to `logger.warn`:

```ts
export const findChallengeByName = (challengeName: string) => {
  for (const challenge of Object.values(challenges)) {
    if (challenge.name === challengeName) {
      return challenge
    }
  }
  logger.warn('Missing challenge with name: ' + challengeName)
}
```

No later application guard removes CR or LF before the sink. Consequently, a value such as `missing\r\nforged log entry` reaches Winston as part of one message containing embedded record separators. The route still answers with HTTP 200, so the attacker does not need to observe the server's logs to repeat the operation.

Release history narrows the affected versions more than the supplied triage summary. The route, lookup helper, and unsafe error output were introduced together in the source merged for release `v2.26.0`; direct inspection confirms they are absent in `v2.25.0` and present in `v2.26.0`. A later change included in `v7.1.0` only capitalised `missing` to `Missing`; it did not introduce the unsafe concatenation. Later changes replaced `console.error` with Winston logging, reduced the level to `warn`, migrated the code to TypeScript, and moved the helper to `lib/challengeUtils.ts` without neutralising the attacker-controlled line breaks. Direct inspection confirms the same vulnerable statement in `v20.1.1` and the assessed post-release revision. Intermediate releases were not all inspected individually, and no released remediation or backport was found.

## Exploitability Analysis

The established primitive is unauthenticated control of CR and LF characters in a value passed to the configured line-oriented console logger. Under the shipped simple formatter, those characters split the visible output into additional physical lines. Mallory can therefore append text that may look like an independent event. This crosses the log-integrity boundary even though it does not change the real log level, timestamp, process identity, or server state.

The practical effect depends on how an operator collects and interprets console logs. A human reader or collector that treats every line as a separate event can be misled; a collector that adds trusted metadata outside the message or safely escapes embedded newlines may make the forgery easier to recognise. Deployment prevalence and the behaviour of external log collectors were not measured, so this report does not claim that Mallory can forge trusted structured metadata or reliably evade a particular monitoring product.

The source and regression checks provide the following controls:

- A safe unknown name still returns `undefined` and produces the exact expected one-line warning, ruling out a fix that simply suppresses every missing-challenge log.
- Known challenge names still resolve normally, ruling out a change to challenge matching as the reason the malicious case passes.
- The route-level test requires HTTP 200 for a `%0D%0A` input and inspects the actual argument handed to `logger.warn`, showing that URL decoding and the real Express route reach the protected boundary.
- The unit test covers LF, CR, CRLF, and repeated LF. Before the proposed patch, the malicious test observed the embedded line breaks and failed; after the patch, all captured warning arguments were free of CR and LF.

These controls demonstrate the source-to-sink condition and its removal by the proposed patch. They do not demonstrate code execution, authentication bypass, disclosure of challenge data, or compromise of a remote log-management system.

## Proof of Concept

No separate PoC program is required because the existing HTTP endpoint and regression tests exercise the complete relevant path. Testing is safe against a disposable local Juice Shop instance: the request performs a challenge-name lookup, may emit a warning, and returns HTTP 200. It should not be directed at public or production systems without explicit target-specific permission.

The minimal request is:

```http
GET /rest/repeat-notification?challenge=missing%0D%0Aforged%20log%20entry HTTP/1.1
Host: 127.0.0.1:3000
Connection: close
```

At the vulnerable revision, source review and the observed pre-fix regression run establish that the logger argument contains the equivalent of:

```text
Missing challenge with name: missing\r\nforged log entry
```

The backslash notation above makes the control characters visible for the reader; it is not copied terminal output. In the real string, `\r\n` consists of a carriage return and line feed. The supplied validation record reports that the pre-fix malicious unit assertion failed for exactly this reason.

From the repository root, the focused unit regression can be run with the project's supported Node.js 24 runtime:

```sh
npx --yes node@24 \
  --import ./test/server/helpers/test-env.mjs \
  --import tsx \
  --test \
  --test-force-exit \
  --test-name-pattern=findChallengeByName \
  test/server/challengeUtils.unit.test.ts
```

The recorded post-patch result was 3 passed, 0 failed, with exit code 0. The route-level regression was run against an isolated disposable local application and recorded 4 passed, 0 failed, with exit code 0. Those results describe the uncommitted proposed fix, not the vulnerable revision and not a released version.

The decisive assertion is `assert.doesNotMatch(logArgument, /[\r\n]/)`. It fails whenever either line separator reaches `logger.warn`. The route-level test additionally requires status 200, while the neighbouring tests cover requests with no challenge, an unsolved challenge, and a solved challenge. No cleanup beyond stopping the disposable local application is required.

## Remediation

The application should preserve the original `challengeName` for lookup but convert CR and LF into safe output, or remove them, at the logging boundary. The current uncommitted proposal makes that narrow change in `lib/challengeUtils.ts`:

```ts
logger.warn('Missing challenge with name: ' + challengeName.replace(/[\r\n]/g, ''))
```

This prevents the two record separators reported by CodeQL from reaching the logger while leaving the return value, challenge matching, notification logic, and HTTP response unchanged. Escaping them as visible `\\r` and `\\n` would preserve more forensic information and would also satisfy the invariant, provided the logger receives no literal CR or LF from the attacker-controlled value.

The proposed unit coverage is appropriately centred on the sink and includes CR, LF, CRLF, repeated separators, a safe missing name, and an existing challenge. The proposed API test carries encoded CRLF through the public endpoint and preserves the HTTP 200 contract. After committing the fix, the project should run its lint, TypeScript, server/API, and Refactoring Safety Net checks, then rerun CodeQL on the fixed commit. Until that commit is analysed and a released tag containing it is inspected, the remediation should not be described as shipped and no fixed release should be claimed.

## Summary

From verified release `v2.26.0` through `v20.1.1` and the assessed post-`v20.1.1` branch revision, an unauthenticated caller can send encoded CR or LF characters to `GET /rest/repeat-notification`; an unmatched decoded value reaches `logger.warn` without neutralisation. The demonstrated impact is forged physical log lines and potential confusion of line-oriented log consumers, not code execution, authentication bypass, or data disclosure.

The uncommitted sink-level patch removes CR and LF only from the logged representation. Observed focused unit and local route-level runs show the regression tests pass while ordinary lookup and HTTP behaviour remain intact. The remaining validation step is to commit the patch, rerun the full applicable CI and CodeQL analysis, and identify the first release that actually ships the fix.
