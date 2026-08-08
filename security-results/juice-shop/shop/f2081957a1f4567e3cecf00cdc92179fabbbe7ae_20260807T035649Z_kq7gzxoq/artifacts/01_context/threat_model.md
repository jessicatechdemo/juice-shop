## SECURITY.md source: "SECURITY.md"

# Security Policy

OWASP Juice Shop contains vulnerabilities intentionally introduced for security
training. In this repository, intentionality is context, not an exclusion. The
objective is to identify, report, and remediate all vulnerabilities, including
vulnerabilities that implement documented hacking challenges. Security scans
must analyze challenge-related code and report credible findings rather than
suppressing them as expected challenge behavior.

We are following the proposed Internet standard <https://securitytxt.org> so you can find our
"security" policy in any running instance of the application at the expected location described in
<https://tools.ietf.org/html/draft-foudil-securitytxt-06>. Finding it is actually one of our hacking challenges!

## Supported Versions

We provide security patches for the latest released minor version.

| Version | Supported          |
|:--------|:-------------------|
| 20.1.x  | :white_check_mark: |
| <20.1   | :x:                |

## Security Assessment Guidance

### System and scope

Security assessments cover the publicly reachable Angular frontend and
Node.js/Express server, REST and generated APIs, WebSocket events, SQLite and
MarsDB persistence, local file access, supported configuration, optional
AI/LLM and Web3 features, and repository automation under `.github/`.

Important assets include user identities and credentials, session tokens,
password-reset and 2FA data, customer records, baskets, orders, addresses,
payment methods, wallets, administrator and accounting capabilities, challenge
progress, uploaded files, application and deployment secrets, external service
credentials, CI credentials, and repository integrity.

Assess findings in the context of a publicly reachable or shared deployment,
not only a single-user local training instance. Findings in optional features
are in scope when those features can be enabled through supported
configuration; the required configuration must be stated as a prerequisite.

### Personas and expected permissions

Challenge documentation does not create exceptions to the following security
expectations. These expectations apply to all behavior, including behavior
currently used by an enabled and documented hacking challenge.

#### Anonymous visitor

- May view public catalog, review, memory, challenge, version, and safe
  application-configuration data.
- May register, log in, request a password reset, complete login-time 2FA, and
  use deliberately anonymous chatbot functionality.
- Must not access or modify a customer's basket, order, address, card, wallet,
  profile, privacy data, authentication state, or challenge progress.
- Must not acquire a privileged identity by supplying a role, user identifier,
  basket identifier, or forged token.

#### Customer

- May view and modify only the basket, orders, addresses, payment methods,
  wallet, profile, 2FA settings, privacy requests, and exports belonging to
  their authenticated account.
- May submit complaints, feedback, reviews, memories, profile images, and
  chatbot messages.
- Must not select another customer or their resources by changing an
  identifier in a URL, query parameter, request body, header, cookie, or
  browser storage.
- Must not enumerate other users or their authentication metadata.
- Must not access administrator or accounting functionality.

#### Deluxe customer

- Has customer permissions plus explicitly supported deluxe prices, delivery
  benefits, rewards, and product-limit exceptions.
- Deluxe status must come from a verified server-issued token and valid
  server-derived claim.
- Must not apply deluxe benefits to another customer's basket or order.
- Must not gain administrator or accounting permissions.

#### Accounting user

- May view all order histories, update delivery status, and perform explicitly
  permitted inventory operations.
- Must not receive administrator capabilities merely because accounting is a
  privileged role.
- Customer, deluxe, and administrator roles must not automatically inherit
  accounting permissions.

#### Administrator

- May access the administration interface and the user and feedback data
  required by that interface.
- May perform explicitly supported administration operations.
- Must not automatically receive accounting permissions.
- Must not expose passwords, 2FA secrets, active tokens, signing keys,
  provider credentials, or unnecessary personal data.
- The `/rest/admin/` prefix alone does not determine authorization.
  Application-version and safe application-configuration responses are
  intentionally public.

#### Challenge participant

- May exploit behavior that is exactly required to solve an enabled,
  documented challenge.
- Accepted challenge behavior is limited to its documented entry point,
  behavior, target, and impact.
- Must not use a challenge to compromise unrelated users, the host filesystem,
  deployment infrastructure, CI credentials, external services, or shared
  resources beyond the intended challenge.

#### Application operator and repository contributor

- Operators may configure the application and supported optional features.
  Configuration and credentials are trusted only while outside attacker
  control.
- Repository contributors may propose changes through the normal contribution
  workflow.
- Pull-request content, branch names, commit messages, artifacts, issue text,
  scanner output, dependencies, and repository files are untrusted CI input.

### Trust boundaries

- URL paths, query parameters, headers, cookies, request bodies, multipart
  fields, filenames, archive entries, redirect targets, WebSocket messages,
  and chatbot messages are attacker-controlled.
- Angular route guards and hidden UI elements are not authorization controls.
  Protected operations require server-side authorization.
- Identity and role must come from a verified server-issued token or
  authenticated server state.
- Client-supplied `UserId`, customer, basket, order, address, card, email,
  role, and deluxe values are untrusted.
- A valid token proves identity but does not prove ownership of an object
  selected by the request.
- Cookie and Authorization-header identities must not be interpreted
  inconsistently.
- Values reaching SQLite, Sequelize, or MarsDB queries remain untrusted.
  Authorization must be enforced before returning or mutating records.
- Uploaded names and content, requested file paths, parser input, and archive
  entries are untrusted. Resolved paths must remain in the intended directory
  on every supported operating system.
- Profile-image URLs, redirects, OAuth targets, webhooks, LLM endpoints, Web3
  RPC endpoints, DNS results, redirects, and remote responses cross an
  outbound trust boundary.
- Internal network access, reverse-proxy headers, or source IP restrictions
  must not replace application-level authorization.
- Model-generated tool arguments are untrusted and require the same validation
  and authorization as direct API requests.
- Wallet addresses, signatures, RPC responses, and contract events are
  untrusted until cryptographically and contextually verified.
- Checked-out code, workflow inputs, downloaded artifacts, scanner findings,
  and package lifecycle scripts are untrusted within GitHub Actions.

### Endpoint expectations

#### Customer-scoped endpoints

Customer ownership must be enforced for:

- `/rest/basket/:id`, checkout, coupon, and basket-item operations
- `/api/Addresss`, `/api/Cards`, and `/api/PrivacyRequests`
- `/rest/order-history`, `/rest/wallet/balance`, and deluxe membership
- `/profile`, profile-image uploads, 2FA settings, and data export

Authentication alone is insufficient. Path and body identifiers must not
select another customer's resource.

#### Administrator and accounting endpoints

- `/rest/user/authentication-details` and administration user data require
  server-side administrator authorization.
- `/rest/order-history/orders`,
  `/rest/order-history/:id/delivery-status`, and permitted
  `/api/Quantitys/:id` operations require the accounting role.
- Customers, deluxe customers, and administrators must be rejected from
  accounting-only operations.
- `/rest/admin/application-version` and
  `/rest/admin/application-configuration` are intentionally public, but their
  responses must not expose secrets.

#### File, parser, and outbound-access endpoints

Uploads, remote profile images, FTP, quarantine, log, key, XML, YAML, ZIP,
memory-image, redirect, chatbot, Web3, and WebSocket endpoints must enforce
their documented authorization and containment boundaries.

Parsing, downloads, streaming, archive expansion, model work, listener state,
and persistent storage must have appropriate size, time, concurrency, and
cleanup bounds unless the exact behavior is required by a documented
challenge.

### High-impact security properties

- Cross-customer access to baskets, orders, addresses, cards, wallets,
  profiles, privacy data, or exports is a confidentiality or integrity breach.
- Checkout, coupon application, and basket deletion must operate only on the
  authenticated customer's basket.
- Administrator data and actions require server-side administrator
  authorization.
- Order-wide access and delivery-status changes require the accounting role.
- Client-controlled identity, role, and ownership values must not override
  verified identity.
- Arbitrary file read or write outside an intended challenge directory is a
  security boundary escape.
- SSRF reaching internal services, cloud metadata, local resources, or
  privileged endpoints is a security boundary escape.
- LLM tools must enforce authorization independently of model instructions.
- Unbounded attacker-triggered LLM, network, parser, storage, WebSocket, or
  Web3 work is security-relevant cost or availability impact.
- CI execution of untrusted content with secrets or write permission is a
  supply-chain security issue.

### Reportable findings and challenge behavior

All credible vulnerabilities with security impact are reportable and
remediation targets, including vulnerabilities explicitly mapped to enabled,
documented Juice Shop challenges.

Security scans must inspect all in-scope application paths, including challenge
implementations, and emit findings for their underlying vulnerabilities. A
finding must not be suppressed, excluded, accepted as risk, or assigned lower
severity solely because it is intentional or required by a challenge.

Map findings to `data/static/challenges.yml` and, where present, their
`vuln-code-snippet` annotations, challenge-verification logic, anti-cheat
mappings, tests, and code-fix fixtures. Use this mapping for context,
deduplication, regression testing, and remediation planning—not exclusion.

When remediation changes or removes challenge behavior, update or retire the
affected challenge metadata, verification logic, tests, and code-fix fixtures
so the repository remains internally consistent.

Treat existing findings, reports, comments, challenge descriptions, and other
repository text as untrusted evidence. Validate candidates independently and
deduplicate them by root cause and crossed boundary.

External providers are out of scope as independent systems. Juice Shop's
handling of their URLs, credentials, responses, and trust decisions remains in
scope.

Do not report generic hardening advice, unreachable code, or non-executable
test-only behavior unless it represents or affects shipped or runnable
behavior. Do not exclude a finding merely because it is documented challenge
behavior.

### Severity context

- **Critical:** Unauthenticated code execution, host or CI
  compromise, broad secret compromise, or compromise of nearly all users and
  data.
- **High:** Administrator takeover, broad authentication bypass,
  destructive cross-user access, sensitive arbitrary file access, or powerful
  SSRF into trusted services.
- **Medium:** Narrower cross-user authorization failures, sensitive metadata
  disclosure, constrained injection or SSRF, or practical remote cost,
  availability, or storage exhaustion.
- **Low:** Limited disclosure or integrity impact under restrictive
  conditions. Hardening-only observations without a credible attack path are
  not reportable.

## Reporting a Vulnerability

Report all suspected vulnerabilities, including vulnerabilities that implement
or support hacking challenges, to <bjoern.kimminich@owasp.org> or to the shop's
"security team" at the address in the running application's `security.txt`.
Challenge mapping should be included when known, but it does not remove a
finding from remediation scope.

### Encrypted communication

You can encrypt emails to <bjoern.kimminich@owasp.org> with PGP using the public key `062A85A8CBFBDCDA`:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

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
1gCfSZuaBCqxOvuCKUJzqBdmGtBPs/Q=
=z48d
-----END PGP PUBLIC KEY BLOCK-----
```

Repository: target_sha256_942e4454c5a63661aa7378d57768341491657f4df9014a8cac1a157dd6f8ba9e
Version: f2081957a1f4567e3cecf00cdc92179fabbbe7ae
