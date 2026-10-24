# Security Testing Strategy

This lab treats each vulnerability as a paired regression test: the same attacker-controlled input is exercised against an intentionally vulnerable route and its remediated counterpart. The goal is to demonstrate not only that an exploit exists, but that the specific engineering control closes it without changing the intended application behavior.

## Test invariant

For every vulnerability class, the suite should prove both sides:

1. **Exploitability:** a representative malicious input succeeds against `/vuln/*`.
2. **Remediation:** the same input fails safely against `/secure/*`.
3. **Expected behavior:** legitimate use of the secure route still works.

This structure avoids a common weakness in security demos where a README describes a fix but no automated test proves the regression is closed.

## Current coverage

| Vulnerability | Attack property under test | Security control |
|---|---|---|
| SQL injection | User input changes SQL query semantics | Parameterized SQL binding |
| Reflected XSS | Attacker-controlled markup is emitted as executable HTML | Output escaping with `markupsafe.escape()` |
| IDOR / broken access control | Authenticated user reads another user's object by changing an identifier | Object lookup scoped to the authenticated owner |
| CSRF on note editing | A logged-in user can be induced to POST an edit without a request token | Per-session unpredictable token, validated before updating the owned note |

The login path also clears the existing session before establishing the authenticated session, reducing session-fixation risk, and reads the Flask secret from the environment instead of embedding a production-style secret in source.

## Why paired tests matter

A passing "secure" test alone can be misleading: the payload might be malformed or the vulnerable condition might never have existed. Requiring the corresponding vulnerable route to demonstrate the exploit validates the test itself. Conversely, an exploit demonstration without a remediation assertion proves only offensive behavior. The pair gives a small but auditable red/green security regression loop.

## What this lab does not claim

This is an educational local application, not a complete web application security assessment. The suite does not currently cover SSRF, file upload abuse, deserialization, rate limiting, dependency vulnerabilities, browser CSP behavior, or production deployment hardening. The CSRF example uses session-bound form tokens but does not claim complete protection for every state-changing route or deployment configuration. It also does not replace DAST/SAST/SCA or manual penetration testing.

## Next useful extensions

High-value additions would be:

- Stored XSS to complement reflected XSS.
- Authentication rate limiting and lockout tests.
- Security-header assertions for a production-oriented configuration.
- A small DAST job against the local lab in CI, kept isolated from public deployment.

The design principle should remain the same: every added weakness needs a reproducible exploit assertion and a corresponding remediation assertion.