# Flask AppSec Lab 🔐

[![CI](https://github.com/koushikchowdary6/flask-appsec-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/flask-appsec-lab/actions/workflows/ci.yml)

A hands-on web-security lab built with Flask. Every vulnerability is shown
**twice** — an exploitable `/vuln/...` route and a fixed `/secure/...` route
with identical functionality — so the difference is visible in the code, not
just described. An automated regression suite proves each vulnerability is
real on the `/vuln` side and actually closed on the `/secure` side.

> ⚠️ The `/vuln/*` routes are intentionally insecure. Run this only on
> `127.0.0.1`. Never deploy it to a network anyone else can reach.

## Vulnerability classes covered

| Class | Vulnerable route | Secure route | The fix |
|---|---|---|---|
| SQL Injection | `POST /vuln/login` | `POST /secure/login` | Parameterized query instead of string interpolation |
| Reflected XSS | `GET /vuln/search?q=` | `GET /secure/search?q=` | `markupsafe.escape()` on reflected input |
| IDOR (broken access control) | `GET /vuln/note/<id>` | `GET /secure/note/<id>` | Ownership check scoping the query to the session user |
| Cross-site request forgery (CSRF) | `POST /vuln/note/<id>/edit` | `POST /secure/note/<id>/edit` | Unpredictable session-bound form token checked with constant-time comparison |

**Authentication isolation:** The intentionally injectable /vuln login and the
/secure login use separate session identities. Exploiting /vuln/login cannot
unlock /secure/note/<id>, and signing in to /secure does not implicitly
log in to /vuln. This prevents the teaching lab's vulnerable authentication
path from undermining the fixed authorization example.

**Sensitive-response caching:** The secure login, private-note, and note-edit routes
return `Cache-Control: no-store` (including unsuccessful responses), reducing
the risk of credentials or private notes being retained in browser or
intermediary HTTP caches. The public search endpoint and intentionally
vulnerable demonstration routes remain unchanged for comparison. This is
defense in depth, not a substitute for proper authorization.

The secure login also demonstrates two extra hardening steps: `session.clear()`
on login to prevent session fixation, and sourcing the Flask secret key from
the environment instead of a hardcoded value.

## Security regression coverage

The repository keeps exploit behavior and remediation behavior in separate,
readable tests rather than treating security as a manual demo:

- `tests/test_sqli.py` verifies the injection payload succeeds against the
  vulnerable login and is rejected by the parameterized secure path.
- `tests/test_xss.py` checks raw reflected markup on the vulnerable route and
  escaped output on the secure route.
- `tests/test_idor.py` verifies cross-user note access is possible only through
  the intentionally vulnerable handler, and that /vuln authentication cannot
  authorize /secure note access.
- `tests/test_csrf.py` demonstrates a forged note edit on the vulnerable route, rejects missing/stale/cross-session tokens on the secure route, and verifies legitimate edits and ownership checks.
- `tests/test_security_headers.py` checks browser-facing hardening headers so
  response-level protections cannot silently disappear during refactoring.

This structure makes the lab useful as a small AppSec regression harness: a
future change that reopens one of the demonstrated weaknesses should break CI
instead of relying on a reviewer to notice it manually.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python run.py            # serves on http://127.0.0.1:5000
```

## Run the tests

```bash
python -m pytest tests/ -v
```

The suite asserts both directions for each demonstrated class — for example,
that `' OR '1'='1' --` logs in on `/vuln/login` and is rejected on
`/secure/login` — and separately covers security headers.

## Exploit walkthroughs

**SQL injection.** `POST /vuln/login` with username `' OR '1'='1' --` and any
password logs you in as the first user, because the input is concatenated
directly into the `WHERE` clause. `/secure/login` binds the same input as a
parameter, so it is treated as a literal (nonexistent) username.

**Reflected XSS.** `GET /vuln/search?q=<script>alert(document.cookie)</script>`
reflects the script into the page unescaped. `/secure/search` escapes it, so it
renders as inert text.

**IDOR.** Log in as `alice` / `alice-password-1`, then request `/vuln/note/1`
to read the admin's private note — the handler never checks ownership.
`/secure/note/1` returns 404 for alice because the query is scoped to her own
user id.

**CSRF.** Sign in as `alice` and submit `POST /vuln/note/2/edit`
with `body=forged`: the edit succeeds without a form token, even if the
request came from a different site. On the secure side, first visit
`GET /secure/note/2/edit` to obtain the session-bound hidden
`csrf_token`, then submit that token with the `body`. A missing,
invalid, stale, or cross-session token returns 403 without updating the
note. Both edit routes check note ownership so the paired example isolates
CSRF from the separate IDOR demonstration. The vulnerable half is an
educational simulation, not a safe service to expose.

## Demo credentials

| Username | Password | Notes |
|---|---|---|
| `admin` | `S3cure-Admin-Pw!` | owns note 1 (the "secret") |
| `alice` | `alice-password-1` | owns note 2 |

(These live only in a local demo SQLite DB that is regenerated on startup.)

## Mapping

Each class maps to OWASP Top 10 (2021) and CWE: SQLi → A03 / CWE-89,
XSS → A03 / CWE-79, IDOR → A01 / CWE-639.

## Author

Koushik Chowdary — [LinkedIn](https://linkedin.com/in/koushik-chowdary) · [GitHub](https://github.com/koushikchowdary6)
