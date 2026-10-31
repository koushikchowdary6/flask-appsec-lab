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
| SQL Injection | `POST /vuln/login` | `POST /secure/login` | Parameterized username lookup and salted password-hash verification |
| Reflected XSS | `GET /vuln/search?q=` | `GET /secure/search?q=` | `markupsafe.escape()` on reflected input |
| IDOR (broken access control) | `GET /vuln/note/<id>` | `GET /secure/note/<id>` | Ownership check scoping the query to the session user |
| Cross-site request forgery (CSRF) | `POST /vuln/note/<id>/edit` | `POST /secure/note/<id>/edit` | Unpredictable session-bound form token checked with constant-time comparison |

**Authentication isolation:** The intentionally injectable /vuln login and the
/secure login use separate session identities. Exploiting /vuln/login cannot
unlock /secure/note/<id>, and signing in to /secure does not implicitly
log in to /vuln. This prevents the teaching lab's vulnerable authentication
path from undermining the fixed authorization example.

**Bounded secure note edits:** The hardened `/secure/note/<id>/edit` POST
limits the total form body to 16 KiB before Werkzeug parses it and rejects
note text longer than 10,000 characters with HTTP 413. It also
rejects duplicate CSRF tokens or duplicate note-body form parameters instead
of silently selecting one value, and rejects a missing body. This avoids
ambiguous HTTP parameter pollution on state-changing requests. Oversized or
ambiguous requests do not overwrite existing notes. The hardened edit form
also stores a SHA-256 digest of its CSRF token in SQLite, scoped to the
authenticated user **and target note**, expiring after 24 hours. A token
issued for one owned note cannot authorize edits to a different owned note.
Opening a form for another note issues a fresh session token. A successful
edit consumes the database token and updates the note in **one transaction**,
so replaying
an older valid signed session cookie cannot repeat that particular edit.
Rejected edits preserve an unexpired token; request a fresh form after a
successful edit or expiry. Regression tests cover cookie replay, multiple
clients sharing a cookie, expiry, and invalid-body handling. This is
server-enforced one-time form-token use, **not** session revocation: stolen
authenticated cookies can still be used to request fresh forms. Existing
local demo databases created before note-scoped tokens are upgraded at app
startup: the old, unscoped token table is replaced, invalidating outstanding
edit forms **without deleting users or notes**. Reopen the form to get a fresh
token. This is not a general-purpose database migration framework or a
complete production CSRF/session-management system.
The `/vuln` teaching route intentionally retains its unbounded edit behavior
for comparison; neither route is safe to expose outside localhost.

**Bounded secure search:** The hardened `/secure/search` checks the raw query
string before URL parameter parsing and returns HTTP 414 above 4 KiB. This
limits reflection and parsing work for oversized requests; the intentionally
vulnerable `/vuln/search` remains unchanged for side-by-side comparison.

**Cross-origin form-post checks:** The secure blueprint rejects browser POSTs
whose `Origin` differs from the request's scheme, host and effective port,
or whose `Sec-Fetch-Site` indicates a cross-site or same-site (but
cross-origin) request. This applies to login as well as note edits and rejects
malformed or opaque (`null`) origins. Same-origin browser forms and legacy
clients without these headers remain usable. The checks are **defense in
depth, not full login-CSRF protection**: non-browser clients can omit or forge
these headers, and a browser that sends neither header is not covered.
The note-edit endpoint still requires its independent, database-backed,
one-time CSRF token. Regression tests ensure rejected cross-origin requests
do not authenticate users or consume legitimate edit tokens.

**Strict Fetch Metadata handling:** When `Sec-Fetch-Site` is present on a
secure POST, only the standard `same-origin` and `none` values are
accepted. `same-site`, `cross-site`, unknown, case-altered, and combined
values are rejected rather than silently bypassing the browser-origin check.
Legacy requests with no Fetch Metadata remain supported; this is defense in
depth and cannot authenticate a non-browser client.

**Secure form-target hardening:** The secure routes send a Content Security
Policy with `form-action 'self'` and `base-uri 'none'`, in addition to the
existing frame and script restrictions. These directives constrain where
secure login/edit forms can submit and prevent injected HTML `<base>` tags
from rewriting relative URLs. Regression tests cover successful and rejected
secure responses. This is browser defense in depth, not a replacement for
CSRF validation or HTML escaping; the vulnerable teaching routes remain
intentionally unchanged.

**Sensitive-response caching:** Every `/secure` route now returns
`Cache-Control: no-store`, including reflected search results, private notes,
login forms, and rejected requests. Search query values may contain
identifiers or secrets inadvertently pasted into a URL; no-store reduces
retention of response bodies in browser and intermediary HTTP caches.
It does **not** erase query URLs from browser history or server/proxy logs.
The intentionally vulnerable `/vuln` demonstration routes retain their
original caching behavior for comparison. This is defense in depth, not a
substitute for proper authorization or safe handling of sensitive query data.

**Password storage in the paired lab:** The secure login verifies a salted
Werkzeug password hash rather than comparing a plaintext password in SQL.
For the isolated SQL-injection demonstration only, the same local demo database
still contains a plaintext `password` column used by `/vuln/login`.
This deliberate teaching compromise means the application is **not**
production-ready; do not reuse its database design or demo credentials.

The secure login performs dummy password-hash verification for unknown users
to reduce account-existence timing differences, and rejects malformed stored
hashes with HTTP 401 instead of an unhandled error. This is **not** a claim
of constant-time authentication or brute-force protection.

The secure login also demonstrates session rotation with `session.clear()`
and signed-cookie integrity. Without `FLASK_SECRET_KEY`, each app instance
creates a fresh cryptographically random signing key instead of using a
publicly known development fallback (which would allow session forgery).
Set a strong, private `FLASK_SECRET_KEY` in the environment when sessions
must persist across restarts or multiple workers. Otherwise, restarting the
local lab invalidates existing sessions. This does **not** make the intentionally
vulnerable routes safe to deploy.

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
- `tests/test_secure_password_hashing.py` verifies salted hashes, password-column isolation, and rejection of tampered hashes.
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
