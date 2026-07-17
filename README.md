# Flask AppSec Lab 🔐

[![CI](https://github.com/koushikchowdary6/flask-appsec-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/flask-appsec-lab/actions/workflows/ci.yml)

A hands-on web-security lab built with Flask. Every vulnerability is shown
**twice** — an exploitable `/vuln/...` route and a fixed `/secure/...` route
with identical functionality — so the difference is visible in the code, not
just described. An automated test suite proves each vulnerability is real on
the `/vuln` side and actually closed on the `/secure` side.

> ⚠️ The `/vuln/*` routes are intentionally insecure. Run this only on
> `127.0.0.1`. Never deploy it to a network anyone else can reach.

## Vulnerability classes covered

| Class | Vulnerable route | Secure route | The fix |
|---|---|---|---|
| SQL Injection | `POST /vuln/login` | `POST /secure/login` | Parameterized query instead of string interpolation |
| Reflected XSS | `GET /vuln/search?q=` | `GET /secure/search?q=` | `markupsafe.escape()` on reflected input |
| IDOR (broken access control) | `GET /vuln/note/<id>` | `GET /secure/note/<id>` | Ownership check scoping the query to the session user |

The secure login also demonstrates two extra hardening steps: `session.clear()`
on login to prevent session fixation, and sourcing the Flask secret key from
the environment instead of a hardcoded value.

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

The suite (8 tests) asserts both directions for every class — for example,
that `' OR '1'='1' --` logs in on `/vuln/login` and is rejected on
`/secure/login`.

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
