# Security policy

pima ships an authenticated dashboard and a public tracking endpoint that
writes into a local SQLite database. Security reports are genuinely welcome.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's **private vulnerability reporting** (Security → Report a
vulnerability) on this repository. If that is unavailable, reach the maintainer
via https://ludescher.studio.

Please include: affected file/function, PHP version, and a minimal
reproduction. A short proof-of-concept is worth more than a description.

Expect a first response within a few days. This is a small project maintained
alongside client work — timelines are best-effort, not contractual.

## Scope

**In scope**

- Bypassing the dashboard login, its CSRF protection, or its per-IP lockout
- Reading `analytics.db` — or any `pima-cache/` file — over HTTP on a server
  that has the documented `.htaccess` in place
- SQL injection through any tracker parameter (`p`, `r`, `title`) or through
  a dashboard filter
- Stored XSS: a value recorded by `pima-tracker.php` that executes when the
  dashboard renders it. The tracker accepts visitor-controlled strings, so
  this is the most interesting surface in the project
- CSV injection surviving the export (`=`, `+`, `-`, `@`, including leading
  whitespace, are neutralised at write and export time — a bypass is a bug)
- De-anonymising a visitor from stored data. pima stores no IP addresses; the
  visitor hash is salted per day and the salt is discarded after two days.
  Geo-cache and rate-limit keys are keyed digests, never raw IPs

**Out of scope**

- A site running the shipped default password (`change-me-please`). The
  dashboard shows a permanent red warning banner on both the login screen and
  the dashboard for exactly this; changing it is step one of every install.
- Fake pageviews injected by someone who read `TRACKER_TOKEN` out of a page's
  HTML source. The token is embedded in every tracked page and is therefore
  **public by design** — it raises the bar against drive-by noise, nothing
  more. It authorises *writing* hits, never *reading* the dashboard.
  Rate limiting reduces abuse volume but cannot make a public token secret.
- Missing `.htaccess` hardening. Denying web access to `pima-core.php` and
  `pima-cache/` is a documented install step (see `pima-AGENT.md`, Step 6), and
  on Nginx an equivalent `deny` rule is required. A server that skips it is a
  deployment issue, not a pima bug.
  **In scope, however, is a shipped rule that does not do what it claims** — if
  the documented pattern fails to block a file the docs say it blocks, that is
  a pima bug.
- Anything requiring an already-compromised dashboard password.
- Country lookups being wrong or absent. `GEO_ENABLED` calls a third-party
  service best-effort (see `THIRD-PARTY.md`); it is not a security boundary.
- Self-XSS, or missing security headers on the customer's own site.

## Hardening checklist for operators

- Set a strong `STATS_PASSWORD`. `password_hash()` output is supported and
  preferred — pima detects it automatically by the leading `$`.
- Verify that `.htaccess` actually denies `pima-core.php` (it holds the
  password and the tracker token) by requesting `/pima-core.php` in a browser
  and confirming a 403 rather than a blank page.
- Verify that `pima-cache/` is blocked by requesting
  `/pima-cache/analytics.db` and confirming a 403. A blank page or a download
  both mean the rule is not doing its job.
- Serve the dashboard over HTTPS — session cookies only get the `secure` flag
  when the request is HTTPS.
- Leave `TRUST_PROXY` off unless a trusted reverse proxy really does sit in
  front of the site, and list every permitted proxy address in
  `TRUSTED_PROXY_IPS`. The login lockout always keys on `REMOTE_ADDR`.
- Review `DATA_RETENTION_DAYS`; the shipped default removes rows after 365 days.
- Leave `ADVANCED_MODE` off in normal operation. It enables the Danger Zone,
  which clears the whole database in one click.
