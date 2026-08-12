# Third-party components

## Bundled code

**None.** pima vendors no libraries. There is no JavaScript framework, no
charting library and no CDN reference anywhere in `pima.php` — the dashboard
charts are plain HTML and CSS, and the logos are inline SVG. Everything in this
repository other than the files listed below is original work, licensed under
the terms in `LICENSE`.

The only runtime requirements are PHP with the `sqlite3` extension, and
`mbstring` for the tracker's string truncation.

## Outbound network calls

One, and it is optional.

| Service | Endpoint | Purpose | Switch |
|---|---|---|---|
| IPWhois.io | `https://ipwho.is/<ip>?fields=success,country_code` | Maps a visitor IP to a two-letter country code | `GEO_ENABLED` in `pima-core.php` |

What this means in practice:

- The call happens in `pima-tracker.php`, server-side. Visitors' browsers never
  contact IPWhois.io, so no third party can set a cookie through this path.
- The visitor's IP address **is** transmitted to IPWhois.io over HTTPS to resolve
  it. That is the entire purpose of the call, and it is the one place where a
  visitor IP leaves the server. pima itself never stores it.
- Results are cached for 7 days in `pima-cache/.geo_cache.json`. Cache keys are
  HMAC digests generated with a local random secret; raw IP addresses are not
  written to the cache.
- The request has a 1-second timeout and fails silently. If IPWhois.io is slow,
  rate-limited or unreachable, the hit is still recorded — just without a country.
- Setting `GEO_ENABLED` to `false` disables the call completely. pima then
  makes no outbound requests at all, and the country column stays empty.

IPWhois.io's own terms and privacy policy apply to that request:
https://ipwhois.io/terms · https://ipwhois.io/privacy

**Note for privacy policies.** The wording suggested in `pima-AGENT.md` states
that no data is passed to third parties only when `GEO_ENABLED` is `false`.
If country detection is left on, the privacy policy of the tracked site should
disclose the IP lookup and name the provider.

## Data pima stores

For completeness, since it is the usual follow-up question: `pima-cache/analytics.db`
holds one row per pageview with the date, time, page path, page title, external
referrer host, entry marker, device class, country code, browser language, and a visitor hash. The hash is
`sha256(daily-random-salt + date + truncated-IP + user-agent)`, cut to 12
characters; the daily salt file is deleted after two days, which makes the hash
unlinkable across days and non-reversible afterwards. Raw IP addresses are never
written to the database. Tracker rate-limit files and the Geo cache also use
keyed digests instead of IP addresses.

IPv4 addresses are reduced to a `/24` and IPv6 addresses to a `/64` before they
enter the daily visitor hash. Rows older than `DATA_RETENTION_DAYS` are removed
automatically; the shipped default is 365 days.
