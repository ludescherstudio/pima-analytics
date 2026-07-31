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
| ip-api.com | `http://ip-api.com/json/<ip>?fields=countryCode` | Maps a visitor IP to a two-letter country code | `GEO_ENABLED` in `pima-core.php` |

What this means in practice:

- The call happens in `pima-tracker.php`, server-side. Visitors' browsers never
  contact ip-api.com, so no third party can set a cookie or fingerprint them
  through this path.
- The visitor's IP address **is** transmitted to ip-api.com in order to resolve
  it. That is the entire purpose of the call, and it is the one place where a
  visitor IP leaves the server. pima itself never stores it.
- Results are cached per IP for 7 days in `pima-cache/.geo_cache.json`, so a
  returning visitor triggers no further lookup.
- The request has a 1-second timeout and fails silently. If ip-api.com is slow,
  rate-limited (free tier: 45 requests/minute) or unreachable, the hit is still
  recorded — just without a country.
- Setting `GEO_ENABLED` to `false` disables the call completely. pima then
  makes no outbound requests at all, and the country column stays empty.

ip-api.com's own terms and privacy policy apply to that request:
https://ip-api.com/docs/legal

**Note for privacy policies.** The wording suggested in `pima-AGENT.md` states
that no data is passed to third parties. That is accurate only with
`GEO_ENABLED` set to `false`. If country detection is left on, the privacy
policy of the tracked site should disclose the IP lookup and name the provider.

## Data pima stores

For completeness, since it is the usual follow-up question: `pima-cache/analytics.db`
holds one row per pageview with the date, time, page path, page title, referrer,
device class, country code, browser language, and a visitor hash. The hash is
`sha256(daily-random-salt + date + truncated-IP + user-agent)`, cut to 12
characters; the daily salt file is deleted after two days, which makes the hash
unlinkable across days and non-reversible afterwards. Raw IP addresses are never
written to the database.

The IP truncation zeroes the final octet of an IPv4 address (`1.2.3.4` →
`1.2.3.0`). An IPv6 address does not match that pattern and therefore enters the
hash in full — still salted, still discarded with the salt after two days, but
without the extra coarsening its IPv4 counterpart gets.
