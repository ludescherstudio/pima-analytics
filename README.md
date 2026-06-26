<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/pima_dark_logo.svg">
    <img src="assets/pima_light_logo.svg" height="52" alt="pima Analytics">
  </picture>
</p>

> *Pima* (Swahili) — to measure, to assess.
> **pima Analytics** does exactly that: it measures your website traffic. No cloud. No complexity. Just your data, on your hosting.

**Cookie-free, GDPR-compliant website analytics for PHP shared hosting.**

No Node.js. No Docker. No external database. No cookies. No consent banner.
Just upload four files, add a few lines to your existing `.htaccess` and `robots.txt`, paste one snippet — done.

Designed for beginners — if you can upload files via FTP and edit a text file, you can run pima Analytics. Works on any website: static HTML, WordPress, or any PHP-based site.

---

## Why pima Analytics?

| | pima Analytics | Matomo | Plausible | Google Analytics |
|---|---|---|---|---|
| No cookies | ✅ | ⚠️ | ✅ | ❌ |
| No external database | ✅ | ❌ MySQL | ❌ PostgreSQL + ClickHouse | ❌ |
| Shared hosting | ✅ | ⚠️ | ❌ requires Docker | ✅ |
| Self-hosted | ✅ | ✅ | ✅ | ❌ |
| Install time | ~5 min | 30+ min | 1–2h | 5 min |

---

## Screenshots

<p align="center">
  <a href="assets/screenshot_1.webp"><img src="assets/screenshot_1.webp" alt="pima Analytics dashboard — overview" width="49%"></a>
  <a href="assets/screenshot_2.webp"><img src="assets/screenshot_2.webp" alt="pima Analytics dashboard — details" width="49%"></a>
</p>

---

## What's in this repository

Only the four files you actually need:

```
pima.php             ← Dashboard (served at /pima and /analytics)
pima-tracker.php     ← Tracking pixel endpoint
pima-core.php        ← Configuration (passwords, branding, timezone)
pima-cache/
└── .htaccess        ← Blocks direct access to the SQLite database
```

No `.htaccess` in the project root, no `robots.txt`. You almost certainly already have both — the instructions below show exactly which lines to add to your existing files.

The repository also includes [`pima-AGENT.md`](pima-AGENT.md) — an optional install guide for AI coding agents (see [Installation](#installation)).

> **Downloaded the whole repository?** Only `pima.php`, `pima-tracker.php`, `pima-core.php` and `pima-cache/` need to go on your server. Everything else — `README.md`, `LICENSE`, `pima-AGENT.md`, `.gitignore` and the `assets/` folder — is just for GitHub and can be deleted from your web root. The dashboard logos are embedded directly in `pima.php`, so `assets/` is not needed at runtime.

---

## Installation

> **Using an AI coding agent?** If you work with an AI agent that can edit your project (Claude Code, Cursor, Copilot, …), you don't have to follow the steps manually. Copy the pima files into your project, then prompt:
>
> > Read `pima-AGENT.md` and install pima into this site.
>
> The agent configures `pima-core.php`, inserts the tracking snippet into your footer, and updates your `.htaccess` and `robots.txt` for you — following the included [`pima-AGENT.md`](pima-AGENT.md) guide. Prefer to do it yourself? Just follow the manual steps below.

### Step 1 — Upload the files

Upload all four files to your web root via FTP, keeping the structure intact:

```
your-webroot/
├── pima.php
├── pima-tracker.php
├── pima-core.php
└── pima-cache/
    └── .htaccess
```

Make sure `pima-cache/` is writable by PHP (permissions `0750` on most shared hosts). The SQLite database is created automatically on the first page view.

### Step 2 — Set your passwords, timezone and language

Open `pima-core.php` and edit these lines:

```php
// --- Auth ---
define('STATS_PASSWORD', 'your-dashboard-password');

// --- Tracker token ---
define('TRACKER_TOKEN', 'my-secret-word');

// --- Timezone ---
define('TIMEZONE', 'Europe/Vienna'); // full list: php.net/timezones

// --- Language ---
define('LANG', 'en'); // 'en' = English, 'de' = German
```

> **Why two passwords?**
> The **tracker token** appears in every tracked page's HTML source — anyone can see it. It only allows *writing* hits, not reading your dashboard. Your **dashboard password** stays completely secret and is never exposed in your code.
>
> **Important:** Use a different value for the tracker token than any of your existing passwords — since it's visible in your source code, treat it as a public identifier, not a secret.

### Step 3 — Add two lines to your existing `.htaccess`

Your project root almost certainly already has a `.htaccess`. Open it and append this block at the end:

```apache
# pima analytics
RewriteEngine On
RewriteRule ^pima$       pima.php [L]
RewriteRule ^analytics$  pima.php [L]
<Files "pima-core.php">
    Require all denied
</Files>
Options -Indexes
```

What each line does:

| Line | Purpose | Safe to skip if… |
|---|---|---|
| `RewriteEngine On` | Enables the rewrite rules below | …it already appears earlier in your file |
| `RewriteRule ^pima$ pima.php [L]` | Maps `/pima` → `pima.php` | Never — required for the dashboard URL |
| `RewriteRule ^analytics$ pima.php [L]` | Maps `/analytics` → `pima.php` | Never — required for the alternate URL |
| `<Files "pima-core.php">…</Files>` | Blocks web access to your password and token | Only if the same file is already denied elsewhere |
| `Options -Indexes` | Disables directory listings | …it already appears earlier |

> **Older Apache (2.2)?** Replace `Require all denied` with:
> ```apache
> Order Allow,Deny
> Deny from all
> ```

> **No `.htaccess` at all?** Create one in your web root with exactly the block above.

### Step 4 — Add four lines to your existing `robots.txt`

Your project root almost certainly already has a `robots.txt`. Open it and — inside the `User-agent: *` section — append:

```
Disallow: /pima
Disallow: /analytics
Disallow: /pima-tracker.php
Disallow: /pima-cache/
```

> **No `robots.txt` at all?** Create one in your web root with:
> ```
> User-agent: *
> Disallow: /pima
> Disallow: /analytics
> Disallow: /pima-tracker.php
> Disallow: /pima-cache/
> ```

### Step 5 — Add the tracking snippet

Replace `my-secret-word` with the value you set for `TRACKER_TOKEN` in Step 2.

**Static HTML sites**

Paste this snippet directly before the closing `</body>` tag of every page you want to track — or better, into your shared footer file (`footer.php`, `partials/footer.php`, `includes/footer.html`, …) so it appears on every page automatically.

```html
<script>
fetch('/pima-tracker.php?p=' + encodeURIComponent(location.pathname)
  + '&title=' + encodeURIComponent(document.title)
  + '&r=' + encodeURIComponent(document.referrer)
  + '&t=my-secret-word');
</script>
```

**WordPress**

Open **Appearance → Theme File Editor → functions.php** and paste this at the end of the file:

```php
function pima_tracker() { ?>
<script>
fetch('/pima-tracker.php?p=' + encodeURIComponent(location.pathname)
  + '&title=' + encodeURIComponent(document.title)
  + '&r=' + encodeURIComponent(document.referrer)
  + '&t=my-secret-word');
</script>
<?php }
add_action('wp_footer', 'pima_tracker');
```

This runs automatically on every page — no need to touch individual posts or templates.

> **Critical:** Never insert the snippet twice on the same rendered page (e.g. once in a shared footer *and* again on an individual page). Every hit would be double-counted.

### Done.

Open `yourdomain.com/pima` or `yourdomain.com/analytics` in your browser, enter your dashboard password, and watch your traffic come in.

### Step 6 — Make it yours (optional)

Open `pima-core.php` and adapt the dashboard to match your site:

```php
// --- Branding ---
define('BRAND_COLOR', '#0d9488'); // any hex color, e.g. '#c0392b' for red
define('BRAND_LOGO',  '');        // path or URL to your logo (see below)
define('BRAND_NAME',  'pima'); // change this to your site name
```

**Adding your logo:**

```php
// Option A — file on your server (recommended)
define('BRAND_LOGO', '/assets/logo.svg');

// Option B — full URL
define('BRAND_LOGO', 'https://yourdomain.com/assets/logo.png');
```

Supported formats: SVG, PNG, JPG, WebP. The logo appears centered above the summary sentence. Leave empty to show `BRAND_NAME` as text instead.

---

## Language

pima Analytics ships in English and German. Set your language in `pima-core.php`:

```php
define('LANG', 'en'); // 'en' = English, 'de' = German
```

**Adding your own language** takes about 5 minutes — open `pima.php`, find the `$strings` array, copy the `'en'` block, give it a new key (e.g. `'fr'`), translate the strings, and set `LANG` to `'fr'` in your config. All dashboard labels, tooltips, and messages will follow.

---

## Security

pima Analytics is designed to be reasonably secure out of the box for a self-hosted tool on shared hosting.

**What's protected:**
- `pima-core.php` is blocked from web access via `.htaccess` — no one can read your password from the browser
- `pima-cache/` is fully blocked — the SQLite database cannot be downloaded directly
- The login form has **brute-force protection**: after 5 failed attempts, the form locks out for 15 minutes (configurable in `pima-core.php`)
- After a successful login, the session ID is regenerated to prevent session fixation attacks
- All inputs to `pima-tracker.php` are safely bound using SQLite3 prepared statements to prevent SQL injection
- The **tracker token** (`TRACKER_TOKEN`) ensures only your own snippet can write hits — preventing fake data from being injected

**Important:** pima Analytics should only be used on sites with HTTPS. The login password is sent via POST — over plain HTTP it would be visible in transit. Most shared hosts provide free SSL — make sure it's active.

**Configuring lockout settings:**
```php
define('MAX_LOGIN_ATTEMPTS', 5);    // Failed attempts before lockout
define('LOCKOUT_SECONDS',    900);  // Lockout duration (900 = 15 minutes)
```

---

## Dashboard

- **Summary** — Monthly pageviews and estimated visitors at a glance
- **KPIs** — Total views, today, this week, this month (with week/month deltas)
- **14-day trend** — Daily bar chart
- **Top pages** — Ranked with week-over-week delta
- **Referrers** — Where your visitors come from
- **Entry pages** — First pages seen by visitors arriving from external sources
- **Browser language** — Language distribution of your visitors
- **Time of day** — When your visitors are most active
- **Device split** — Desktop / Mobile / Tablet
- **Countries** — Top countries
- **Recent hits** — Last 50 page views (collapsed by default)
- **CSV Export** — Download all your data anytime

---

## What gets tracked

| Field | Example | Notes |
|---|---|---|
| Date | `2026-04-15` | Server date |
| Time | `14:32:01` | Server time |
| Page | `/blog/hello-world` | URL path |
| Title | `Hello World — My Blog` | Human-readable page title |
| Referrer | `google.com` | Domain only |
| Device | `desktop` / `mobile` / `tablet` | Via User-Agent, never stored |
| Country | `AT` | Via IP lookup — IP itself never stored |
| Language | `de` | Primary language from `Accept-Language` header |

**Never stored:** IP address, cookies, fingerprint, user identity, browser details.

---

## Configuration reference

All settings in `pima-core.php`:

```php
define('STATS_PASSWORD',     'change-me');                           // Dashboard password
define('TRACKER_TOKEN',      'my-secret-word');                      // Second password for tracking snippet
define('TIMEZONE',           'Europe/Vienna');                       // php.net/timezones
define('LANG',               'en');                                  // 'en' or 'de'

define('BRAND_COLOR',        '#0d9488');                             // Any CSS hex color
define('BRAND_NAME',         'pima');                                     // Shown in header and browser tab
define('BRAND_LOGO',         '');                                    // Path to self-hosted logo image
define('DB_PATH',            __DIR__.'/pima-cache/analytics.db');    // SQLite database location
define('GEO_ENABLED',        true);                                  // Country lookup via ip-api.com
define('EXCLUDED_IPS',       []);                                    // Your own IPs to ignore
define('TRUST_PROXY',        false);                                 // Enable only behind a trusted CDN/proxy
define('MAX_LOGIN_ATTEMPTS', 5);                                     // Failed attempts before lockout
define('LOCKOUT_SECONDS',    900);                                   // Lockout duration (900 = 15 min)
define('RECENT_ENTRIES',     50);                                    // Rows in recent hits table
define('TREND_DAYS',         14);                                    // Days shown in trend chart
define('ADVANCED_MODE',      false);                                 // Enable danger zone in dashboard
```

---

## Privacy & GDPR

- No cookies — no consent banner needed
- IPs used only for country lookup, then discarded — **never written to disk**
- Only the country code (e.g. `AT`) is stored, not the IP
- All data stays on your own server
- For zero external requests: set `GEO_ENABLED = false`

---

## Advanced Mode

For power users who want extra control. Disabled by default — won't appear for regular users.

Enable it in `pima-core.php`:

```php
define('ADVANCED_MODE', true);
```

This adds a **Danger Zone** section at the bottom of the dashboard with:
- Database info (file size, row count)
- **Clear all data** — permanently deletes all analytics rows (requires confirmation)

Disable again by setting it back to `false`.

---

## Troubleshooting

### "No data yet" — dashboard stays empty

The most common reason: the tracking snippet is missing or the token is wrong.

1. Open your page in the browser, right-click → View Page Source, and search for `pima-tracker.php` — if it's not there, the snippet wasn't added correctly
2. Make sure the token in your snippet matches `TRACKER_TOKEN` in `pima-core.php` exactly — it's case-sensitive
3. Check that the `pima-cache/` folder exists on your server. If it's missing, create it manually via FTP and set permissions to `0750`
4. To test the tracker directly, open `yourdomain.com/pima-tracker.php?p=/test&t=YOUR_TOKEN` in your browser — you should see a blank white page (1×1 pixel), not an error

### Login doesn't work

Open `pima-core.php` and check `STATS_PASSWORD` — watch out for extra spaces or special characters that your text editor may have added. The password is case-sensitive.

If you're locked out after too many attempts, wait 15 minutes or increase `MAX_LOGIN_ATTEMPTS` temporarily.

### Dashboard is completely blank

This is usually a PHP syntax error in `pima-core.php`. Check that your password doesn't contain special characters like `$` or `'` — if it does, choose a simpler password with only letters and numbers.

### Country detection not working

Your host may have `allow_url_fopen` disabled. Set `GEO_ENABLED = false` in `pima-core.php` to disable country lookup — everything else will continue to work normally.

### `/pima` or `/analytics` returns a 404

`mod_rewrite` may be disabled on your server, or `.htaccess` files may not be allowed. Contact your host and ask them to enable `mod_rewrite` and `AllowOverride All`.

### Your own visits are showing up in the stats

Add your IP address to `EXCLUDED_IPS` in `pima-core.php`:
```php
define('EXCLUDED_IPS', ['your.ip.address']);
```
You can find your current IP at [whatismyip.com](https://www.whatismyip.com).

### Something looks wrong and you're not sure why

Try clearing the cache: connect via FTP, open the `pima-cache/` folder, and delete everything except `.htaccess`. The database will be recreated automatically on the next page visit. You can also do this from the dashboard if `ADVANCED_MODE` is enabled.

---

## Honest limitations

- **Daily unique visitors only** — pima Analytics counts unique visitors per day using an anonymous hash (salt rotates every 24h, so the same person on two different days cannot be correlated). This is intentional: no cookies, no cross-day tracking, no fingerprinting. The "Today" KPI is accurate; all-time "unique visitors" would be meaningless with this design and is deliberately not shown.
- **Not for high-traffic sites** — SQLite handles millions of rows comfortably, but concurrent write spikes (500+ simultaneous visitors) may cause brief delays.
- **No real-time view** — dashboard reflects data as written to the database.

---

## Requirements

- PHP 7.4+
- Apache with `.htaccess` support (standard on all shared hosts)
- SQLite3 and PDO_SQLITE extensions enabled (standard on all major hosts)
- `allow_url_fopen` (only for country detection)
- HTTPS (strongly recommended)

---

## License

MIT — free to use, modify, and self-host.

---

*pima Analytics — measure more. manage less.*

---

## Support

pima Analytics is free and open-source. If it saves you time or a cookie banner, consider buying me a coffee. ☕

<a href="https://ko-fi.com/ludescherstudio" target="_blank"><img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="ko-fi"></a>
