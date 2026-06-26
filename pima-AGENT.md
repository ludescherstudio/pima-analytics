# pima Analytics — Agent Integration Guide

You are integrating **pima Analytics**, a cookie‑free, self‑hosted PHP analytics tool, into a finished website.

## What pima does

pima records pageviews into a local SQLite database via a tiny tracking pixel (`pima-tracker.php`). The dashboard at `/pima` or `/analytics` shows traffic, top pages, referrers, devices, countries, languages and time‑of‑day charts. No cookies, no consent banner, no external database, no Node.js, no Docker.

## File structure

After the user has copied the pima files into the web root, the project contains these pima files:

```
webroot/
├── pima.php            # Dashboard (served at /pima and /analytics)
├── pima-tracker.php         # Tracking pixel endpoint
├── pima-core.php       # Configuration (passwords, branding, timezone)
├── pima-cache/
│   └── .htaccess       # Blocks direct access to the SQLite DB
└── pima-AGENT.md       # This file
```

pima does **not** ship its own root `.htaccess` or `robots.txt`. The target site is assumed to already have both — Steps 6 and 7 below describe exactly which lines to append to them.

## The tracking snippet

Every trackable page must include this snippet directly before the closing `</body>` tag:

```html
<script>
fetch('/pima-tracker.php?p=' + encodeURIComponent(location.pathname)
  + '&title=' + encodeURIComponent(document.title)
  + '&r=' + encodeURIComponent(document.referrer)
  + '&t=TRACKER_TOKEN');
</script>
```

`TRACKER_TOKEN` must be replaced with the literal value set in `pima-core.php`. This token lives in the HTML source of every tracked page and **is public** — it only authorises *writing* pageviews, not *reading* the dashboard. The dashboard has its own separate password.

---

## Integration procedure

Execute these steps in order.

### Step 1 — Verify pima files exist

Check that these files are present in the web root:
- `pima.php`
- `pima-tracker.php`
- `pima-core.php`
- `pima-cache/.htaccess`

If any are missing: **stop and report.** Do not generate these files — they come from the pima package.

### Step 2 — Configure pima-core.php

Open `pima-core.php` and update the relevant `define()` calls. Do **not** rewrite the whole file — edit the specific lines:

1. **`STATS_PASSWORD`** — generate a secure random password (16+ chars from `[a-zA-Z0-9]`). Avoid `'`, `\`, `$` to keep copy‑paste safe for the client. Use a cryptographic random source (e.g. `openssl rand -base64 16 | tr -d '/=+' | head -c 16`).
2. **`TRACKER_TOKEN`** — generate a random 12‑char alphanumeric token. This value is embedded in every tracked page's HTML, so treat it as a public identifier, not a secret. It only needs to be unguessable enough that random attackers can't inject fake hits.
3. **`TIMEZONE`** — default `Europe/Vienna` unless the project context clearly indicates another timezone.
4. **`LANG`** — `'de'` for German‑speaking clients (default), `'en'` if the site is clearly English‑only.
5. **`BRAND_NAME`** — the client/project name (same name you'd use for `PESI_SITE_NAME` if pesi is also installed).
6. **`BRAND_COLOR`** — try to match the site's primary color by scanning the main CSS file for a dominant `--primary`, `--accent`, or hex value used in headings / buttons. If unclear, leave the default `#0d9488`.
7. **`BRAND_LOGO`** — if the site has a logo at a predictable path (e.g. `/assets/logo.svg`, `/img/logo.png`), set it. Otherwise leave empty — the dashboard falls back to `BRAND_NAME` as text.

Both `STATS_PASSWORD` and `TRACKER_TOKEN` **must be reported verbatim in the final summary** so the user can save them. The password is not recoverable after install — only resettable by editing `pima-core.php`.

Do not touch `DB_PATH`, `GEO_ENABLED`, `EXCLUDED_IPS`, `BOT_PATTERNS`, `MAX_LOGIN_ATTEMPTS`, `LOCKOUT_SECONDS`, `RECENT_ENTRIES`, `TREND_DAYS`, or `ADVANCED_MODE` — their defaults are correct.

### Step 3 — Find the footer file

This project follows the standard build pattern: a single `footer.php` (or `partials/footer.php`, `includes/footer.php`, `_footer.html`, etc.) that is included by every page.

**Start here:** look for that file first. Common locations:
- `footer.php` in the web root
- `partials/footer.php`, `includes/footer.php`, `templates/footer.php`
- `_footer.html` or `layouts/footer.php`

If a footer file is found, **skip the full page inventory** — you only need the one insertion point. Proceed directly to Step 4.

If no footer file is found, fall back to scanning all `.php` and `.html` files for `</body>` tags to identify insertion points. Also check `wp-content/themes/<active-theme>/functions.php` for WordPress sites.

Exclude from any scan:
- `pima.php`, `pima-tracker.php`, `pima-core.php`
- Anything inside `pima-cache/`, `admin/`, `vendor/`, `node_modules/`, `.git/`
- The `pesi-core.php` and `admin/` files if pesi CMS is present

### Step 4 — Decide placement strategy

**Default assumption:** the site uses a shared footer file (see Step 3). Insert the snippet there **once** — done.

Only fall back to alternatives if no footer file exists:

1. **Shared footer template** ← default and strongly preferred
2. **WordPress `functions.php`** — register a `wp_footer` action hook
3. **Per‑page insertion** — last resort, only if every page has its own `</body>` with no shared include

**Critical rule:** never insert the snippet twice in the rendered output. A page that gets the snippet from both a shared footer *and* its own body would double‑count every hit. Before inserting, confirm the target file does not already contain a `fetch('/pima-tracker.php` call.

### Step 5 — Insert the snippet

Substitute the real tracker token (from Step 2) into the snippet wherever you insert it.

**Static HTML / plain PHP** — directly before `</body>`:
```html
<script>
fetch('/pima-tracker.php?p=' + encodeURIComponent(location.pathname)
  + '&title=' + encodeURIComponent(document.title)
  + '&r=' + encodeURIComponent(document.referrer)
  + '&t=REPLACE_WITH_ACTUAL_TOKEN');
</script>
</body>
```

**WordPress `functions.php`** — append:
```php
function pima_tracker() { ?>
<script>
fetch('/pima-tracker.php?p=' + encodeURIComponent(location.pathname)
  + '&title=' + encodeURIComponent(document.title)
  + '&r=' + encodeURIComponent(document.referrer)
  + '&t=REPLACE_WITH_ACTUAL_TOKEN');
</script>
<?php }
add_action('wp_footer', 'pima_tracker');
```

If a file already contains a fetch to `pima-tracker.php`, **do not add another one** — it is already tracked.

### Step 6 — Update .htaccess

The project root almost always already has a `.htaccess`. Open it and append the following block at the end of the file, exactly as shown:

```apache
# pima Analytics
RewriteEngine On
RewriteRule ^pima$       pima.php [L]
RewriteRule ^analytics$  pima.php [L]
<Files "pima-core.php">
    Require all denied
</Files>
Options -Indexes
```

What each line does (so you can judge conflicts):

| Line | Purpose | Safe to omit if… |
|---|---|---|
| `RewriteEngine On` | Enables mod_rewrite for the rules below | …it already appears earlier in the file |
| `RewriteRule ^pima$ pima.php [L]` | Maps `/pima` → `pima.php` | Never — required for the dashboard URL |
| `RewriteRule ^analytics$ pima.php [L]` | Maps `/analytics` → `pima.php` | Never — required for the alternate URL |
| `<Files "pima-core.php">…</Files>` | Blocks direct web access to the config (password + token) | Only if the same file is already denied by another rule |
| `Options -Indexes` | Disables directory listings | …it already appears earlier in the file |

Compatibility notes:
- On older Apache (2.2) the deny directive is `Order Allow,Deny` + `Deny from all` instead of `Require all denied`. If the existing `.htaccess` uses the old syntax throughout, match that style for consistency.
- Do not duplicate `RewriteEngine On` or `Options -Indexes` if they are already set — Apache tolerates it, but it's noise.
- Never delete or rewrite existing rules in the file. Only append.

**If the project root has no `.htaccess` at all:** create one with exactly the block above as its entire contents.

### Step 7 — Update robots.txt

The project root almost always already has a `robots.txt`. Open it and append these four lines at the end:

```
Disallow: /pima
Disallow: /analytics
Disallow: /pima-tracker.php
Disallow: /pima-cache/
```

Notes:
- If the file has a `User-agent: *` section, add the `Disallow` lines inside that section. If it has multiple `User-agent` blocks, add them under `User-agent: *` (create it if missing).
- Skip any individual line that is already present verbatim.
- Never delete or rewrite existing rules. Only append.

**If the project root has no `robots.txt` at all:** create one with the following contents:

```
User-agent: *
Disallow: /pima
Disallow: /analytics
Disallow: /pima-tracker.php
Disallow: /pima-cache/
```

### Step 8 — Remove repository extras (cleanup)

If the user copied the **entire pima repository** into the web root (rather than just the four required files), several files that are only needed on GitHub are now sitting on the live server. Remove the pima‑specific extras so they aren't publicly accessible:

- `pima-AGENT.md` — always safe to delete (this file).
- pima's own images: `assets/pima_dark_logo.svg`, `assets/pima_light_logo.svg`, `assets/screenshot_1.webp`, `assets/screenshot_2.webp`. The dashboard logos are embedded directly in `pima.php`, so these are unused at runtime. Delete the whole `assets/` folder **only if it contains nothing but these pima files** — otherwise delete just these four files and leave the rest.

**Critical — never delete the host site's own files.** `README.md`, `LICENSE` and `.gitignore` are generic names that may belong to the website itself:
- Delete them **only** if they are clearly pima's (e.g. the repo was cloned wholesale and the site had none of its own — `README.md` is pima's if its main heading is "pima Analytics").
- If in doubt, leave them and note it in the report.

Never delete `pima.php`, `pima-tracker.php`, `pima-core.php` or `pima-cache/` — these are required at runtime.

### Step 9 — Validate

Run through this checklist. Report any failures:

- `pima-core.php` has a non‑default `STATS_PASSWORD` (not `change-me-please`)
- `pima-core.php` has a non‑default `TRACKER_TOKEN` (not `my-secret-word`)
- The `&t=...` value in every inserted snippet matches `TRACKER_TOKEN` in `pima-core.php` **exactly** (case‑sensitive)
- Exactly one snippet per rendered page — no duplicates from combining shared footer + per‑page inserts
- Every touched `.php` file still passes `php -l` (syntax clean)
- `</body>` closing tag still present and well‑formed on every touched page
- `.htaccess` contains rewrite rules for both `pima` and `analytics`
- `.htaccess` denies direct access to `pima-core.php`
- `robots.txt` contains all four pima `Disallow` lines
- `pima-cache/` directory exists and has its `.htaccess` blocking all access
- Repository extras removed from the web root if the full repo was uploaded — `pima-AGENT.md` and pima's `assets/` images are gone; only the four runtime files (plus the host site's own files) remain
- Existing pesi CMS integration (if any) is untouched — pima and pesi co‑exist without conflict

### Step 10 — Report

Output a summary in this exact format:

```
pima Analytics integration complete.

Snippet insertion:   [shared-footer | wordpress-hook | per-page]
Locations touched:   X
- path/to/footer.php  (or list of per-page files)

Dashboard URL:       https://<domain>/pima
Dashboard password:  <generated password>
Tracker token:       <generated token>

Config:
- Timezone:    Europe/Vienna
- Language:    de
- Brand name:  <name>
- Brand color: <color>
- Brand logo:  <path or "default text">

Next steps for the user:
- Save the dashboard password in a password manager — it is not recoverable
- Open https://<domain>/pima and log in
- Visit any tracked page once, then refresh the dashboard to confirm hits are recorded
- Verify pima-cache/ directory has write permissions (chmod 0750 if needed)
- Optionally add the developer's own IP to EXCLUDED_IPS in pima-core.php to hide dev traffic
```

---

## Privacy policy

After integration, the website's privacy policy must be updated with a section about pima Analytics.

**For German-language websites**, insert the following text (e.g. under "Analyse & Statistik"):

> Diese Website verwendet eine selbst gehostete, datenschutzfreundliche Analysesoftware (pima Analytics). Es werden anonymisierte Nutzungsstatistiken erfasst (aufgerufene Seiten, Gerättyp, Browsersprache, Herkunftsland). IP-Adressen werden nicht gespeichert. Es werden keine Cookies gesetzt und keine Daten an Dritte weitergegeben. Rechtsgrundlage ist Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an der Websiteoptimierung).

**For English-language websites**, insert the following (e.g. under "Analytics & Statistics"):

> This website uses a self-hosted, privacy-friendly analytics tool (pima Analytics). Anonymised usage statistics are collected (pages visited, device type, browser language, country of origin). IP addresses are not stored. No cookies are set and no data is shared with third parties. The legal basis is Art. 6(1)(f) GDPR (legitimate interest in website optimisation).

**No cookie banner required** — since pima sets no cookies and stores no directly personal data, a consent banner is generally not necessary. When in doubt, seek legal advice.

---

## Full example

**Before** — a simple site with a shared footer:

`partials/footer.php`:
```php
<footer>
  <p>&copy; <?= date('Y') ?> Dr. Müller · Musterstraße 12, 6800 Feldkirch</p>
</footer>
</body>
</html>
```

`pima-core.php` (relevant lines, still default):
```php
define('STATS_PASSWORD', 'change-me-please');
define('TRACKER_TOKEN',  'my-secret-word');
define('TIMEZONE',       'Europe/Vienna');
define('LANG',           'en');
define('BRAND_COLOR',    '#0d9488');
define('BRAND_LOGO',     '');
define('BRAND_NAME',     'pima');
```

**After:**

`partials/footer.php`:
```php
<footer>
  <p>&copy; <?= date('Y') ?> Dr. Müller · Musterstraße 12, 6800 Feldkirch</p>
</footer>
<script>
fetch('/pima-tracker.php?p=' + encodeURIComponent(location.pathname)
  + '&title=' + encodeURIComponent(document.title)
  + '&r=' + encodeURIComponent(document.referrer)
  + '&t=k7m2x9p4q8vz');
</script>
</body>
</html>
```

`pima-core.php` (changed lines only):
```php
define('STATS_PASSWORD', 'Rt4vBq92LxKp7mWn');
define('TRACKER_TOKEN',  'k7m2x9p4q8vz');
define('TIMEZONE',       'Europe/Vienna');
define('LANG',           'de');
define('BRAND_COLOR',    '#2c5282');
define('BRAND_LOGO',     '/assets/logo.svg');
define('BRAND_NAME',     'Dr. Müller');
```

Key decisions:
- Shared `partials/footer.php` exists → **one** insertion point, not per‑page
- Token value in snippet matches `TRACKER_TOKEN` in config exactly
- `BRAND_COLOR` adapted from the site's existing CSS (`#2c5282` is the dominant heading color)
- `BRAND_LOGO` set because `/assets/logo.svg` was found in the project
- `LANG` set to `de` for a German‑speaking client
- `STATS_PASSWORD` and `TRACKER_TOKEN` both reported verbatim in the final summary

Report at the end:

```
pima Analytics integration complete.

Snippet insertion:   shared-footer
Locations touched:   1
- partials/footer.php

Dashboard URL:       https://drmueller.at/pima
Dashboard password:  Rt4vBq92LxKp7mWn
Tracker token:       k7m2x9p4q8vz

Config:
- Timezone:    Europe/Vienna
- Language:    de
- Brand name:  Dr. Müller
- Brand color: #2c5282
- Brand logo:  /assets/logo.svg

Next steps for the user:
- Save the dashboard password in a password manager — it is not recoverable
- Open https://drmueller.at/pima and log in
- Visit any tracked page once, then refresh the dashboard to confirm hits are recorded
- Verify pima-cache/ directory has write permissions (chmod 0750 if needed)
- Optionally add the developer's own IP to EXCLUDED_IPS in pima-core.php to hide dev traffic
```
