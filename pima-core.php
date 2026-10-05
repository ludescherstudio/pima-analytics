<?php
// pima Analytics — settings · ludescher.studio
// This file is yours. Updates replace only pima.php and pima-tracker.php;
// pima-core.php and pima-cache/ stay as they are. Documentation: README.md

// --- Auth ---
// Dashboard password (plaintext or password_hash() value). The shipped value
// locks sign-in — set your own before going live.
define('STATS_PASSWORD', 'change-me-please');
// Users may change the password in the dashboard. It is then stored in
// pima-cache/.pima-password; delete that file to reset to STATS_PASSWORD.
define('STATS_PASSWORD_CHANGE', true);

// --- Tracker token ---
// A public identifier that goes into your tracking snippet.
// It rejects accidental requests, but cannot prevent deliberate fake hits.
define('TRACKER_TOKEN', 'my-secret-word');

// --- Timezone ---
define('TIMEZONE', 'Europe/Vienna'); // full list: php.net/timezones

// --- Language ---
// Dashboard language: 'en' = English, 'de' = Deutsch (formal "Sie").
define('LANG', 'en');

// --- Branding ---
define('BRAND_COLOR',    '#0d9488');          // any hex color
define('BRAND_LOGO',     '');                // e.g. '/assets/logo.svg'
define('BRAND_NAME',     'My Website');      // your site name: login screen and dashboard

// --- Database ---
define('DB_PATH', __DIR__ . '/pima-cache/analytics.db');

// --- IP Geolocation (optional) ---
// Uses ipwho.is over HTTPS (free, no key needed, rate-limited)
// Only the truncated IP is sent (IPv4 /24, IPv6 /64)
// Set to false to disable country detection entirely
define('GEO_ENABLED', true);

// --- Data retention ---
// Pageviews older than this are deleted automatically. Set to 0 to keep forever.
define('DATA_RETENTION_DAYS', 365);

// --- IPs to exclude from tracking ---
define('EXCLUDED_IPS', [
    // '1.2.3.4',
]);

// --- Reverse proxy ---
// Only enable if your site sits behind a trusted reverse proxy/CDN
// (e.g. Cloudflare, nginx). Affects tracking only — the login lockout
// always uses REMOTE_ADDR, so a wrong setting here cannot bypass it.
define('TRUST_PROXY', false);
// Required when TRUST_PROXY is true. Only requests arriving from these proxy
// addresses may supply X-Forwarded-For / X-Forwarded-Proto.
define('TRUSTED_PROXY_IPS', [
    // '127.0.0.1',
]);

// --- Bot filter ---
define('BOT_PATTERNS', [
    'bot', 'crawl', 'spider', 'slurp', 'wget', 'curl',
    'python-requests', 'axios', 'java/', 'go-http',
    'googlebot', 'bingbot', 'yandexbot', 'duckduckbot',
    'baiduspider', 'facebot', 'ia_archiver',
    'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot',
    'screaming frog', 'rogerbot', 'exabot', 'sistrix',
    'petalbot', 'bytespider', 'gptbot', 'claudebot',
    'anthropic-ai', 'ccbot', 'dataforseobot',
]);

// --- Dashboard display settings ---
define('RECENT_ENTRIES', 50);
define('TREND_DAYS', 14);

// --- Brute-force protection ---
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_SECONDS', 900); // 15 minutes
define('SESSION_IDLE_SECONDS', 1800); // 30 minutes
define('SESSION_MAX_SECONDS', 43200); // sign in again after 12 hours at the latest

// --- Tracker abuse protection ---
define('TRACKER_RATE_LIMIT', 120); // accepted hits per IP bucket
define('TRACKER_RATE_WINDOW', 60); // seconds

// --- Own wording (optional) ---
// Overrides single dashboard texts without touching pima.php. The full list
// of keys is in $strings in pima.php.
//
// $PIMA_STRINGS = [
//     'login_help' => 'Forgot your password? Call us: +43 123 456789',
//     'no_data'    => 'No visits yet — they will show up here within minutes.',
// ];

// --- Advanced ---
// Set to true to enable the Danger Zone in the dashboard (clear all data, DB info)
define('ADVANCED_MODE', false);
