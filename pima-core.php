<?php
// ============================================================
// pima — pima-core.php
// ============================================================

// --- Auth ---
define('STATS_PASSWORD', 'change-me-please');

// --- Tracker token ---
// A second password that goes into your tracking snippet.
// Prevents fake hits from being injected into your analytics.
define('TRACKER_TOKEN', 'my-secret-word');

// --- Timezone ---
define('TIMEZONE', 'Europe/Vienna'); // full list: php.net/timezones

// --- Language ---
define('LANG', 'en'); // 'en' = English, 'de' = German

// --- Branding ---
define('BRAND_COLOR',    '#0d9488');          // any hex color
define('BRAND_LOGO',     '');                // e.g. '/assets/logo.svg'
define('BRAND_NAME',     'pima');            // change to your site name

// --- Database ---
define('DB_PATH', __DIR__ . '/pima-cache/analytics.db');

// --- IP Geolocation (optional) ---
// Uses ip-api.com (free, no key needed, rate-limited to 45 req/min)
// Set to false to disable country detection entirely
define('GEO_ENABLED', true);

// --- IPs to exclude from tracking ---
define('EXCLUDED_IPS', [
    // '1.2.3.4',
]);

// --- Reverse proxy ---
// Only enable if your site sits behind a trusted reverse proxy/CDN
// (e.g. Cloudflare, nginx). If disabled (default), the real client IP
// is taken from REMOTE_ADDR, which cannot be spoofed by visitors.
define('TRUST_PROXY', false);

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

// --- Advanced ---
// Set to true to enable the Danger Zone in the dashboard (clear all data, DB info)
define('ADVANCED_MODE', false);
