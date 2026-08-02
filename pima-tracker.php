<?php
// ============================================================
// pima — tracker.php
// Receives page view pings, filters bots, logs to SQLite.
// No cookies. No IP storage. GDPR-friendly.
// ============================================================

header('Content-Type: image/gif');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Access-Control-Allow-Origin: *');
echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');

$configPath = __DIR__ . '/pima-core.php';
if (!file_exists($configPath)) exit;
require_once $configPath;

date_default_timezone_set(TIMEZONE);

// ---- Tracker token check ----
if (defined('TRACKER_TOKEN') && TRACKER_TOKEN !== '') {
    if (($_GET['t'] ?? '') !== TRACKER_TOKEN) exit;
}

// ---- Helpers ----

function isBot(string $ua): bool {
    if (empty($ua)) return true;
    $ua = strtolower($ua);
    foreach (BOT_PATTERNS as $pattern) {
        if (strpos($ua, strtolower($pattern)) !== false) return true;
    }
    return false;
}

function getDevice(string $ua): string {
    if (preg_match('/(mobile|android|iphone|ipod|blackberry|windows phone|opera mini)/i', $ua)) return 'mobile';
    if (preg_match('/(tablet|ipad)/i', $ua)) return 'tablet';
    return 'desktop';
}

function getCountry(string $ip): string {
    if (!GEO_ENABLED) return '';
    if ($ip === '' || in_array($ip, ['127.0.0.1', '::1'], true) || preg_match('/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/', $ip)) return 'local';

    // File-based cache per IP (TTL 7 days) — keeps ip-api.com off the hot
    // path when the service is slow or unreachable.
    $cacheFile = dirname(DB_PATH) . '/.geo_cache.json';
    $ttl       = 7 * 86400;
    $cache     = [];
    if (file_exists($cacheFile)) {
        $cache = json_decode(@file_get_contents($cacheFile), true) ?: [];
        if (isset($cache[$ip]) && ($cache[$ip]['t'] ?? 0) > time() - $ttl) {
            return (string) ($cache[$ip]['c'] ?? '');
        }
    }

    $ctx = stream_context_create(['http' => ['timeout' => 1]]);
    $res = @file_get_contents('http://ip-api.com/json/' . urlencode($ip) . '?fields=countryCode', false, $ctx);
    $country = '';
    if ($res) {
        $data    = json_decode($res, true);
        $country = $data['countryCode'] ?? '';
    }

    $cache[$ip] = ['c' => $country, 't' => time()];
    // Prune stale entries so the file cannot grow unbounded.
    foreach ($cache as $k => $v) {
        if (($v['t'] ?? 0) < time() - $ttl) unset($cache[$k]);
    }
    @file_put_contents($cacheFile, json_encode($cache), LOCK_EX);
    return $country;
}

function visitorHash(string $ip, string $ua, string $date): string {
    $ipAnon   = preg_replace('/\.\d+$/', '.0', $ip);
    $saltFile = dirname(DB_PATH) . '/.salt_' . $date;
    if (!file_exists($saltFile)) {
        // Lock and re-read, or two concurrent requests end up with different
        // salts for the same day.
        $fh = @fopen($saltFile, 'c+');
        if ($fh) {
            @flock($fh, LOCK_EX);
            $existing = stream_get_contents($fh);
            if ($existing === '' || $existing === false) {
                fwrite($fh, bin2hex(random_bytes(16)));
                fflush($fh);
            }
            @flock($fh, LOCK_UN);
            fclose($fh);
        }
        foreach (glob(dirname(DB_PATH) . '/.salt_*') as $f) {
            if ($f !== $saltFile && filemtime($f) < strtotime('-2 days')) @unlink($f);
        }
    }
    $salt = file_get_contents($saltFile);
    return substr(hash('sha256', $salt . $date . $ipAnon . $ua), 0, 12);
}

function parseLang(string $raw): string {
    // Extract primary language from Accept-Language header e.g. "de-AT,de;q=0.9,en;q=0.8" → "de"
    if (empty($raw)) return '';
    preg_match('/^([a-zA-Z]{2,3})/', trim($raw), $m);
    return strtolower($m[1] ?? '');
}

function sanitize(string $val, int $maxLen = 512): string {
    $val = str_replace(["\r", "\n", "\t"], ' ', $val);
    $val = ltrim($val, '=+-@');
    return mb_substr(trim($val), 0, $maxLen);
}

function initDb(): SQLite3 {
    $cacheDir = dirname(DB_PATH);
    if (!is_dir($cacheDir)) mkdir($cacheDir, 0750, true);
    $db = new SQLite3(DB_PATH);
    $db->enableExceptions(true);
    $db->exec('PRAGMA journal_mode=WAL');  // better concurrent write handling
    $db->exec('PRAGMA synchronous=NORMAL');
    $db->exec('CREATE TABLE IF NOT EXISTS hits (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        date     TEXT NOT NULL,
        time     TEXT NOT NULL,
        page     TEXT NOT NULL,
        title    TEXT,
        referrer TEXT,
        device   TEXT,
        country  TEXT,
        vid      TEXT,
        lang     TEXT
    )');
    // Add columns if upgrading from an older version
    try { $db->exec('ALTER TABLE hits ADD COLUMN lang  TEXT'); } catch (Exception $e) {}
    try { $db->exec('ALTER TABLE hits ADD COLUMN title TEXT'); } catch (Exception $e) {}
    $db->exec('CREATE INDEX IF NOT EXISTS idx_date    ON hits(date)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_page    ON hits(page)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_country ON hits(country)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_vid     ON hits(vid)');
    return $db;
}

// ---- Main ----

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
// REMOTE_ADDR cannot be spoofed; read X-Forwarded-For only when allowed
$trustProxy = defined('TRUST_PROXY') ? TRUST_PROXY : false;
$ip = ($trustProxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR']))
    ? trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0])
    : ($_SERVER['REMOTE_ADDR'] ?? '');

if (isBot($ua)) exit;
if (!empty(EXCLUDED_IPS) && in_array($ip, EXCLUDED_IPS, true)) exit;

$page     = sanitize($_GET['p'] ?? '/', 255);

// Normalize common index variants to /
$page = preg_replace('|/index\.html?$|i', '/', $page);
$page = preg_replace('|/index\.php$|i', '/', $page);
// Strip .html/.htm and .php extensions to unify clean-URL and file-extension variants
$page = preg_replace('#\.(?:html?|php)$#i', '', $page);
if ($page === '') $page = '/';
$referrer = sanitize($_GET['r']     ?? '', 512);
$title    = sanitize($_GET['title'] ?? '', 255);

$host = $_SERVER['HTTP_HOST'] ?? '';
if ($host && strpos($referrer, $host) !== false) $referrer = '';

$device  = getDevice($ua);
$country = getCountry($ip);
$date    = date('Y-m-d');
$time    = date('H:i:s');
$vid     = visitorHash($ip, $ua, $date);
$lang    = parseLang($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');

try {
    $db   = initDb();
    $stmt = $db->prepare('INSERT INTO hits (date, time, page, title, referrer, device, country, vid, lang) VALUES (:date, :time, :page, :title, :referrer, :device, :country, :vid, :lang)');
    $stmt->bindValue(':date',     $date);
    $stmt->bindValue(':time',     $time);
    $stmt->bindValue(':page',     $page);
    $stmt->bindValue(':title',    $title);
    $stmt->bindValue(':referrer', $referrer);
    $stmt->bindValue(':device',   $device);
    $stmt->bindValue(':country',  $country);
    $stmt->bindValue(':vid',      $vid);
    $stmt->bindValue(':lang',     $lang);
    $stmt->execute();
    $db->close();
} catch (Exception $e) {
    // Fail silently — never break the tracked page
}
