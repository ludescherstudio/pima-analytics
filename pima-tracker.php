<?php
// ============================================================
// pima — tracker.php
// Receives page view pings, filters bots, logs to SQLite.
// No tracking cookies. No raw IP storage. Privacy-friendly.
// ============================================================

header('Content-Type: image/gif');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');
echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');

$configPath = __DIR__ . '/pima-core.php';
if (!file_exists($configPath)) exit;
require_once $configPath;

date_default_timezone_set(TIMEZONE);

// ---- Tracker token check ----
if (defined('TRACKER_TOKEN') && TRACKER_TOKEN !== '') {
    $providedToken = $_GET['t'] ?? '';
    if (!is_string($providedToken) || !hash_equals((string) TRACKER_TOKEN, $providedToken)) exit;
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
    // Tablet first: iPads include "Mobile" and Android tablets include
    // "Android", so checking phones first makes the tablet bucket useless.
    if (preg_match('/(ipad|tablet|kindle|silk|playbook|android(?!.*mobile))/i', $ua)) return 'tablet';
    if (preg_match('/(mobile|iphone|ipod|blackberry|windows phone|opera mini|android)/i', $ua)) return 'mobile';
    return 'desktop';
}

function persistentSecret(string $path): string {
    $fh = @fopen($path, 'c+');
    if (!$fh || !@flock($fh, LOCK_EX)) {
        if ($fh) fclose($fh);
        return '';
    }
    $secret = trim((string) stream_get_contents($fh));
    if ($secret === '') {
        $secret = bin2hex(random_bytes(32));
        rewind($fh);
        ftruncate($fh, 0);
        if (fwrite($fh, $secret) !== strlen($secret)) $secret = '';
        fflush($fh);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $secret;
}

function getCountry(string $ip, string $runtimeSecret): string {
    if (!GEO_ENABLED) return '';
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return '';
    if ($ip === '' || in_array($ip, ['127.0.0.1', '::1'], true) || preg_match('/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/', $ip)) return 'local';

    // The cache key is a keyed digest, never the raw visitor IP.
    $cacheFile = dirname(DB_PATH) . '/.geo_cache.json';
    $ttl       = 7 * 86400;
    $cache     = [];
    $cacheDirty = false;
    $cacheKey  = $runtimeSecret !== '' ? hash_hmac('sha256', $ip, $runtimeSecret) : '';
    if (file_exists($cacheFile)) {
        $cache = json_decode(@file_get_contents($cacheFile), true) ?: [];
        // Remove legacy cache entries whose keys were raw IP addresses.
        foreach (array_keys($cache) as $key) {
            if (!preg_match('/^[a-f0-9]{64}$/', (string) $key)) {
                unset($cache[$key]);
                $cacheDirty = true;
            }
        }
        if ($cacheKey !== '' && isset($cache[$cacheKey]) && ($cache[$cacheKey]['t'] ?? 0) > time() - $ttl) {
            if ($cacheDirty) @file_put_contents($cacheFile, json_encode($cache), LOCK_EX);
            return (string) ($cache[$cacheKey]['c'] ?? '');
        }
    }

    $ctx = stream_context_create(['http' => ['timeout' => 1, 'ignore_errors' => true]]);
    $res = @file_get_contents('https://ipwho.is/' . rawurlencode($ip) . '?fields=success,country_code', false, $ctx);
    $country = '';
    if ($res) {
        $data    = json_decode($res, true);
        $country = !empty($data['success']) ? strtoupper((string) ($data['country_code'] ?? '')) : '';
        if (!preg_match('/^[A-Z]{2}$/', $country)) $country = '';
    }

    if ($cacheKey === '') return $country;
    $cache[$cacheKey] = ['c' => $country, 't' => time()];
    // Prune stale entries.
    foreach ($cache as $k => $v) {
        if (($v['t'] ?? 0) < time() - $ttl) unset($cache[$k]);
    }
    @file_put_contents($cacheFile, json_encode($cache), LOCK_EX);
    return $country;
}

function visitorHash(string $ip, string $ua, string $date): string {
    $ipAnon   = anonymizeIp($ip);
    $saltFile = dirname(DB_PATH) . '/.salt_' . $date;
    if (!file_exists($saltFile)) {
        // Lock and re-read so the day's salt is written exactly once.
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

function purgeLegacyGeoCache(): void {
    $cacheFile = dirname(DB_PATH) . '/.geo_cache.json';
    if (!file_exists($cacheFile)) return;
    $cache = json_decode(@file_get_contents($cacheFile), true);
    if (!is_array($cache)) return;
    $changed = false;
    foreach (array_keys($cache) as $key) {
        if (!preg_match('/^[a-f0-9]{64}$/', (string) $key)) {
            unset($cache[$key]);
            $changed = true;
        }
    }
    if ($changed) @file_put_contents($cacheFile, json_encode($cache), LOCK_EX);
}

function anonymizeIp(string $ip): string {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return preg_replace('/\.\d+$/', '.0', $ip);
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $packed = inet_pton($ip);
        if ($packed !== false) return (string) inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8));
    }
    return '';
}

function parseLang(string $raw): string {
    // Extract primary language from Accept-Language header e.g. "de-AT,de;q=0.9,en;q=0.8" → "de"
    if (empty($raw)) return '';
    preg_match('/^([a-zA-Z]{2,3})/', trim($raw), $m);
    return strtolower($m[1] ?? '');
}

function sanitize(string $val, int $maxLen = 512): string {
    $val = str_replace(["\r", "\n", "\t"], ' ', $val);
    $val = trim($val);
    $val = ltrim($val, '=+-@');
    return mb_substr($val, 0, $maxLen);
}

function queryString(string $key, string $default = ''): string {
    $value = $_GET[$key] ?? $default;
    return is_scalar($value) ? (string) $value : $default;
}

function normalizeHost(string $value): string {
    $host = parse_url($value, PHP_URL_HOST);
    if ($host === null && strpos($value, '://') === false) {
        $host = parse_url('http://' . $value, PHP_URL_HOST);
    }
    $host = strtolower(rtrim((string) $host, '.'));
    return preg_replace('/^www\./', '', $host);
}

function allowTrackerHit(string $ip, string $runtimeSecret): bool {
    $limit  = defined('TRACKER_RATE_LIMIT') ? max(1, (int) TRACKER_RATE_LIMIT) : 120;
    $window = defined('TRACKER_RATE_WINDOW') ? max(1, (int) TRACKER_RATE_WINDOW) : 60;
    if ($runtimeSecret === '' || $ip === '') return false;

    $bucket = substr(hash_hmac('sha256', $ip, $runtimeSecret), 0, 32);
    $file   = dirname(DB_PATH) . '/.rate_' . $bucket . '.json';
    $fh     = @fopen($file, 'c+');
    if (!$fh || !@flock($fh, LOCK_EX)) {
        if ($fh) fclose($fh);
        return false;
    }
    $data  = json_decode((string) stream_get_contents($fh), true);
    $start = is_array($data) ? (int) ($data['start'] ?? 0) : 0;
    $count = is_array($data) ? (int) ($data['count'] ?? 0) : 0;
    if ($start <= 0 || $start <= time() - $window) {
        $start = time();
        $count = 0;
    }
    $allowed = $count < $limit;
    if ($allowed) $count++;
    $json = json_encode(['start' => $start, 'count' => $count]);
    rewind($fh);
    ftruncate($fh, 0);
    fwrite($fh, (string) $json);
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);

    if (mt_rand(1, 100) === 1) {
        foreach (glob(dirname(DB_PATH) . '/.rate_*.json') as $old) {
            if ((int) @filemtime($old) < time() - ($window * 2)) @unlink($old);
        }
    }
    return $allowed;
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
        lang     TEXT,
        is_entry INTEGER
    )');
    // Add columns if upgrading from an older version
    try { $db->exec('ALTER TABLE hits ADD COLUMN lang  TEXT'); } catch (Exception $e) {}
    try { $db->exec('ALTER TABLE hits ADD COLUMN title TEXT'); } catch (Exception $e) {}
    try {
        $db->exec('ALTER TABLE hits ADD COLUMN is_entry INTEGER');
        // Legacy external referrers are known entries. Empty legacy referrers
        // stay NULL because they cannot be distinguished from internal hits.
        $db->exec("UPDATE hits SET is_entry = 1 WHERE referrer IS NOT NULL AND referrer != ''");
    } catch (Exception $e) {}
    $db->exec('CREATE INDEX IF NOT EXISTS idx_date    ON hits(date)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_page    ON hits(page)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_country ON hits(country)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_vid     ON hits(vid)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_entry   ON hits(is_entry)');
    $retentionDays = defined('DATA_RETENTION_DAYS') ? (int) DATA_RETENTION_DAYS : 365;
    if ($retentionDays > 0) {
        $pruneFile = dirname(DB_PATH) . '/.last_prune';
        $fh = @fopen($pruneFile, 'c+');
        if ($fh && @flock($fh, LOCK_EX)) {
            $lastPrune = (int) trim((string) stream_get_contents($fh));
            if ($lastPrune < strtotime('today')) {
                $cutoff = date('Y-m-d', strtotime('-' . max(0, $retentionDays - 1) . ' days'));
                $stmt = $db->prepare('DELETE FROM hits WHERE date < :cutoff');
                $stmt->bindValue(':cutoff', $cutoff);
                $stmt->execute();
                rewind($fh);
                ftruncate($fh, 0);
                fwrite($fh, (string) time());
                fflush($fh);
            }
            flock($fh, LOCK_UN);
        }
        if ($fh) fclose($fh);
    }
    return $db;
}

// ---- Main ----

$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
// REMOTE_ADDR cannot be spoofed; read X-Forwarded-For only when allowed
$remoteIp   = $_SERVER['REMOTE_ADDR'] ?? '';
$trustProxy = defined('TRUST_PROXY') && TRUST_PROXY
    && defined('TRUSTED_PROXY_IPS') && in_array($remoteIp, TRUSTED_PROXY_IPS, true);
$ip = ($trustProxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR']))
    ? trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0])
    : $remoteIp;
if (!filter_var($ip, FILTER_VALIDATE_IP)) $ip = $remoteIp;

if (isBot($ua)) exit;
if (!empty(EXCLUDED_IPS) && in_array($ip, EXCLUDED_IPS, true)) exit;
$cacheDir = dirname(DB_PATH);
if (!is_dir($cacheDir) && !@mkdir($cacheDir, 0750, true)) exit;
$runtimeSecret = persistentSecret(dirname(DB_PATH) . '/.runtime_secret');
purgeLegacyGeoCache();
if (!allowTrackerHit($ip, $runtimeSecret)) exit;

$page     = sanitize(queryString('p', '/'), 255);

// Normalize common index variants to /
$page = preg_replace('|/index\.html?$|i', '/', $page);
$page = preg_replace('|/index\.php$|i', '/', $page);
// Strip .html/.htm and .php extensions to unify clean-URL and file-extension variants
$page = preg_replace('#\.(?:html?|php)$#i', '', $page);
if ($page === '') $page = '/';
if ($page[0] !== '/') $page = '/' . $page;
$referrerRaw  = sanitize(queryString('r'), 512);
$title        = sanitize(queryString('title'), 255);
$currentHost  = normalizeHost($_SERVER['HTTP_HOST'] ?? '');
$referrerHost = normalizeHost($referrerRaw);
$isEntry      = ($referrerRaw === '' || $referrerHost === '' || $referrerHost !== $currentHost) ? 1 : 0;
$referrer     = ($isEntry === 1 && $referrerHost !== $currentHost) ? $referrerHost : '';

$device  = getDevice($ua);
$country = getCountry($ip, $runtimeSecret);
$date    = date('Y-m-d');
$time    = date('H:i:s');
$vid     = visitorHash($ip, $ua, $date);
$lang    = parseLang($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');

try {
    $db   = initDb();
    $stmt = $db->prepare('INSERT INTO hits (date, time, page, title, referrer, device, country, vid, lang, is_entry) VALUES (:date, :time, :page, :title, :referrer, :device, :country, :vid, :lang, :is_entry)');
    $stmt->bindValue(':date',     $date);
    $stmt->bindValue(':time',     $time);
    $stmt->bindValue(':page',     $page);
    $stmt->bindValue(':title',    $title);
    $stmt->bindValue(':referrer', $referrer);
    $stmt->bindValue(':device',   $device);
    $stmt->bindValue(':country',  $country);
    $stmt->bindValue(':vid',      $vid);
    $stmt->bindValue(':lang',     $lang);
    $stmt->bindValue(':is_entry', $isEntry, SQLITE3_INTEGER);
    $stmt->execute();
    $db->close();
} catch (Exception $e) {
    // Fail silently — never break the tracked page
}
