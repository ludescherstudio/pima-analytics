<?php
/**
 * pima Analytics — dashboard · ludescher.studio
 * URL: example.com/pima
 */

define('PIMA_VERSION', '0.6.1');

require_once __DIR__ . '/pima-core.php';
date_default_timezone_set(TIMEZONE);

// Must be set before session_start(). Proxy headers are trusted only from an
// explicitly configured proxy address.
$remoteAddr   = $_SERVER['REMOTE_ADDR'] ?? '';
$trustedProxy = defined('TRUST_PROXY') && TRUST_PROXY
    && defined('TRUSTED_PROXY_IPS') && in_array($remoteAddr, TRUSTED_PROXY_IPS, true);
$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['SERVER_PORT'] ?? 0) == 443)
    || ($trustedProxy && (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'));
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
$sessionDir = dirname(DB_PATH);
if (is_dir($sessionDir) && is_writable($sessionDir)) ini_set('session.save_path', $sessionDir);
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
// Own cookie name: with the default PHPSESSID, another PHP app on the same
// domain (pesi, a shop) would overwrite the cookie and sign the user out.
session_name('pima_session');
session_start();

function pimaPasswordFile(): string {
    return dirname(DB_PATH) . '/.pima-password';
}

// null = no file, STATS_PASSWORD applies. '' = file present but without a
// valid hash: sign-in stays locked instead of silently falling back.
function pimaPasswordOverride(): ?string {
    $f = pimaPasswordFile();
    if (!file_exists($f)) return null;
    $h = @file_get_contents($f);
    $h = is_string($h) ? trim($h) : '';
    return $h !== '' && $h[0] === '$' && password_get_info($h)['algoName'] !== 'unknown' ? $h : '';
}

// Checks a password against the stored value: password_hash() or, from
// pima-core.php, plaintext.
function pimaPasswordVerify(string $pw, string $stored): bool {
    if ($stored === '') return false;
    return strlen($stored) > 3 && $stored[0] === '$'
        ? password_verify($pw, $stored)
        : hash_equals($stored, $pw);
}

// Rules for a new password, checked after the current one was verified.
// Returns '' when fine, otherwise the key of the message.
function pimaPasswordRules(string $current, string $new, string $repeat): string {
    if ($new !== $repeat) return 'pw_err_repeat';
    if (preg_match_all('/./su', $new) < 10 || trim($new) === '') return 'pw_err_short';
    if ($new === $current) return 'pw_err_same';
    return '';
}

// Writes the hash to a temp file and swaps it in atomically.
// Returns the new hash, or null when nothing was written.
function pimaPasswordWrite(string $new): ?string {
    $hash = password_hash($new, PASSWORD_DEFAULT);
    $f = pimaPasswordFile();
    try {
        $tmp = $f . '-tmp-' . bin2hex(random_bytes(8));
    } catch (Throwable $e) {
        return null;
    }
    $fp = @fopen($tmp, 'x+b');
    $ok = $fp && fwrite($fp, $hash) === strlen($hash) && fflush($fp);
    if ($fp && function_exists('fsync')) $ok = fsync($fp) && $ok;
    if ($fp) fclose($fp);
    if ($ok) {
        @chmod($tmp, 0600);
        $ok = @rename($tmp, $f);
    }
    if (!$ok) { @unlink($tmp); return null; }
    clearstatcache(true, $f);
    return pimaPasswordOverride() === $hash ? $hash : null;
}

// ---- Dashboard password ----
// A password changed in the dashboard is stored as password_hash() in
// pima-cache/.pima-password and takes precedence over STATS_PASSWORD.
// Deleting that file restores STATS_PASSWORD. An empty or shipped default
// password locks sign-in.
$pwChangeEnabled = defined('STATS_PASSWORD_CHANGE') ? (bool) STATS_PASSWORD_CHANGE : true;
$pwOverride      = pimaPasswordOverride();
$storedPassword  = $pwOverride ?? (defined('STATS_PASSWORD') ? (string) STATS_PASSWORD : '');
$defaultPassword = in_array(trim($storedPassword), ['', 'change-me-please', 'change-me'], true);

// Expire idle sessions, sessions past their maximum lifetime and sessions
// created with an older dashboard password.
$sessionIdle = defined('SESSION_IDLE_SECONDS') ? max(60, (int) SESSION_IDLE_SECONDS) : 1800;
$sessionMax  = defined('SESSION_MAX_SECONDS')  ? max(60, (int) SESSION_MAX_SECONDS)  : 43200;
$authKey     = hash('sha256', $storedPassword);
if (!empty($_SESSION['pima_auth'])) {
    $expired = empty($_SESSION['pima_last_activity'])
        || (int) $_SESSION['pima_last_activity'] < time() - $sessionIdle
        || (int) ($_SESSION['pima_login_at'] ?? 0) < time() - $sessionMax;
    $passwordChanged = $defaultPassword
        || !isset($_SESSION['pima_auth_key'])
        || !hash_equals($authKey, (string) $_SESSION['pima_auth_key']);
    if ($expired || $passwordChanged) {
        unset($_SESSION['pima_auth'], $_SESSION['pima_auth_key'], $_SESSION['pima_last_activity'], $_SESSION['pima_login_at']);
    } elseif (!isset($_GET['live'])) {
        // The header's background poll must not keep an idle session alive.
        $_SESSION['pima_last_activity'] = time();
    }
}

// CSRF token, persistent per session
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['csrf'];
$csrfOk = isset($_POST['csrf']) && is_scalar($_POST['csrf'])
    && hash_equals($csrf, (string) $_POST['csrf']);

header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
if ($isHttps) header('Strict-Transport-Security: max-age=31536000');

// ---- Brute-force protection (file-based, per IP) ----
$maxAttempts = defined('MAX_LOGIN_ATTEMPTS') ? MAX_LOGIN_ATTEMPTS : 5;
$lockoutSecs = defined('LOCKOUT_SECONDS')    ? LOCKOUT_SECONDS    : 900;

// Keyed on REMOTE_ADDR, never on X-Forwarded-For, regardless of TRUST_PROXY.
$ipKey    = substr(hash('sha256', $remoteAddr . '|pima-lockout'), 0, 16);
$lockFile = dirname(DB_PATH) . '/.lockout_' . $ipKey . '.json';

// Unlocked read — drives the lock screen only.
$lockState = ['attempts' => 0, 'locked_until' => 0];
if (file_exists($lockFile)) {
    $fh = @fopen($lockFile, 'r');
    if ($fh && @flock($fh, LOCK_SH)) {
        $decoded = json_decode((string) stream_get_contents($fh), true);
        flock($fh, LOCK_UN);
        if (is_array($decoded)) {
            $lockState['attempts']     = (int) ($decoded['attempts'] ?? 0);
            $lockState['locked_until'] = (int) ($decoded['locked_until'] ?? 0);
        }
    }
    if ($fh) fclose($fh);
}
$now = time();
if ($lockState['locked_until'] > 0 && $lockState['locked_until'] <= $now) {
    $lockState = ['attempts' => 0, 'locked_until' => 0];
}
$attempts    = $lockState['attempts'];
$lockedUntil = $lockState['locked_until'];
$isLocked    = $now < $lockedUntil;

// Prune by mtime — locked_until is still 0 on counters below the threshold.
if (mt_rand(1, 50) === 1) {
    foreach (glob(dirname(DB_PATH) . '/.lockout_*.json') as $f) {
        if ((int) @filemtime($f) < time() - max(3600, $lockoutSecs * 2)) @unlink($f);
    }
}

/**
 * Runs one password check under the per-IP lockout. $check is called only
 * while the IP is not locked, inside the exclusive lock, so parallel requests
 * cannot share an attempt. A correct password clears the counter, a wrong one
 * counts towards the lockout.
 * Returns 'ok', 'fail', 'locked' or 'unavailable' (lockout file not usable);
 * 'saved' is false when the new counter could not be written.
 */
function pimaLockedCheck(string $lockFile, int $maxAttempts, int $lockoutSecs, callable $check): array {
    $state = ['result' => 'unavailable', 'saved' => false, 'attempts' => 0, 'locked_until' => 0];
    $fh = @fopen($lockFile, 'c+');
    if (!$fh || !@flock($fh, LOCK_EX)) {
        if ($fh) fclose($fh);
        return $state;
    }
    $decoded = json_decode((string) stream_get_contents($fh), true);
    $attempts = is_array($decoded) ? (int) ($decoded['attempts'] ?? 0) : 0;
    $lockedUntil = is_array($decoded) ? (int) ($decoded['locked_until'] ?? 0) : 0;
    if ($lockedUntil > 0 && $lockedUntil <= time()) {
        $attempts = 0;
        $lockedUntil = 0;
    }

    if (time() < $lockedUntil) {
        $result = 'locked';
    } elseif ($check()) {
        $attempts = 0;
        $lockedUntil = 0;
        $result = 'ok';
    } else {
        $attempts++;
        if ($attempts >= $maxAttempts) $lockedUntil = time() + $lockoutSecs;
        $result = time() < $lockedUntil ? 'locked' : 'fail';
    }

    $json = (string) json_encode(['attempts' => $attempts, 'locked_until' => $lockedUntil]);
    rewind($fh);
    ftruncate($fh, 0);
    $saved = fwrite($fh, $json) === strlen($json);
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return ['result' => $result, 'saved' => $saved, 'attempts' => $attempts, 'locked_until' => $lockedUntil];
}

// Own path for redirects. Exactly one leading slash: '//host' and '/\host'
// would be read as protocol-relative URLs, i.e. an open redirect.
$selfUrl = strtok($_SERVER['REQUEST_URI'] ?? '/pima', '?');
if (!is_string($selfUrl) || $selfUrl === '' || $selfUrl[0] !== '/'
    || (isset($selfUrl[1]) && ($selfUrl[1] === '/' || $selfUrl[1] === '\\'))
    || preg_match('/[\x00-\x1F\x7F]/', $selfUrl)) {
    $selfUrl = '/pima';
}

// ---- Auth ----
// With the default password the form is disabled and nothing is checked.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password']) && !$defaultPassword) {
    if (!$csrfOk) {
        // Invalid cross-site posts do not consume another person's IP quota.
        $authError = true;
        sleep(1);
    } else {
        $pw    = is_scalar($_POST['password']) ? (string) $_POST['password'] : '';
        $check = pimaLockedCheck($lockFile, $maxAttempts, $lockoutSecs,
            function () use ($pw, $storedPassword): bool { return pimaPasswordVerify($pw, $storedPassword); });
        $attempts    = $check['attempts'];
        $lockedUntil = $check['locked_until'];
        if ($check['result'] === 'unavailable' || !$check['saved']) {
            $authUnavailable = true;
            error_log('pima: login lockout file unavailable (T15)');
        }
        if ($check['result'] === 'locked') {
            $isLocked = true;
        } elseif ($check['result'] === 'fail') {
            $authError = true;
        } elseif ($check['result'] === 'ok') {
            session_regenerate_id(true);
            $_SESSION['pima_auth']          = true;
            $_SESSION['pima_auth_key']      = $authKey;
            $_SESSION['pima_login_at']      = time();
            $_SESSION['pima_last_activity'] = time();
            $_SESSION['csrf']               = bin2hex(random_bytes(16));
            $csrf = $_SESSION['csrf'];
        }

        if ($isLocked) sleep(min(3, max(1, $lockedUntil - time())));
        elseif (!empty($authError)) sleep(min(8, max(1, $attempts)));
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout']) && $csrfOk) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    header('Location: ' . $selfUrl);
    exit;
}
$authed = !empty($_SESSION['pima_auth']);

// ---- Branding ----
$brandColor   = defined('BRAND_COLOR')    ? BRAND_COLOR    : '#0d9488';
// Normalise 3-digit hex (#abc) to 6 — the alpha suffixes below need 6 digits
if (preg_match('/^#([0-9a-f])([0-9a-f])([0-9a-f])$/i', $brandColor, $m)) {
    $brandColor = '#' . $m[1].$m[1].$m[2].$m[2].$m[3].$m[3];
}
$brandLogo    = defined('BRAND_LOGO')     ? BRAND_LOGO     : '';
$brandName    = defined('BRAND_NAME')     ? BRAND_NAME     : 'pima';
$brandFont    = 'system-ui, -apple-system, sans-serif';
$advancedMode = defined('ADVANCED_MODE')  ? ADVANCED_MODE  : false;

// ---- pima logos (base64 embedded — no external file dependency) ----
$pimaLogoDark  = 'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyBpZD0iRWJlbmVfMiIgZGF0YS1uYW1lPSJFYmVuZSAyIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzOTUuMDQgNTcuNDIiPgogIDxkZWZzPgogICAgPHN0eWxlPgogICAgICAuY2xzLTEgewogICAgICAgIGZpbGw6ICNmM2YzZjM7CiAgICAgIH0KCiAgICAgIC5jbHMtMiB7CiAgICAgICAgZmlsbDogIzA4OTQ4ODsKICAgICAgfQogICAgPC9zdHlsZT4KICA8L2RlZnM+CiAgPGcgaWQ9IkViZW5lXzEtMiIgZGF0YS1uYW1lPSJFYmVuZSAxIj4KICAgIDxnPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Ik0wLDEzLjA4aDUuNDZ2NC41YzEuMjgtMS42NCwyLjg5LTIuOTIsNC44My0zLjg0LDEuOTQtLjkyLDQuMTEtMS4zOCw2LjUxLTEuMzgsMywwLDUuNzIuNzQsOC4xNiwyLjIyLDIuNDQsMS40OCw0LjM2LDMuNTEsNS43Niw2LjA5LDEuNCwyLjU4LDIuMSw1LjQ1LDIuMSw4LjYxcy0uNyw2LjAyLTIuMSw4LjU4Yy0xLjQsMi41Ni0zLjMyLDQuNTgtNS43Niw2LjA2LTIuNDQsMS40OC01LjE4LDIuMjItOC4yMiwyLjIyLTIuMzIsMC00LjQ1LS40NS02LjM5LTEuMzVzLTMuNTMtMi4xOS00Ljc3LTMuODd2MTYuNUgwVjEzLjA4Wk02Ljk5LDM1LjEzYy45NCwxLjc0LDIuMjMsMy4xMSwzLjg3LDQuMTEsMS42NCwxLDMuNDYsMS41LDUuNDYsMS41czMuODEtLjUsNS40My0xLjVjMS42Mi0xLDIuODgtMi4zNywzLjc4LTQuMTEuOS0xLjc0LDEuMzUtMy42OSwxLjM1LTUuODVzLS40Ni00LjEyLTEuMzgtNS44OGMtLjkyLTEuNzYtMi4xOC0zLjE0LTMuNzgtNC4xNC0xLjYtMS0zLjQtMS41LTUuNC0xLjVzLTMuODIuNS01LjQ2LDEuNWMtMS42NCwxLTIuOTMsMi4zOC0zLjg3LDQuMTQtLjk0LDEuNzYtMS40MSwzLjcyLTEuNDEsNS44OHMuNDcsNC4xMSwxLjQxLDUuODVaIi8+CiAgICAgIDxwYXRoIGNsYXNzPSJjbHMtMSIgZD0iTTM5Ljg0LDEuOTJjLjY0LS42NCwxLjQ4LS45NiwyLjUyLS45NnMxLjg4LjMyLDIuNTIuOTZjLjY0LjY0Ljk2LDEuNDguOTYsMi41MnMtLjMyLDEuODgtLjk2LDIuNTJjLS42NC42NC0xLjQ4Ljk2LTIuNTIuOTZzLTEuODgtLjMyLTIuNTItLjk2Yy0uNjQtLjY0LS45Ni0xLjQ4LS45Ni0yLjUycy4zMi0xLjg4Ljk2LTIuNTJaTTM5LjU0LDE4LjQyaDUuNTh2MjdoLTUuNTh2LTI3WiIvPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Ik01My4xNiwxMy4wOGg1LjQ2djQuMDJjLjkyLTEuNTIsMi4xNy0yLjY5LDMuNzUtMy41MSwxLjU4LS44MiwzLjMzLTEuMjMsNS4yNS0xLjIzLDIuMiwwLDQuMjEuNTMsNi4wMywxLjU5LDEuODIsMS4wNiwzLjIxLDIuNDksNC4xNyw0LjI5LDEuMDQtMS44OCwyLjQ1LTMuMzMsNC4yMy00LjM1LDEuNzgtMS4wMiwzLjc1LTEuNTMsNS45MS0xLjUzczQuMjIuNTMsNi4wNiwxLjU5YzEuODQsMS4wNiwzLjMsMi41MSw0LjM4LDQuMzUsMS4wOCwxLjg0LDEuNjIsMy45LDEuNjIsNi4xOHYyMC45NGgtNS42NHYtMTkuMTRjMC0yLjY0LS42OS00LjcyLTIuMDctNi4yNC0xLjM4LTEuNTItMy4xNy0yLjI4LTUuMzctMi4yOHMtNC4wNi43Ny01LjQ2LDIuMzFjLTEuNCwxLjU0LTIuMSwzLjYxLTIuMSw2LjIxdjE5LjE0aC01LjY0di0xOS4xNGMwLTIuNjQtLjY4LTQuNzItMi4wNC02LjI0LTEuMzYtMS41Mi0zLjE2LTIuMjgtNS40LTIuMjhzLTQuMDEuNzctNS40MywyLjMxYy0xLjQyLDEuNTQtMi4xMywzLjYxLTIuMTMsNi4yMXYxOS4xNGgtNS41OFYxMy4wOFoiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJNMTA5LjAyLDQzLjU5Yy0yLTEuNy0zLTMuOTEtMy02LjYzcy44Ny00Ljg1LDIuNjEtNi42M2MxLjc0LTEuNzgsNC4zOS0yLjk3LDcuOTUtMy41N2wxMS4wNC0xLjh2LTEuNWMwLTEuNzYtLjY2LTMuMTktMS45OC00LjI5LTEuMzItMS4xLTMuMDItMS42NS01LjEtMS42NS0xLjg0LDAtMy40Ny40Ny00Ljg5LDEuNDEtMS40Mi45NC0yLjQ3LDIuMTktMy4xNSwzLjc1bC00Ljg2LTIuNTJjLjkyLTIuMjQsMi42LTQuMSw1LjA0LTUuNTgsMi40NC0xLjQ4LDUuMS0yLjIyLDcuOTgtMi4yMiwyLjQ0LDAsNC42MS40Nyw2LjUxLDEuNDEsMS45Ljk0LDMuMzgsMi4yNSw0LjQ0LDMuOTMsMS4wNiwxLjY4LDEuNTksMy42LDEuNTksNS43NnYyMS45NmgtNS40NnYtNC4yYy0xLjE2LDEuNTItMi42OSwyLjcyLTQuNTksMy42LTEuOS44OC00LjAxLDEuMzItNi4zMywxLjMyLTMuMiwwLTUuOC0uODUtNy44LTIuNTVaTTExMy40OSw0MC4wOGMxLjA2Ljg4LDIuMzksMS4zMiwzLjk5LDEuMzIsMS45NiwwLDMuNzEtLjQzLDUuMjUtMS4yOSwxLjU0LS44NiwyLjc0LTIuMDMsMy42LTMuNTEuODYtMS40OCwxLjI5LTMuMTIsMS4yOS00Ljkydi0yLjA0bC05Ljc4LDEuNjJjLTMuOTYuNjgtNS45NCwyLjUyLTUuOTQsNS41MiwwLDEuMzIuNTMsMi40MiwxLjU5LDMuM1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMTUyLjcsNDMuNTljLTItMS43LTMtMy45MS0zLTYuNjNzLjg3LTQuODUsMi42MS02LjYzYzEuNzQtMS43OCw0LjM5LTIuOTcsNy45NS0zLjU3bDExLjA0LTEuOHYtMS41YzAtMS43Ni0uNjYtMy4xOS0xLjk4LTQuMjktMS4zMi0xLjEtMy4wMi0xLjY1LTUuMS0xLjY1LTEuODQsMC0zLjQ3LjQ3LTQuODksMS40MS0xLjQyLjk0LTIuNDcsMi4xOS0zLjE1LDMuNzVsLTQuODYtMi41MmMuOTItMi4yNCwyLjYtNC4xLDUuMDQtNS41OCwyLjQ0LTEuNDgsNS4xLTIuMjIsNy45OC0yLjIyLDIuNDQsMCw0LjYxLjQ3LDYuNTEsMS40MSwxLjkuOTQsMy4zOCwyLjI1LDQuNDQsMy45MywxLjA2LDEuNjgsMS41OSwzLjYsMS41OSw1Ljc2djIxLjk2aC01LjQ2di00LjJjLTEuMTYsMS41Mi0yLjY5LDIuNzItNC41OSwzLjYtMS45Ljg4LTQuMDEsMS4zMi02LjMzLDEuMzItMy4yLDAtNS44LS44NS03LjgtMi41NVpNMTU3LjE3LDQwLjA4YzEuMDYuODgsMi4zOSwxLjMyLDMuOTksMS4zMiwxLjk2LDAsMy43MS0uNDMsNS4yNS0xLjI5LDEuNTQtLjg2LDIuNzQtMi4wMywzLjYtMy41MS44Ni0xLjQ4LDEuMjktMy4xMiwxLjI5LTQuOTJ2LTIuMDRsLTkuNzgsMS42MmMtMy45Ni42OC01Ljk0LDIuNTItNS45NCw1LjUyLDAsMS4zMi41MywyLjQyLDEuNTksMy4zWiIvPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0xODQuOTIsMTMuMDhoNS40NnYzLjk2Yy45Ni0xLjUyLDIuMjQtMi42OCwzLjg0LTMuNDhzMy40LTEuMiw1LjQtMS4yYzIuMjgsMCw0LjM0LjUzLDYuMTgsMS41OSwxLjg0LDEuMDYsMy4yOSwyLjUxLDQuMzUsNC4zNSwxLjA2LDEuODQsMS41OSwzLjksMS41OSw2LjE4djIwLjk0aC01LjY0di0xOS4xNGMwLTIuNjQtLjcxLTQuNzItMi4xMy02LjI0LTEuNDItMS41Mi0zLjI5LTIuMjgtNS42MS0yLjI4cy00LjIxLjc3LTUuNjcsMi4zMWMtMS40NiwxLjU0LTIuMTksMy42MS0yLjE5LDYuMjF2MTkuMTRoLTUuNThWMTMuMDhaIi8+CiAgICAgIDxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTIyMC44LDQzLjU5Yy0yLTEuNy0zLTMuOTEtMy02LjYzcy44Ny00Ljg1LDIuNjEtNi42M2MxLjc0LTEuNzgsNC4zOS0yLjk3LDcuOTUtMy41N2wxMS4wNC0xLjh2LTEuNWMwLTEuNzYtLjY2LTMuMTktMS45OC00LjI5LTEuMzItMS4xLTMuMDItMS42NS01LjEtMS42NS0xLjg0LDAtMy40Ny40Ny00Ljg5LDEuNDEtMS40Mi45NC0yLjQ3LDIuMTktMy4xNSwzLjc1bC00Ljg2LTIuNTJjLjkyLTIuMjQsMi42LTQuMSw1LjA0LTUuNTgsMi40NC0xLjQ4LDUuMS0yLjIyLDcuOTgtMi4yMiwyLjQ0LDAsNC42MS40Nyw2LjUxLDEuNDEsMS45Ljk0LDMuMzgsMi4yNSw0LjQ0LDMuOTMsMS4wNiwxLjY4LDEuNTksMy42LDEuNTksNS43NnYyMS45NmgtNS40NnYtNC4yYy0xLjE2LDEuNTItMi42OSwyLjcyLTQuNTksMy42LTEuOS44OC00LjAxLDEuMzItNi4zMywxLjMyLTMuMiwwLTUuOC0uODUtNy44LTIuNTVaTTIyNS4yNyw0MC4wOGMxLjA2Ljg4LDIuMzksMS4zMiwzLjk5LDEuMzIsMS45NiwwLDMuNzEtLjQzLDUuMjUtMS4yOSwxLjU0LS44NiwyLjc0LTIuMDMsMy42LTMuNTEuODYtMS40OCwxLjI5LTMuMTIsMS4yOS00Ljkydi0yLjA0bC05Ljc4LDEuNjJjLTMuOTYuNjgtNS45NCwyLjUyLTUuOTQsNS41MiwwLDEuMzIuNTMsMi40MiwxLjU5LDMuM1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMjUzLjAyLDBoNS41OHY0NS40MmgtNS41OFYwWiIvPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0yNzUuODIsNDUuMzZsLTEyLjg0LTMyLjI4aDYuMDZsOS44NCwyNS4yNiw5Ljc4LTI1LjI2aDYuMThsLTE3Ljg4LDQ0LjM0aC02LjE4bDUuMDQtMTIuMDZaIi8+CiAgICAgIDxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTMwNS4wNyw0My4xMWMtMS43LTEuNzgtMi41NS00LjMzLTIuNTUtNy42NXYtMTcuMDRoLTUuODh2LTUuMzRoMS4yYzEuNDQsMCwyLjU4LS40MywzLjQyLTEuMjkuODQtLjg2LDEuMjYtMi4wMywxLjI2LTMuNTF2LTIuNjRoNS41OHY3LjQ0aDcuMjZ2NS4zNGgtNy4yNnYxNi44NmMwLDMuNiwxLjgsNS40LDUuNCw1LjQuNzYsMCwxLjUtLjA2LDIuMjItLjE4djQuOThjLS44NC4yLTEuOTYuMy0zLjM2LjMtMy4xNiwwLTUuNTktLjg5LTcuMjktMi42N1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzIyLjY4LDEuOTJjLjY0LS42NCwxLjQ4LS45NiwyLjUyLS45NnMxLjg4LjMyLDIuNTIuOTZjLjY0LjY0Ljk2LDEuNDguOTYsMi41MnMtLjMyLDEuODgtLjk2LDIuNTJjLS42NC42NC0xLjQ4Ljk2LTIuNTIuOTZzLTEuODgtLjMyLTIuNTItLjk2Yy0uNjQtLjY0LS45Ni0xLjQ4LS45Ni0yLjUycy4zMi0xLjg4Ljk2LTIuNTJaTTMyMi4zOCwxOC40Mmg1LjU4djI3aC01LjU4di0yN1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzQyLjQ4LDQzLjkyYy0yLjUyLTEuNDgtNC40OC0zLjUxLTUuODgtNi4wOS0xLjQtMi41OC0yLjEtNS40NS0yLjEtOC42MXMuNy02LjA4LDIuMS04LjY0YzEuNC0yLjU2LDMuMzUtNC41Nyw1Ljg1LTYuMDMsMi41LTEuNDYsNS4zNS0yLjE5LDguNTUtMi4xOXM1Ljk3LjgxLDguNTUsMi40Myw0LjQxLDMuNzEsNS40OSw2LjI3bC01LjA0LDIuNGMtLjc2LTEuNzItMS45NS0zLjEtMy41Ny00LjE0LTEuNjItMS4wNC0zLjQzLTEuNTYtNS40My0xLjU2cy0zLjc1LjUtNS4zNywxLjVjLTEuNjIsMS0yLjg5LDIuMzctMy44MSw0LjExLS45MiwxLjc0LTEuMzgsMy43MS0xLjM4LDUuOTFzLjQ3LDQuMTEsMS40MSw1Ljg1Yy45NCwxLjc0LDIuMjEsMy4xMSwzLjgxLDQuMTEsMS42LDEsMy4zOCwxLjUsNS4zNCwxLjVzMy44Ni0uNTIsNS40Ni0xLjU2YzEuNi0xLjA0LDIuNzgtMi40NiwzLjU0LTQuMjZsNS4wNCwyLjUyYy0xLjA0LDIuNTItMi44Niw0LjYtNS40Niw2LjI0LTIuNiwxLjY0LTUuNDYsMi40Ni04LjU4LDIuNDZzLTYtLjc0LTguNTItMi4yMloiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzc0Ljg4LDQzLjgzYy0yLjQtMS41NC00LjEyLTMuNjMtNS4xNi02LjI3bDQuNS0yLjI4Yy45MiwxLjg4LDIuMTgsMy4zNiwzLjc4LDQuNDQsMS42LDEuMDgsMy4zNCwxLjYyLDUuMjIsMS42MnMzLjI4LS40Miw0LjQ0LTEuMjZjMS4xNi0uODQsMS43NC0xLjk0LDEuNzQtMy4zcy0uNTItMi4zOS0xLjU2LTMuMjFjLTEuMDQtLjgyLTIuMTYtMS4zMS0zLjM2LTEuNDdsLTQuODYtLjY2Yy0yLjg4LS43Mi01LjA0LTEuOTItNi40OC0zLjYtMS40NC0xLjY4LTIuMTYtMy42Ni0yLjE2LTUuOTQsMC0xLjg4LjQ5LTMuNTQsMS40Ny00Ljk4Ljk4LTEuNDQsMi4zNC0yLjU2LDQuMDgtMy4zNiwxLjc0LS44LDMuNjctMS4yLDUuNzktMS4yLDIuOCwwLDUuMzEuNyw3LjUzLDIuMSwyLjIyLDEuNCwzLjgxLDMuMzQsNC43Nyw1LjgybC00LjQ0LDIuMjhjLS44LTEuNjQtMS45MS0yLjk0LTMuMzMtMy45LTEuNDItLjk2LTIuOTktMS40NC00LjcxLTEuNDRzLTIuOTYuNC0zLjk2LDEuMmMtMSwuOC0xLjUsMS44NC0xLjUsMy4xMnMuNDcsMi4zNywxLjQxLDMuMTVjLjk0Ljc4LDEuOTcsMS4yNywzLjA5LDEuNDdsNS4zNC43MmMyLjY4LjcyLDQuNzcsMS45NSw2LjI3LDMuNjksMS41LDEuNzQsMi4yNSwzLjc1LDIuMjUsNi4wMywwLDEuODQtLjUsMy40OC0xLjUsNC45Mi0xLDEuNDQtMi40LDIuNTctNC4yLDMuMzktMS44LjgyLTMuODYsMS4yMy02LjE4LDEuMjMtMy4xMiwwLTUuODgtLjc3LTguMjgtMi4zMVoiLz4KICAgIDwvZz4KICA8L2c+Cjwvc3ZnPg==';
$pimaLogoLight = 'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyBpZD0iRWJlbmVfMiIgZGF0YS1uYW1lPSJFYmVuZSAyIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzOTUuMDQgNTcuNDIiPgogIDxkZWZzPgogICAgPHN0eWxlPgogICAgICAuY2xzLTEgewogICAgICAgIGZpbGw6ICMzMzM7CiAgICAgIH0KCiAgICAgIC5jbHMtMiB7CiAgICAgICAgZmlsbDogIzA4OTQ4ODsKICAgICAgfQogICAgPC9zdHlsZT4KICA8L2RlZnM+CiAgPGcgaWQ9IkViZW5lXzEtMiIgZGF0YS1uYW1lPSJFYmVuZSAxIj4KICAgIDxnPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Ik0wLDEzLjA4aDUuNDZ2NC41YzEuMjgtMS42NCwyLjg5LTIuOTIsNC44My0zLjg0LDEuOTQtLjkyLDQuMTEtMS4zOCw2LjUxLTEuMzgsMywwLDUuNzIuNzQsOC4xNiwyLjIyLDIuNDQsMS40OCw0LjM2LDMuNTEsNS43Niw2LjA5LDEuNCwyLjU4LDIuMSw1LjQ1LDIuMSw4LjYxcy0uNyw2LjAyLTIuMSw4LjU4Yy0xLjQsMi41Ni0zLjMyLDQuNTgtNS43Niw2LjA2LTIuNDQsMS40OC01LjE4LDIuMjItOC4yMiwyLjIyLTIuMzIsMC00LjQ1LS40NS02LjM5LTEuMzVzLTMuNTMtMi4xOS00Ljc3LTMuODd2MTYuNUgwVjEzLjA4Wk02Ljk5LDM1LjEzYy45NCwxLjc0LDIuMjMsMy4xMSwzLjg3LDQuMTEsMS42NCwxLDMuNDYsMS41LDUuNDYsMS41czMuODEtLjUsNS40My0xLjVjMS42Mi0xLDIuODgtMi4zNywzLjc4LTQuMTEuOS0xLjc0LDEuMzUtMy42OSwxLjM1LTUuODVzLS40Ni00LjEyLTEuMzgtNS44OGMtLjkyLTEuNzYtMi4xOC0zLjE0LTMuNzgtNC4xNC0xLjYtMS0zLjQtMS41LTUuNC0xLjVzLTMuODIuNS01LjQ2LDEuNWMtMS42NCwxLTIuOTMsMi4zOC0zLjg3LDQuMTQtLjk0LDEuNzYtMS40MSwzLjcyLTEuNDEsNS44OHMuNDcsNC4xMSwxLjQxLDUuODVaIi8+CiAgICAgIDxwYXRoIGNsYXNzPSJjbHMtMSIgZD0iTTM5Ljg0LDEuOTJjLjY0LS42NCwxLjQ4LS45NiwyLjUyLS45NnMxLjg4LjMyLDIuNTIuOTZjLjY0LjY0Ljk2LDEuNDguOTYsMi41MnMtLjMyLDEuODgtLjk2LDIuNTJjLS42NC42NC0xLjQ4Ljk2LTIuNTIuOTZzLTEuODgtLjMyLTIuNTItLjk2Yy0uNjQtLjY0LS45Ni0xLjQ4LS45Ni0yLjUycy4zMi0xLjg4Ljk2LTIuNTJaTTM5LjU0LDE4LjQyaDUuNTh2MjdoLTUuNTh2LTI3WiIvPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTEiIGQ9Ik01My4xNiwxMy4wOGg1LjQ2djQuMDJjLjkyLTEuNTIsMi4xNy0yLjY5LDMuNzUtMy41MSwxLjU4LS44MiwzLjMzLTEuMjMsNS4yNS0xLjIzLDIuMiwwLDQuMjEuNTMsNi4wMywxLjU5LDEuODIsMS4wNiwzLjIxLDIuNDksNC4xNyw0LjI5LDEuMDQtMS44OCwyLjQ1LTMuMzMsNC4yMy00LjM1LDEuNzgtMS4wMiwzLjc1LTEuNTMsNS45MS0xLjUzczQuMjIuNTMsNi4wNiwxLjU5YzEuODQsMS4wNiwzLjMsMi41MSw0LjM4LDQuMzUsMS4wOCwxLjg0LDEuNjIsMy45LDEuNjIsNi4xOHYyMC45NGgtNS42NHYtMTkuMTRjMC0yLjY0LS42OS00LjcyLTIuMDctNi4yNC0xLjM4LTEuNTItMy4xNy0yLjI4LTUuMzctMi4yOHMtNC4wNi43Ny01LjQ2LDIuMzFjLTEuNCwxLjU0LTIuMSwzLjYxLTIuMSw2LjIxdjE5LjE0aC01LjY0di0xOS4xNGMwLTIuNjQtLjY4LTQuNzItMi4wNC02LjI0LTEuMzYtMS41Mi0zLjE2LTIuMjgtNS40LTIuMjhzLTQuMDEuNzctNS40MywyLjMxYy0xLjQyLDEuNTQtMi4xMywzLjYxLTIuMTMsNi4yMXYxOS4xNGgtNS41OFYxMy4wOFoiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0xIiBkPSJNMTA5LjAyLDQzLjU5Yy0yLTEuNy0zLTMuOTEtMy02LjYzcy44Ny00Ljg1LDIuNjEtNi42M2MxLjc0LTEuNzgsNC4zOS0yLjk3LDcuOTUtMy41N2wxMS4wNC0xLjh2LTEuNWMwLTEuNzYtLjY2LTMuMTktMS45OC00LjI5LTEuMzItMS4xLTMuMDItMS42NS01LjEtMS42NS0xLjg0LDAtMy40Ny40Ny00Ljg5LDEuNDEtMS40Mi45NC0yLjQ3LDIuMTktMy4xNSwzLjc1bC00Ljg2LTIuNTJjLjkyLTIuMjQsMi42LTQuMSw1LjA0LTUuNTgsMi40NC0xLjQ4LDUuMS0yLjIyLDcuOTgtMi4yMiwyLjQ0LDAsNC42MS40Nyw2LjUxLDEuNDEsMS45Ljk0LDMuMzgsMi4yNSw0LjQ0LDMuOTMsMS4wNiwxLjY4LDEuNTksMy42LDEuNTksNS43NnYyMS45NmgtNS40NnYtNC4yYy0xLjE2LDEuNTItMi42OSwyLjcyLTQuNTksMy42LTEuOS44OC00LjAxLDEuMzItNi4zMywxLjMyLTMuMiwwLTUuOC0uODUtNy44LTIuNTVaTTExMy40OSw0MC4wOGMxLjA2Ljg4LDIuMzksMS4zMiwzLjk5LDEuMzIsMS45NiwwLDMuNzEtLjQzLDUuMjUtMS4yOSwxLjU0LS44NiwyLjc0LTIuMDMsMy42LTMuNTEuODYtMS40OCwxLjI5LTMuMTIsMS4yOS00Ljkydi0yLjA0bC05Ljc4LDEuNjJjLTMuOTYuNjgtNS45NCwyLjUyLTUuOTQsNS41MiwwLDEuMzIuNTMsMi40MiwxLjU5LDMuM1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMTUyLjcsNDMuNTljLTItMS43LTMtMy45MS0zLTYuNjNzLjg3LTQuODUsMi42MS02LjYzYzEuNzQtMS43OCw0LjM5LTIuOTcsNy45NS0zLjU3bDExLjA0LTEuOHYtMS41YzAtMS43Ni0uNjYtMy4xOS0xLjk4LTQuMjktMS4zMi0xLjEtMy4wMi0xLjY1LTUuMS0xLjY1LTEuODQsMC0zLjQ3LjQ3LTQuODksMS40MS0xLjQyLjk0LTIuNDcsMi4xOS0zLjE1LDMuNzVsLTQuODYtMi41MmMuOTItMi4yNCwyLjYtNC4xLDUuMDQtNS41OCwyLjQ0LTEuNDgsNS4xLTIuMjIsNy45OC0yLjIyLDIuNDQsMCw0LjYxLjQ3LDYuNTEsMS40MSwxLjkuOTQsMy4zOCwyLjI1LDQuNDQsMy45MywxLjA2LDEuNjgsMS41OSwzLjYsMS41OSw1Ljc2djIxLjk2aC01LjQ2di00LjJjLTEuMTYsMS41Mi0yLjY5LDIuNzItNC41OSwzLjYtMS45Ljg4LTQuMDEsMS4zMi02LjMzLDEuMzItMy4yLDAtNS44LS44NS03LjgtMi41NVpNMTU3LjE3LDQwLjA4YzEuMDYuODgsMi4zOSwxLjMyLDMuOTksMS4zMiwxLjk2LDAsMy43MS0uNDMsNS4yNS0xLjI5LDEuNTQtLjg2LDIuNzQtMi4wMywzLjYtMy41MS44Ni0xLjQ4LDEuMjktMy4xMiwxLjI5LTQuOTJ2LTIuMDRsLTkuNzgsMS42MmMtMy45Ni42OC01Ljk0LDIuNTItNS45NCw1LjUyLDAsMS4zMi41MywyLjQyLDEuNTksMy4zWiIvPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0xODQuOTIsMTMuMDhoNS40NnYzLjk2Yy45Ni0xLjUyLDIuMjQtMi42OCwzLjg0LTMuNDhzMy40LTEuMiw1LjQtMS4yYzIuMjgsMCw0LjM0LjUzLDYuMTgsMS41OSwxLjg0LDEuMDYsMy4yOSwyLjUxLDQuMzUsNC4zNSwxLjA2LDEuODQsMS41OSwzLjksMS41OSw2LjE4djIwLjk0aC01LjY0di0xOS4xNGMwLTIuNjQtLjcxLTQuNzItMi4xMy02LjI0LTEuNDItMS41Mi0zLjI5LTIuMjgtNS42MS0yLjI4cy00LjIxLjc3LTUuNjcsMi4zMWMtMS40NiwxLjU0LTIuMTksMy42MS0yLjE5LDYuMjF2MTkuMTRoLTUuNThWMTMuMDhaIi8+CiAgICAgIDxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTIyMC44LDQzLjU5Yy0yLTEuNy0zLTMuOTEtMy02LjYzcy44Ny00Ljg1LDIuNjEtNi42M2MxLjc0LTEuNzgsNC4zOS0yLjk3LDcuOTUtMy41N2wxMS4wNC0xLjh2LTEuNWMwLTEuNzYtLjY2LTMuMTktMS45OC00LjI5LTEuMzItMS4xLTMuMDItMS42NS01LjEtMS42NS0xLjg0LDAtMy40Ny40Ny00Ljg5LDEuNDEtMS40Mi45NC0yLjQ3LDIuMTktMy4xNSwzLjc1bC00Ljg2LTIuNTJjLjkyLTIuMjQsMi42LTQuMSw1LjA0LTUuNTgsMi40NC0xLjQ4LDUuMS0yLjIyLDcuOTgtMi4yMiwyLjQ0LDAsNC42MS40Nyw2LjUxLDEuNDEsMS45Ljk0LDMuMzgsMi4yNSw0LjQ0LDMuOTMsMS4wNiwxLjY4LDEuNTksMy42LDEuNTksNS43NnYyMS45NmgtNS40NnYtNC4yYy0xLjE2LDEuNTItMi42OSwyLjcyLTQuNTksMy42LTEuOS44OC00LjAxLDEuMzItNi4zMywxLjMyLTMuMiwwLTUuOC0uODUtNy44LTIuNTVaTTIyNS4yNyw0MC4wOGMxLjA2Ljg4LDIuMzksMS4zMiwzLjk5LDEuMzIsMS45NiwwLDMuNzEtLjQzLDUuMjUtMS4yOSwxLjU0LS44NiwyLjc0LTIuMDMsMy42LTMuNTEuODYtMS40OCwxLjI5LTMuMTIsMS4yOS00Ljkydi0yLjA0bC05Ljc4LDEuNjJjLTMuOTYuNjgtNS45NCwyLjUyLTUuOTQsNS41MiwwLDEuMzIuNTMsMi40MiwxLjU5LDMuM1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMjUzLjAyLDBoNS41OHY0NS40MmgtNS41OFYwWiIvPgogICAgICA8cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik0yNzUuODIsNDUuMzZsLTEyLjg0LTMyLjI4aDYuMDZsOS44NCwyNS4yNiw5Ljc4LTI1LjI2aDYuMThsLTE3Ljg4LDQ0LjM0aC02LjE4bDUuMDQtMTIuMDZaIi8+CiAgICAgIDxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTMwNS4wNyw0My4xMWMtMS43LTEuNzgtMi41NS00LjMzLTIuNTUtNy42NXYtMTcuMDRoLTUuODh2LTUuMzRoMS4yYzEuNDQsMCwyLjU4LS40MywzLjQyLTEuMjkuODQtLjg2LDEuMjYtMi4wMywxLjI2LTMuNTF2LTIuNjRoNS41OHY3LjQ0aDcuMjZ2NS4zNGgtNy4yNnYxNi44NmMwLDMuNiwxLjgsNS40LDUuNCw1LjQuNzYsMCwxLjUtLjA2LDIuMjItLjE4djQuOThjLS44NC4yLTEuOTYuMy0zLjM2LjMtMy4xNiwwLTUuNTktLjg5LTcuMjktMi42N1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzIyLjY4LDEuOTJjLjY0LS42NCwxLjQ4LS45NiwyLjUyLS45NnMxLjg4LjMyLDIuNTIuOTZjLjY0LjY0Ljk2LDEuNDguOTYsMi41MnMtLjMyLDEuODgtLjk2LDIuNTJjLS42NC42NC0xLjQ4Ljk2LTIuNTIuOTZzLTEuODgtLjMyLTIuNTItLjk2Yy0uNjQtLjY0LS45Ni0xLjQ4LS45Ni0yLjUycy4zMi0xLjg4Ljk2LTIuNTJaTTMyMi4zOCwxOC40Mmg1LjU4djI3aC01LjU4di0yN1oiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzQyLjQ4LDQzLjkyYy0yLjUyLTEuNDgtNC40OC0zLjUxLTUuODgtNi4wOS0xLjQtMi41OC0yLjEtNS40NS0yLjEtOC42MXMuNy02LjA4LDIuMS04LjY0YzEuNC0yLjU2LDMuMzUtNC41Nyw1Ljg1LTYuMDMsMi41LTEuNDYsNS4zNS0yLjE5LDguNTUtMi4xOXM1Ljk3LjgxLDguNTUsMi40Myw0LjQxLDMuNzEsNS40OSw2LjI3bC01LjA0LDIuNGMtLjc2LTEuNzItMS45NS0zLjEtMy41Ny00LjE0LTEuNjItMS4wNC0zLjQzLTEuNTYtNS40My0xLjU2cy0zLjc1LjUtNS4zNywxLjVjLTEuNjIsMS0yLjg5LDIuMzctMy44MSw0LjExLS45MiwxLjc0LTEuMzgsMy43MS0xLjM4LDUuOTFzLjQ3LDQuMTEsMS40MSw1Ljg1Yy45NCwxLjc0LDIuMjEsMy4xMSwzLjgxLDQuMTEsMS42LDEsMy4zOCwxLjUsNS4zNCwxLjVzMy44Ni0uNTIsNS40Ni0xLjU2YzEuNi0xLjA0LDIuNzgtMi40NiwzLjU0LTQuMjZsNS4wNCwyLjUyYy0xLjA0LDIuNTItMi44Niw0LjYtNS40Niw2LjI0LTIuNiwxLjY0LTUuNDYsMi40Ni04LjU4LDIuNDZzLTYtLjc0LTguNTItMi4yMloiLz4KICAgICAgPHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMzc0Ljg4LDQzLjgzYy0yLjQtMS41NC00LjEyLTMuNjMtNS4xNi02LjI3bDQuNS0yLjI4Yy45MiwxLjg4LDIuMTgsMy4zNiwzLjc4LDQuNDQsMS42LDEuMDgsMy4zNCwxLjYyLDUuMjIsMS42MnMzLjI4LS40Miw0LjQ0LTEuMjZjMS4xNi0uODQsMS43NC0xLjk0LDEuNzQtMy4zcy0uNTItMi4zOS0xLjU2LTMuMjFjLTEuMDQtLjgyLTIuMTYtMS4zMS0zLjM2LTEuNDdsLTQuODYtLjY2Yy0yLjg4LS43Mi01LjA0LTEuOTItNi40OC0zLjYtMS40NC0xLjY4LTIuMTYtMy42Ni0yLjE2LTUuOTQsMC0xLjg4LjQ5LTMuNTQsMS40Ny00Ljk4Ljk4LTEuNDQsMi4zNC0yLjU2LDQuMDgtMy4zNiwxLjc0LS44LDMuNjctMS4yLDUuNzktMS4yLDIuOCwwLDUuMzEuNyw3LjUzLDIuMSwyLjIyLDEuNCwzLjgxLDMuMzQsNC43Nyw1LjgybC00LjQ0LDIuMjhjLS44LTEuNjQtMS45MS0yLjk0LTMuMzMtMy45LTEuNDItLjk2LTIuOTktMS40NC00LjcxLTEuNDRzLTIuOTYuNC0zLjk2LDEuMmMtMSwuOC0xLjUsMS44NC0xLjUsMy4xMnMuNDcsMi4zNywxLjQxLDMuMTVjLjk0Ljc4LDEuOTcsMS4yNywzLjA5LDEuNDdsNS4zNC43MmMyLjY4LjcyLDQuNzcsMS45NSw2LjI3LDMuNjksMS41LDEuNzQsMi4yNSwzLjc1LDIuMjUsNi4wMywwLDEuODQtLjUsMy40OC0xLjUsNC45Mi0xLDEuNDQtMi40LDIuNTctNC4yLDMuMzktMS44LjgyLTMuODYsMS4yMy02LjE4LDEuMjMtMy4xMiwwLTUuODgtLjc3LTguMjgtMi4zMVoiLz4KICAgIDwvZz4KICA8L2c+Cjwvc3ZnPg==';


// ---- Language strings ----
$strings = [
    'en' => [
        'dashboard'        => 'Analytics dashboard',
        'tagline'          => 'measure more. manage less.',
        'login_btn'        => 'Sign in',
        'wrong_password'   => 'That password is not correct.',
        'auth_unavailable' => 'Signing in is not possible right now: pima-cache is not writable. (Code T15)',
        'attempts_left'    => '%d attempt%s remaining before lockout.',
        'locked_out'       => 'Too many failed attempts. Please try again in %s.',
        'summary'             => 'Your site had <strong>%1$s pageviews</strong> %2$s.',
        'summary_avg_full'    => 'That is <strong>%s</strong> per day on average.',
        'summary_avg_partial' => 'That is <strong>%s</strong> per day on average (%d day%s of data so far).',
        'all_time_total'   => '%s pageviews in total',
        'range_nav'        => 'Period',
        'range_today'      => 'Today',
        'range_yesterday'  => 'Yesterday',
        'range_7d'         => 'Last 7 days',
        'range_30d'        => 'Last 30 days',
        'range_last_month' => 'Last month',
        'range_12m'        => 'Last 12 months',
        'phrase_today'      => 'today',
        'phrase_yesterday'  => 'yesterday',
        'phrase_7d'         => 'in the last 7 days',
        'phrase_30d'        => 'in the last 30 days',
        'phrase_last_month' => 'last month',
        'phrase_12m'        => 'in the last 12 months',
        'vs_prev'          => 'vs. previous period',
        'pp'               => 'pp',
        'prev_period'      => 'Previous period',
        'no_prev'          => 'no comparison yet',
        'week_of'          => 'Week of %s',
        'filter_label'     => 'Filtered by',
        'filter_by'        => 'Filter by',
        'filter_remove'    => 'Remove filter',
        'filter_clear'     => 'Clear all',
        'f_page'           => 'Page',
        'f_ref'            => 'Referrer',
        'f_country'        => 'Country',
        'f_device'         => 'Device',
        'f_lang'           => 'Language',
        'kpi_views'        => 'Pageviews',
        'kpi_visitors'     => 'Visitors',
        'counted_daily'    => 'counted daily',
        'tip_views'        => 'Pages opened on your site.',
        'tip_visitors'     => 'People who visited your site.',
        'sessions'         => 'Visits',
        'bounce_rate'      => 'Bounce rate',
        'views_per_session'=> 'Pages per visit',
        'session_duration' => 'Visit duration',
        'tip_sessions'     => 'How often people came to your site.',
        'tip_bounce'       => 'Visits that ended after one page. Lower is better.',
        'tip_views_per_session' => 'How many pages a visit includes on average.',
        'tip_duration'     => 'How long a visit lasts on average.',
        'chart_title'      => 'Trend',
        'chart_metric'     => 'Metric',
        'chart_aria'       => 'Line chart for %s compared with the previous period.',
        'tip_chart'        => 'Dashed: the previous period.',
        'top_pages'        => 'Top pages',
        'referrers'        => 'Referrers',
        'entry_pages'      => 'Entry pages',
        'exit_pages'       => 'Exit pages',
        'session_depth'    => 'Pages per visit',
        'depth_1'          => '1 page',
        'depth_2'          => '2 pages',
        'depth_3'          => '3–4 pages',
        'depth_5'          => '5 or more pages',
        'browser_lang'     => 'Browser language',
        'time_of_day'      => 'Time of day',
        'heatmap_title'    => 'Weekday and hour',
        'peak'             => 'Peak',
        'views'            => 'pageviews',
        'device_type'      => 'Device type',
        'top_countries'    => 'Top countries',
        'channels'         => 'Traffic channels',
        'ch_direct'        => 'Direct',
        'ch_organic'       => 'Organic search',
        'ch_social'        => 'Social',
        'ch_referral'      => 'Referral',
        'tip_channels'     => 'How visitors found your site.',
        'recent_sessions'  => 'Latest %d visits',
        'today_short'      => 'Today',
        'yesterday_short'  => 'Yesterday',
        'pages_count'      => '%d pages',
        'more_pages'       => '+%d more',
        'live_label'       => '%d active',
        'tip_live'         => 'Visitors in the last 5 minutes.',
        'theme_toggle'     => 'Switch between light and dark',
        'show'             => 'Show',
        'hide'             => 'Hide',
        'no_data'          => 'No data yet — add the tracking snippet to your site to get started.',
        'no_pages'         => 'No data in this period',
        'no_referrers'     => 'No referrers in this period',
        'no_external'      => 'No external traffic in this period',
        'no_channels'      => 'No classified entries in this period',
        'no_lang'          => 'No data in this period',
        'no_geo'           => 'Geo disabled or no data',
        'no_sessions'      => 'No visits in this period',
        'device_desktop'   => 'Desktop',
        'device_mobile'    => 'Mobile',
        'device_tablet'    => 'Tablet',
        'refresh'          => 'Refresh',
        'logout'           => 'Sign out',
        'back_to_site'     => '↗ Visit website',
        'export'           => '↓ Export CSV',
        'rows'             => 'entries',
        'cleared'          => 'All data cleared.',
        'danger_title'     => '⚠ Danger zone',
        'danger_desc'      => 'These actions cannot be undone.',
        'clear_btn'        => 'Clear all data',
        'confirm_msg'      => 'Permanently delete all %s entries?',
        'confirm_btn'      => 'Yes, delete everything',
        'tip_pages'        => 'Your most visited pages and their change from the previous period.',
        'tip_referrers'    => 'Websites that sent visitors to you.',
        'tip_entry'        => 'Pages where visitors from other websites arrived.',
        'tip_exit'         => 'Pages where visits ended, with their exit rate.',
        'tip_depth'        => 'How many pages visits include.',
        'tip_lang'         => 'The language of your visitors\' browsers.',
        'tip_tod'          => 'When your site is visited.',
        'tip_heatmap'      => 'When your site is visited during the week.',
        'tip_device'       => 'Devices your visitors use.',
        'tip_countries'    => 'Where your visitors are.',
        'warn_default_pw'  => 'Sign-in is disabled until a password of your own is set as STATS_PASSWORD in pima-core.php. (Code T8)',
        'password_ph'      => 'Password',
        'login_help'       => 'Forgot your password? Whoever looks after your website can reset it.',
        'pw_link'          => 'Change password',
        'pw_title'         => 'Change password',
        'pw_current'       => 'Current password',
        'pw_new'           => 'New password',
        'pw_repeat'        => 'Repeat new password',
        'pw_rule'          => 'At least 10 characters.',
        'pw_btn'           => 'Change password',
        'pw_back'          => '← Back to dashboard',
        'pw_done'          => 'Password changed.',
        'pw_err_session'   => 'The page was open for too long. Please try again.',
        'pw_err_current'   => 'The current password is wrong.',
        'pw_err_repeat'    => 'The new passwords do not match.',
        'pw_err_short'     => 'The new password needs at least 10 characters.',
        'pw_err_same'      => 'The new password is the same as the current one.',
        'pw_err_write'     => 'The password could not be saved. Check that pima-cache is writable. (Code T20)',
        'pw_err_file'      => 'Sign-in is locked: the password file pima-cache/.pima-password is damaged. Delete it to fall back to the password in pima-core.php. (Code T20)',
    ],
    'de' => [
        'dashboard'        => 'Analyse-Dashboard',
        'tagline'          => 'mehr messen. weniger verwalten.',
        'login_btn'        => 'Anmelden',
        'wrong_password'   => 'Das Passwort stimmt nicht.',
        'auth_unavailable' => 'Die Anmeldung ist gerade nicht möglich: pima-cache ist nicht beschreibbar. (Code T15)',
        'attempts_left'    => 'Noch %d Versuch%s bis zur Sperre.',
        'locked_out'       => 'Zu viele Fehlversuche. Bitte versuchen Sie es in %s erneut.',
        'summary'             => 'Ihre Website hatte %2$s <strong>%1$s Seitenaufrufe</strong>.',
        'summary_avg_full'    => 'Das sind im Schnitt <strong>%s</strong> pro Tag.',
        'summary_avg_partial' => 'Das sind im Schnitt <strong>%s</strong> pro Tag (bisher %d Tag%s mit Daten).',
        'all_time_total'   => '%s Seitenaufrufe insgesamt',
        'range_nav'        => 'Zeitraum',
        'range_today'      => 'Heute',
        'range_yesterday'  => 'Gestern',
        'range_7d'         => 'Letzte 7 Tage',
        'range_30d'        => 'Letzte 30 Tage',
        'range_last_month' => 'Letzter Monat',
        'range_12m'        => 'Letzte 12 Monate',
        'phrase_today'      => 'heute',
        'phrase_yesterday'  => 'gestern',
        'phrase_7d'         => 'in den letzten 7 Tagen',
        'phrase_30d'        => 'in den letzten 30 Tagen',
        'phrase_last_month' => 'letzten Monat',
        'phrase_12m'        => 'in den letzten 12 Monaten',
        'vs_prev'          => 'vs. Vorperiode',
        'pp'               => 'PP',
        'prev_period'      => 'Vorperiode',
        'no_prev'          => 'noch kein Vergleich',
        'week_of'          => 'Woche ab %s',
        'filter_label'     => 'Gefiltert nach',
        'filter_by'        => 'Filtern nach',
        'filter_remove'    => 'Filter entfernen',
        'filter_clear'     => 'Alle entfernen',
        'f_page'           => 'Seite',
        'f_ref'            => 'Herkunft',
        'f_country'        => 'Land',
        'f_device'         => 'Gerät',
        'f_lang'           => 'Sprache',
        'kpi_views'        => 'Seitenaufrufe',
        'kpi_visitors'     => 'Besucher',
        'counted_daily'    => 'täglich gezählt',
        'tip_views'        => 'Aufgerufene Seiten Ihrer Website.',
        'tip_visitors'     => 'Personen, die Ihre Website besucht haben.',
        'sessions'         => 'Besuche',
        'bounce_rate'      => 'Absprungrate',
        'views_per_session'=> 'Seiten pro Besuch',
        'session_duration' => 'Besuchsdauer',
        'tip_sessions'     => 'Wie oft Personen auf Ihre Website kamen.',
        'tip_bounce'       => 'Besuche, die nach einer Seite endeten. Niedriger ist besser.',
        'tip_views_per_session' => 'Wie viele Seiten ein Besuch im Schnitt umfasst.',
        'tip_duration'     => 'Wie lange ein Besuch im Schnitt dauert.',
        'chart_title'      => 'Verlauf',
        'chart_metric'     => 'Kennzahl',
        'chart_aria'       => 'Liniendiagramm für %s im Vergleich zur Vorperiode.',
        'tip_chart'        => 'Gestrichelt: die Vorperiode.',
        'top_pages'        => 'Meistbesuchte Seiten',
        'referrers'        => 'Verweisende Websites',
        'entry_pages'      => 'Einstiegsseiten',
        'exit_pages'       => 'Ausstiegsseiten',
        'session_depth'    => 'Seiten pro Besuch',
        'depth_1'          => '1 Seite',
        'depth_2'          => '2 Seiten',
        'depth_3'          => '3–4 Seiten',
        'depth_5'          => '5 oder mehr Seiten',
        'browser_lang'     => 'Browsersprache',
        'time_of_day'      => 'Tageszeit',
        'heatmap_title'    => 'Wochentag und Uhrzeit',
        'peak'             => 'Spitzenzeit',
        'views'            => 'Seitenaufrufe',
        'device_type'      => 'Gerätetyp',
        'top_countries'    => 'Länder',
        'channels'         => 'Traffic-Kanäle',
        'ch_direct'        => 'Direkt',
        'ch_organic'       => 'Organische Suche',
        'ch_social'        => 'Social Media',
        'ch_referral'      => 'Verweise',
        'tip_channels'     => 'Wie Besucher Ihre Website gefunden haben.',
        'recent_sessions'  => 'Letzte %d Besuche',
        'today_short'      => 'Heute',
        'yesterday_short'  => 'Gestern',
        'pages_count'      => '%d Seiten',
        'more_pages'       => '+%d weitere',
        'live_label'       => '%d aktiv',
        'tip_live'         => 'Besucher der letzten 5 Minuten.',
        'theme_toggle'     => 'Zwischen hell und dunkel wechseln',
        'show'             => 'Anzeigen',
        'hide'             => 'Ausblenden',
        'no_data'          => 'Noch keine Daten — fügen Sie das Tracking-Snippet auf Ihrer Website ein.',
        'no_pages'         => 'Keine Daten in diesem Zeitraum',
        'no_referrers'     => 'Keine verweisenden Websites in diesem Zeitraum',
        'no_external'      => 'Kein externer Traffic in diesem Zeitraum',
        'no_channels'      => 'Keine klassifizierten Einstiege in diesem Zeitraum',
        'no_lang'          => 'Keine Daten in diesem Zeitraum',
        'no_geo'           => 'Geo deaktiviert oder keine Daten',
        'no_sessions'      => 'Keine Besuche in diesem Zeitraum',
        'device_desktop'   => 'Desktop',
        'device_mobile'    => 'Mobil',
        'device_tablet'    => 'Tablet',
        'refresh'          => 'Aktualisieren',
        'logout'           => 'Abmelden',
        'back_to_site'     => '↗ Zur Website',
        'export'           => '↓ CSV exportieren',
        'rows'             => 'Einträge',
        'cleared'          => 'Alle Daten gelöscht.',
        'danger_title'     => '⚠ Gefahrenzone',
        'danger_desc'      => 'Diese Aktionen lassen sich nicht rückgängig machen.',
        'clear_btn'        => 'Alle Daten löschen',
        'confirm_msg'      => 'Alle %s Einträge endgültig löschen?',
        'confirm_btn'      => 'Ja, alles löschen',
        'tip_pages'        => 'Ihre meistbesuchten Seiten und die Änderung zur Vorperiode.',
        'tip_referrers'    => 'Websites, die Besucher zu Ihnen geschickt haben.',
        'tip_entry'        => 'Seiten, auf denen Besucher von anderen Websites ankamen.',
        'tip_exit'         => 'Seiten, auf denen Besuche endeten, mit ihrer Ausstiegsrate.',
        'tip_depth'        => 'Wie viele Seiten Besuche umfassen.',
        'tip_lang'         => 'Die Browsersprache Ihrer Besucher.',
        'tip_tod'          => 'Wann Ihre Website besucht wird.',
        'tip_heatmap'      => 'Wann Ihre Website im Wochenverlauf besucht wird.',
        'tip_device'       => 'Geräte Ihrer Besucher.',
        'tip_countries'    => 'Woher Ihre Besucher kommen.',
        'warn_default_pw'  => 'Die Anmeldung ist gesperrt, bis in pima-core.php ein eigenes Passwort als STATS_PASSWORD gesetzt ist. (Code T8)',
        'password_ph'      => 'Passwort',
        'login_help'       => 'Passwort vergessen? Ihre Website-Betreuung kann es zurücksetzen.',
        'pw_link'          => 'Passwort ändern',
        'pw_title'         => 'Passwort ändern',
        'pw_current'       => 'Aktuelles Passwort',
        'pw_new'           => 'Neues Passwort',
        'pw_repeat'        => 'Neues Passwort wiederholen',
        'pw_rule'          => 'Mindestens 10 Zeichen.',
        'pw_btn'           => 'Passwort ändern',
        'pw_back'          => '← Zurück zum Dashboard',
        'pw_done'          => 'Passwort geändert.',
        'pw_err_session'   => 'Die Seite war zu lange geöffnet. Bitte versuchen Sie es erneut.',
        'pw_err_current'   => 'Das aktuelle Passwort stimmt nicht.',
        'pw_err_repeat'    => 'Die neuen Passwörter stimmen nicht überein.',
        'pw_err_short'     => 'Das neue Passwort braucht mindestens 10 Zeichen.',
        'pw_err_same'      => 'Das neue Passwort ist dasselbe wie das bisherige.',
        'pw_err_write'     => 'Das Passwort ließ sich nicht speichern. Bitte prüfen Sie die Schreibrechte von pima-cache. (Code T20)',
        'pw_err_file'      => 'Die Anmeldung ist gesperrt: Die Passwortdatei pima-cache/.pima-password ist beschädigt. Löschen Sie sie, dann gilt wieder das Passwort aus pima-core.php. (Code T20)',
    ],
];
$lang = defined('LANG') ? LANG : 'en';
$t = $strings[$lang] ?? $strings['en'];

// pima-core.php may override single texts via $PIMA_STRINGS.
// Unknown keys are ignored.
if (isset($PIMA_STRINGS) && is_array($PIMA_STRINGS)) {
    foreach ($PIMA_STRINGS as $k => $v) {
        if (is_string($v) && array_key_exists($k, $t)) $t[$k] = $v;
    }
}

// ---- Change password ----
// Only signed in and only while STATS_PASSWORD_CHANGE allows it. Checking the
// current password counts towards the same per-IP lockout as the login, so an
// unattended open session cannot be used to guess it and lock the owner out.
$pwChange  = $authed && $pwChangeEnabled;
$pwView    = $pwChange && isset($_GET['password']);
$pwMsg     = '';
$pwMsgType = '';
if ($pwChange && ($_GET['password'] ?? '') === 'done') {
    $pwMsg     = $t['pw_done'];
    $pwMsgType = 'success';
}
if ($pwChange && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pw_change'])) {
    $pwView    = true;
    $pwMsgType = 'error';
    $pwCurrent = isset($_POST['pw_current']) && is_string($_POST['pw_current']) ? $_POST['pw_current'] : '';
    $pwNew     = isset($_POST['pw_new'])     && is_string($_POST['pw_new'])     ? $_POST['pw_new']     : '';
    $pwRepeat  = isset($_POST['pw_repeat'])  && is_string($_POST['pw_repeat'])  ? $_POST['pw_repeat']  : '';
    if (!$csrfOk) {
        $pwMsg = $t['pw_err_session'];
    } else {
        $check = pimaLockedCheck($lockFile, $maxAttempts, $lockoutSecs,
            function () use ($pwCurrent, $storedPassword): bool { return pimaPasswordVerify($pwCurrent, $storedPassword); });
        if ($check['result'] === 'unavailable' || ($check['result'] !== 'ok' && !$check['saved'])) {
            error_log('pima: login lockout file unavailable (T15)');
            $pwMsg = $t['auth_unavailable'];
        } elseif ($check['result'] === 'locked') {
            $secs  = max(1, $check['locked_until'] - time());
            $pwMsg = sprintf($t['locked_out'], $secs > 60 ? round($secs / 60) . ' min' : $secs . ' sec');
            sleep(min(3, $secs));
        } elseif ($check['result'] === 'fail') {
            $pwMsg = $t['pw_err_current'];
            sleep(min(8, max(1, $check['attempts'])));
        } else {
            $err  = pimaPasswordRules($pwCurrent, $pwNew, $pwRepeat);
            $hash = $err === '' ? pimaPasswordWrite($pwNew) : null;
            if ($err !== '') {
                $pwMsg = $t[$err];
            } elseif ($hash === null) {
                error_log('pima: could not write pima-cache/.pima-password (T20)');
                $pwMsg = $t['pw_err_write'];
            } else {
                // This session stays signed in; all others end on their next
                // request because their key no longer matches.
                session_regenerate_id(true);
                $_SESSION['pima_auth_key'] = hash('sha256', $hash);
                $_SESSION['csrf']          = bin2hex(random_bytes(16));
                header('Location: ' . $selfUrl . '?password=done');
                exit;
            }
        }
    }
}

// ---- DB helper ----
function openDb(): ?SQLite3 {
    if (!file_exists(DB_PATH)) return null;
    try {
        $db = new SQLite3(DB_PATH, SQLITE3_OPEN_READONLY);
        $db->enableExceptions(true);
        $db->busyTimeout(3000);
        return $db;
    } catch (Exception $e) {
        return null;
    }
}

function csvCell($value): string {
    $value = (string) $value;
    // Spreadsheet applications may execute formulas even after whitespace.
    if (preg_match('/^[\x00-\x20]*[=+\-@]/', $value)) $value = "'" . $value;
    return '"' . str_replace('"', '""', $value) . '"';
}

// ---- CSV Export ----
if ($authed && isset($_GET['export'])) {
    $db = openDb();
    if ($db) {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="pima-export-' . date('Y-m-d') . '.csv"');
        echo "date,time,page,title,referrer,device,country,lang\n";
        $res = $db->query('SELECT date,time,page,title,referrer,device,country,lang FROM hits ORDER BY date DESC, time DESC');
        while ($row = $res->fetchArray(SQLITE3_NUM)) {
            echo implode(',', array_map('csvCell', $row)) . "\n";
        }
        $db->close();
    }
    exit;
}

// Distinct visitors with a pageview in the last five minutes. The vid changes
// at midnight, so only today's rows are considered.
function activeVisitors(SQLite3 $db): int {
    $now   = date('H:i:s');
    $since = date('H:i:s', time() - 300);
    if ($since > $now) $since = '00:00:00';
    $today = date('Y-m-d');
    return (int) $db->querySingle("SELECT COUNT(DISTINCT vid) FROM hits WHERE date = '$today' AND time >= '$since' AND vid != ''");
}

// ---- Live count (polled by the dashboard header) ----
// Polling does not refresh the idle timer; see the session check above.
if (isset($_GET['live'])) {
    header('Content-Type: application/json');
    if (!$authed) {
        http_response_code(401);
        echo '{"active":null}';
        exit;
    }
    $db = openDb();
    echo json_encode(['active' => $db ? activeVisitors($db) : 0]);
    if ($db) $db->close();
    exit;
}
// ---- Clear all data (Advanced Mode only) ----
if ($authed && $advancedMode && isset($_POST['clear_data']) && ($_POST['confirm_clear'] ?? '') === 'yes') {
    $tokenOk = isset($_POST['csrf'], $_SESSION['csrf']) && is_scalar($_POST['csrf'])
        && hash_equals($_SESSION['csrf'], (string) $_POST['csrf']);
    if ($tokenOk) {
        try {
            $db = new SQLite3(DB_PATH);
            $db->exec('DELETE FROM hits');
            $db->exec('VACUUM');
            $db->close();
            $clearSuccess = true;
        } catch (Exception $e) {
            $clearError = true;
        }
    } else {
        $clearError = true;
    }
}

// ---- Range and filters ----
// Every panel follows one selected range and compares it with the period of
// the same length before it. Ranges roll and end today, so nothing drops to
// zero on a Monday or the 1st; only "last month" is a completed calendar month.
$rangeIds = ['today', 'yesterday', '7d', '30d', 'last_month', '12m'];
$range    = (isset($_GET['range']) && is_string($_GET['range']) && in_array($_GET['range'], $rangeIds, true))
    ? $_GET['range'] : '30d';

$todayDay = new DateTimeImmutable('today');
switch ($range) {
    case 'today':      $fromDay = $todayDay;                                 $toDay = $todayDay; break;
    case 'yesterday':  $fromDay = $todayDay->modify('-1 day');              $toDay = $fromDay;  break;
    case '7d':         $fromDay = $todayDay->modify('-6 days');             $toDay = $todayDay; break;
    case 'last_month': $fromDay = $todayDay->modify('first day of last month');
                       $toDay   = $todayDay->modify('last day of last month'); break;
    case '12m':        $fromDay = $todayDay->modify('-364 days');           $toDay = $todayDay; break;
    default:           $fromDay = $todayDay->modify('-29 days');            $toDay = $todayDay;
}
$rangeDays = (int) $fromDay->diff($toDay)->format('%a') + 1;
if ($range === 'last_month') {
    $prevFromDay = $fromDay->modify('first day of last month');
    $prevToDay   = $fromDay->modify('-1 day');
} else {
    $prevToDay   = $fromDay->modify('-1 day');
    $prevFromDay = $prevToDay->modify('-' . ($rangeDays - 1) . ' days');
}
$from     = $fromDay->format('Y-m-d');
$to       = $toDay->format('Y-m-d');
$prevFrom = $prevFromDay->format('Y-m-d');
$prevTo   = $prevToDay->format('Y-m-d');
$hourly   = $rangeDays === 1;
// Long periods are charted by week so the line stays readable.
$bucketStep = $rangeDays > 62 ? 7 : 1;
$hasPrev    = false;

// Clicking a row in any ranked list narrows the whole dashboard to it.
$filters = [];
foreach (['page' => 255, 'ref' => 255, 'country' => 5, 'device' => 7, 'lang' => 3] as $key => $maxLen) {
    $value = $_GET[$key] ?? '';
    if (!is_string($value) || $value === '' || mb_strlen($value) > $maxLen) continue;
    if ($key === 'device'  && !in_array($value, ['desktop', 'mobile', 'tablet'], true)) continue;
    if ($key === 'country' && !preg_match('/^([A-Z]{2}|local)$/', $value)) continue;
    if ($key === 'lang'    && !preg_match('/^[a-z]{2,3}$/', $value)) continue;
    $filters[$key] = $value;
}

function refHost(string $referrer): string {
    // Legacy rows can hold a full URL instead of a host.
    return preg_replace('/^www\./', '', parse_url($referrer, PHP_URL_HOST) ?: $referrer);
}

function filterSql(array $filters, string $prefix = ''): string {
    $sql = '';
    foreach ($filters as $key => $value) {
        $quoted = "'" . SQLite3::escapeString($value) . "'";
        if ($key === 'ref') {
            // A source only sits on the entry pageview, so the filter keeps
            // every pageview of the visitor-days that entered from it.
            $like = "'%://" . SQLite3::escapeString(addcslashes($value, '%_\\')) . "/%' ESCAPE '\\'";
            $likeWww = "'%://www." . SQLite3::escapeString(addcslashes($value, '%_\\')) . "/%' ESCAPE '\\'";
            $sql .= " AND ({$prefix}date || {$prefix}vid) IN (SELECT date || vid FROM hits WHERE vid != ''"
                  . " AND (referrer = $quoted OR referrer LIKE $like OR referrer LIKE $likeWww))";
        } else {
            $sql .= " AND {$prefix}{$key} = $quoted";
        }
    }
    return $sql;
}

function rowMatchesFilters(array $row, array $filters): bool {
    foreach ($filters as $key => $value) {
        if ($key === 'ref') {
            if (($row['referrer'] ?? '') === '' || refHost((string) $row['referrer']) !== $value) return false;
        } elseif ((string) ($row[$key] ?? '') !== $value) {
            return false;
        }
    }
    return true;
}

// Builds a dashboard link that keeps the current range and filters.
function dashUrl(array $set = [], array $unset = []): string {
    global $range, $filters;
    $params = $filters;
    if ($range !== '30d') $params = ['range' => $range] + $params;
    foreach ($unset as $key) unset($params[$key]);
    foreach ($set as $key => $value) $params[$key] = $value;
    if (isset($params['range']) && $params['range'] === '30d') unset($params['range']);
    return $params ? '?' . http_build_query($params) : '?';
}

// ---- Data ----
$emptyPeriod = ['views' => 0, 'visitors' => 0, 'sessions' => 0, 'bounces' => 0, 'session_views' => 0, 'session_secs' => 0];
$stats = [
    'total'         => 0,
    'covered_days'  => 1,
    'first_date'    => '',
    'active_now'    => 0,
    'cur'           => $emptyPeriod,
    'prev'          => $emptyPeriod,
    'chart'         => ['labels' => [], 'cur' => [], 'prev' => []],
    'pages'         => [],
    'pages_prev'    => [],
    'referrers'     => [],
    'devices'       => ['desktop' => 0, 'mobile' => 0, 'tablet' => 0],
    'countries'     => [],
    'hours'         => array_fill(0, 24, 0),
    'heatmap'       => array_fill(0, 7, array_fill(0, 24, 0)),
    'languages'     => [],
    'entry_pages'   => [],
    'channels'      => ['direct' => 0, 'organic' => 0, 'social' => 0, 'referral' => 0],
    'exit_pages'    => [],
    'session_depth' => ['1' => 0, '2' => 0, '3' => 0, '5' => 0],
    'recent'        => [],
    'db_size'       => 0,
    'db_rows'       => 0,
];

// Chart buckets: hours for a single day, otherwise days or weeks keyed by
// their first date. Weeks are counted back from the last day, so the newest
// week is complete and only the oldest may be short.
$bucketKeys = [];
$prevBucketKeys = [];
$bucketShift     = $bucketStep > 1 ? ($bucketStep - $rangeDays % $bucketStep) % $bucketStep : 0;
$bucketStart     = $fromDay->modify("-$bucketShift days");
$prevBucketStart = $prevFromDay->modify("-$bucketShift days");
if ($hourly) {
    for ($h = 0; $h < 24; $h++) {
        $bucketKeys[] = sprintf('%02d', $h);
        $prevBucketKeys[] = sprintf('%02d', $h);
    }
} else {
    for ($i = 0; $i < $rangeDays + $bucketShift; $i += $bucketStep) {
        $bucketKeys[] = $bucketStart->modify("+$i days")->format('Y-m-d');
        $prevBucketKeys[] = $prevBucketStart->modify("+$i days")->format('Y-m-d');
    }
}
$bucketOf = function (string $date, DateTimeImmutable $start) use ($bucketStep): string {
    $day = DateTimeImmutable::createFromFormat('!Y-m-d', $date);
    if (!$day || $bucketStep === 1) return $date;
    $offset = (int) $start->diff($day)->format('%r%a');
    return $start->modify('+' . (intdiv($offset, $bucketStep) * $bucketStep) . ' days')->format('Y-m-d');
};
$emptySeries = ['views' => array_fill_keys($bucketKeys, 0), 'visitors' => array_fill_keys($bucketKeys, 0), 'sessions' => array_fill_keys($bucketKeys, 0)];
$chartCur  = $emptySeries;
$chartPrev = ['views' => array_fill_keys($prevBucketKeys, 0), 'visitors' => array_fill_keys($prevBucketKeys, 0), 'sessions' => array_fill_keys($prevBucketKeys, 0)];

if ($authed) {
    $db = openDb();
    if ($db) {
        $hasEntryColumn = false;
        $columns = $db->query('PRAGMA table_info(hits)');
        while ($column = $columns->fetchArray(SQLITE3_ASSOC)) {
            if (($column['name'] ?? '') === 'is_entry') $hasEntryColumn = true;
        }
        $entryWhere  = $hasEntryColumn ? 'is_entry = 1' : "referrer != ''";
        $entryWhereH = $hasEntryColumn ? 'h.is_entry = 1' : "h.referrer != ''";

        $fw   = filterSql($filters);
        $fwH  = filterSql($filters, 'h.');
        $inCur  = "date >= '$from' AND date <= '$to'";
        $inCurH = "h.date >= '$from' AND h.date <= '$to'";
        $inPrev = "date >= '$prevFrom' AND date <= '$prevTo'";

        $stats['total'] = (int) $db->querySingle('SELECT COUNT(*) FROM hits');

        // Days of the range that tracking actually covers, for the daily average.
        $firstDate = (string) $db->querySingle('SELECT MIN(date) FROM hits');
        if ($firstDate) {
            $coverFrom = max($from, $firstDate);
            $coverTo   = min($to, $todayDay->format('Y-m-d'));
            $a = DateTimeImmutable::createFromFormat('!Y-m-d', $coverFrom);
            $b = DateTimeImmutable::createFromFormat('!Y-m-d', $coverTo);
            if ($a && $b && $a <= $b) $stats['covered_days'] = (int) $a->diff($b)->format('%a') + 1;
        }
        // Before tracking began, or after old rows were pruned, the previous
        // period would look emptier than it was.
        $hasPrev = $firstDate !== '' && $prevFrom >= $firstDate;
        $stats['first_date'] = $firstDate;

        // Visitors are visitor-days: the vid is only comparable within one day.
        foreach (['cur' => $inCur, 'prev' => $inPrev] as $period => $where) {
            $stats[$period]['views']    = (int) $db->querySingle("SELECT COUNT(*) FROM hits WHERE $where $fw");
            $stats[$period]['visitors'] = (int) $db->querySingle("SELECT COUNT(DISTINCT date || vid) FROM hits WHERE $where AND vid != '' $fw");
        }

        // Pageviews and visitors per chart bucket, for both periods.
        $bucketExpr = $hourly ? 'substr(time,1,2)' : 'date';
        foreach (['cur' => $inCur, 'prev' => $inPrev] as $period => $where) {
            $res = $db->query("SELECT $bucketExpr AS b, COUNT(*) AS views, COUNT(DISTINCT CASE WHEN vid != '' THEN date || vid END) AS visitors FROM hits WHERE $where $fw GROUP BY b");
            while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                $b = $hourly ? $row['b'] : $bucketOf($row['b'], $period === 'cur' ? $bucketStart : $prevBucketStart);
                if ($period === 'cur' && isset($chartCur['views'][$b])) {
                    $chartCur['views'][$b]    += (int) $row['views'];
                    $chartCur['visitors'][$b] += (int) $row['visitors'];
                } elseif ($period === 'prev' && isset($chartPrev['views'][$b])) {
                    $chartPrev['views'][$b]    += (int) $row['views'];
                    $chartPrev['visitors'][$b] += (int) $row['visitors'];
                }
            }
        }

        // Top pages — subquery takes the most recent non-empty title.
        $res = $db->query("
            SELECT h.page,
                   COUNT(*) AS c,
                   (SELECT h2.title FROM hits h2
                    WHERE h2.page = h.page
                      AND h2.title IS NOT NULL AND h2.title != ''
                    ORDER BY h2.id DESC LIMIT 1) AS title
            FROM hits h
            WHERE $inCurH $fwH
            GROUP BY h.page
            ORDER BY c DESC
            LIMIT 8
        ");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stats['pages'][$row['page']] = ['c' => $row['c'], 'title' => $row['title'] ?? ''];
        }

        // Previous-period counts for exactly the pages listed above.
        if ($stats['pages']) {
            $names = array_keys($stats['pages']);
            $holes = implode(',', array_fill(0, count($names), '?'));
            $stmt  = $db->prepare("SELECT page, COUNT(*) AS c FROM hits WHERE $inPrev $fw AND page IN ($holes) GROUP BY page");
            if ($stmt) {
                foreach ($names as $i => $n) $stmt->bindValue($i + 1, $n);
                $res = $stmt->execute();
                while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                    $stats['pages_prev'][$row['page']] = $row['c'];
                }
            }
        }

        // Roll up to the host first, rank and cap afterwards.
        $res = $db->query("SELECT referrer, COUNT(*) as c FROM hits WHERE $entryWhere AND referrer != '' AND $inCur $fw GROUP BY referrer");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $ref = refHost($row['referrer']);
            $stats['referrers'][$ref] = ($stats['referrers'][$ref] ?? 0) + $row['c'];
        }
        arsort($stats['referrers']);
        $stats['referrers'] = array_slice($stats['referrers'], 0, 8, true);

        // Traffic channels — matches the exact host or a subdomain of it.
        $searchEngines = ['google.com', 'google.de', 'google.at', 'google.ch', 'bing.com', 'duckduckgo.com', 'yahoo.com', 'ecosia.org', 'yandex.com', 'yandex.ru', 'baidu.com', 'qwant.com', 'startpage.com'];
        $socialNets    = ['facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'tiktok.com', 'pinterest.com', 'youtube.com', 'reddit.com', 'whatsapp.com', 'telegram.org', 't.co'];
        $hostMatches = function(string $host, array $domains): bool {
            foreach ($domains as $d) {
                if ($host === $d || substr($host, -(strlen($d) + 1)) === '.' . $d) return true;
            }
            return false;
        };
        $isSearchEngine = function(string $host) use ($hostMatches, $searchEngines): bool {
            return (bool) preg_match('/(^|\.)google\.[a-z.]+$/', $host)
                || $hostMatches($host, $searchEngines);
        };
        $resC = $db->query("SELECT referrer, COUNT(*) as c FROM hits WHERE $entryWhere AND $inCur $fw GROUP BY referrer");
        while ($rowC = $resC->fetchArray(SQLITE3_ASSOC)) {
            $ref = strtolower($rowC['referrer'] ?? '');
            $c   = $rowC['c'];
            if (empty($ref)) {
                $stats['channels']['direct'] += $c;
            } else {
                $host = refHost($ref);
                if      ($isSearchEngine($host))              $stats['channels']['organic']  += $c;
                elseif  ($hostMatches($host, $socialNets))    $stats['channels']['social']   += $c;
                else                                          $stats['channels']['referral'] += $c;
            }
        }

        // Devices
        $res = $db->query("SELECT device, COUNT(DISTINCT date || vid) as c FROM hits WHERE vid != '' AND $inCur $fw GROUP BY device");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $dev = $row['device'] ?: 'desktop';
            $stats['devices'][$dev] = ($stats['devices'][$dev] ?? 0) + $row['c'];
        }

        // Countries
        $res = $db->query("SELECT country, COUNT(DISTINCT date || vid) as c FROM hits WHERE vid != '' AND country != '' AND $inCur $fw GROUP BY country ORDER BY c DESC LIMIT 8");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stats['countries'][$row['country']] = $row['c'];
        }

        // Hours, and weekday × hour (strftime %w: 0 = Sunday)
        $res = $db->query("SELECT CAST(strftime('%w', date) AS INTEGER) AS wd, CAST(substr(time,1,2) AS INTEGER) AS h, COUNT(*) AS views FROM hits WHERE $inCur $fw GROUP BY wd, h");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $h = (int) $row['h'];
            $wd = (int) $row['wd'];
            if ($h < 0 || $h > 23 || $wd < 0 || $wd > 6) continue;
            $stats['hours'][$h] += (int) $row['views'];
            $stats['heatmap'][$wd][$h] += (int) $row['views'];
        }

        // Browser languages
        $res = $db->query("SELECT lang, COUNT(DISTINCT date || vid) as c FROM hits WHERE vid != '' AND lang IS NOT NULL AND lang != '' AND $inCur $fw GROUP BY lang ORDER BY c DESC LIMIT 8");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stats['languages'][$row['lang']] = $row['c'];
        }

        // Entry pages reached from an external referrer.
        $res = $db->query("
            SELECT h.page,
                   COUNT(*) AS c,
                   (SELECT h2.title FROM hits h2
                    WHERE h2.page = h.page
                      AND h2.title IS NOT NULL AND h2.title != ''
                    ORDER BY h2.id DESC LIMIT 1) AS title
            FROM hits h
            WHERE $entryWhereH
              AND h.referrer != ''
              AND $inCurH $fwH
            GROUP BY h.page
            ORDER BY c DESC
            LIMIT 8
        ");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stats['entry_pages'][$row['page']] = ['c' => $row['c'], 'title' => $row['title'] ?? ''];
        }

        // Sessions: consecutive pageviews of one daily vid with no gap longer
        // than 30 minutes. The vid is re-salted nightly, so a session never
        // spans midnight and every session belongs to exactly one date. With a
        // filter, a session counts when any of its pageviews matches.
        $sessionGap       = 1800;
        $recentLimit      = max(1, defined('RECENT_ENTRIES') ? (int) RECENT_ENTRIES : 50);
        $exitCounts       = [];
        $sessionPageViews = [];
        $finishSession = function (?array $s) use (&$stats, &$exitCounts, &$sessionPageViews, &$chartCur, &$chartPrev, $from, $prevTo, $hourly, $recentLimit, $bucketOf, $bucketStart, $prevBucketStart) {
            if ($s === null || !$s['match']) return;
            $bucket = $hourly ? sprintf('%02d', intdiv($s['first'], 3600))
                : $bucketOf($s['date'], $s['date'] < $from ? $prevBucketStart : $bucketStart);
            if ($s['date'] < $from) {
                // A shortened previous month leaves a gap before the range.
                if ($s['date'] > $prevTo) return;
                $stats['prev']['sessions']++;
                if (isset($chartPrev['sessions'][$bucket])) $chartPrev['sessions'][$bucket]++;
                if ($s['views'] === 1) $stats['prev']['bounces']++;
                $stats['prev']['session_views'] += $s['views'];
                $stats['prev']['session_secs']  += $s['last'] - $s['first'];
                return;
            }
            $stats['cur']['sessions']++;
            if (isset($chartCur['sessions'][$bucket])) $chartCur['sessions'][$bucket]++;
            if ($s['views'] === 1) $stats['cur']['bounces']++;
            $stats['cur']['session_views'] += $s['views'];
            $stats['cur']['session_secs']  += $s['last'] - $s['first'];
            $depth = $s['views'] >= 5 ? '5' : ($s['views'] >= 3 ? '3' : (string) $s['views']);
            $stats['session_depth'][$depth]++;
            $exitCounts[$s['exit']] = ($exitCounts[$s['exit']] ?? 0) + 1;
            foreach ($s['page_views'] as $page => $c) {
                $sessionPageViews[$page] = ($sessionPageViews[$page] ?? 0) + $c;
            }
            unset($s['page_views'], $s['match']);
            $stats['recent'][] = $s;
            // Keep only the newest sessions without holding every one in memory.
            if (count($stats['recent']) > $recentLimit * 2) {
                usort($stats['recent'], function ($a, $b) { return [$b['date'], $b['first']] <=> [$a['date'], $a['first']]; });
                $stats['recent'] = array_slice($stats['recent'], 0, $recentLimit);
            }
        };
        $walkFrom = $hasPrev ? $prevFrom : $from;
        $res = $db->query("SELECT date, vid, time, page, referrer, device, country, lang FROM hits WHERE vid != '' AND date >= '$walkFrom' AND date <= '$to' ORDER BY date, vid, time, id");
        $session = null;
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $parts = explode(':', (string) $row['time']);
            $secs  = (int) ($parts[0] ?? 0) * 3600 + (int) ($parts[1] ?? 0) * 60 + (int) ($parts[2] ?? 0);
            $continues = $session !== null
                && $session['date'] === $row['date']
                && $session['vid'] === $row['vid']
                && $secs - $session['last'] <= $sessionGap;
            if ($continues) {
                $session['views']++;
                $session['last'] = $secs;
                $session['exit'] = $row['page'];
                // Enough for the path display: the first five and the last two.
                if (count($session['pages']) < 5) $session['pages'][] = $row['page'];
                $session['tail'] = [end($session['tail']), $row['page']];
            } else {
                $finishSession($session);
                $session = [
                    'date'       => $row['date'],
                    'vid'        => $row['vid'],
                    'first'      => $secs,
                    'last'       => $secs,
                    'views'      => 1,
                    'exit'       => $row['page'],
                    'pages'      => [$row['page']],
                    'tail'       => [$row['page']],
                    'page_views' => [],
                    'source'     => $row['referrer'] !== '' && $row['referrer'] !== null ? refHost((string) $row['referrer']) : '',
                    'device'     => (string) $row['device'],
                    'country'    => (string) $row['country'],
                    'match'      => false,
                ];
            }
            $session['page_views'][$row['page']] = ($session['page_views'][$row['page']] ?? 0) + 1;
            if (!$session['match'] && rowMatchesFilters($row, $filters)) $session['match'] = true;
        }
        $finishSession($session);

        usort($stats['recent'], function ($a, $b) { return [$b['date'], $b['first']] <=> [$a['date'], $a['first']]; });
        $stats['recent'] = array_slice($stats['recent'], 0, $recentLimit);

        arsort($exitCounts);
        foreach (array_slice($exitCounts, 0, 8, true) as $page => $c) {
            $stats['exit_pages'][$page] = [
                'c'     => $c,
                'rate'  => (int) round($c / max(1, $sessionPageViews[$page] ?? 0) * 100),
                'title' => '',
            ];
        }
        if ($stats['exit_pages']) {
            $names = array_keys($stats['exit_pages']);
            $holes = implode(',', array_fill(0, count($names), '?'));
            // With MAX(), SQLite returns the bare title column from that same row.
            $stmt  = $db->prepare(
                "SELECT page, title, MAX(id) FROM hits
                 WHERE page IN ($holes) AND title IS NOT NULL AND title != ''
                 GROUP BY page"
            );
            if ($stmt) {
                foreach ($names as $i => $n) $stmt->bindValue($i + 1, $n);
                $res = $stmt->execute();
                while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                    $stats['exit_pages'][$row['page']]['title'] = (string) $row['title'];
                }
            }
        }

        // Active now: distinct vids with a pageview in the last five minutes.
        $stats['active_now'] = activeVisitors($db);

        $stats['db_size'] = file_exists(DB_PATH) ? round(filesize(DB_PATH) / 1024, 1) : 0;
        $stats['db_rows'] = $stats['total'];

        $db->close();
    }
}

$countryNames = $lang === 'de' ? [
    'AF'=>'Afghanistan','AL'=>'Albanien','DZ'=>'Algerien','AR'=>'Argentinien','AU'=>'Australien',
    'AT'=>'Österreich','BE'=>'Belgien','BR'=>'Brasilien','BG'=>'Bulgarien','CA'=>'Kanada',
    'CL'=>'Chile','CN'=>'China','CO'=>'Kolumbien','HR'=>'Kroatien','CZ'=>'Tschechien',
    'DK'=>'Dänemark','EG'=>'Ägypten','FI'=>'Finnland','FR'=>'Frankreich','DE'=>'Deutschland',
    'GR'=>'Griechenland','HK'=>'Hongkong','HU'=>'Ungarn','IN'=>'Indien','ID'=>'Indonesien',
    'IE'=>'Irland','IL'=>'Israel','IT'=>'Italien','JP'=>'Japan','KZ'=>'Kasachstan',
    'KE'=>'Kenia','KR'=>'Südkorea','MY'=>'Malaysia','MX'=>'Mexiko','MA'=>'Marokko',
    'NL'=>'Niederlande','NZ'=>'Neuseeland','NG'=>'Nigeria','NO'=>'Norwegen','PK'=>'Pakistan',
    'PH'=>'Philippinen','PL'=>'Polen','PT'=>'Portugal','RO'=>'Rumänien','RU'=>'Russland',
    'SA'=>'Saudi-Arabien','RS'=>'Serbien','SG'=>'Singapur','SK'=>'Slowakei','ZA'=>'Südafrika',
    'ES'=>'Spanien','SE'=>'Schweden','CH'=>'Schweiz','TW'=>'Taiwan','TH'=>'Thailand',
    'TR'=>'Türkei','UA'=>'Ukraine','AE'=>'Vereinigte Arabische Emirate','GB'=>'Vereinigtes Königreich','US'=>'Vereinigte Staaten',
    'VN'=>'Vietnam','LI'=>'Liechtenstein','LU'=>'Luxemburg','SI'=>'Slowenien','EE'=>'Estland',
    'LV'=>'Lettland','LT'=>'Litauen','IS'=>'Island','MT'=>'Malta','CY'=>'Zypern',
    'BA'=>'Bosnien und Herzegowina','ME'=>'Montenegro','MK'=>'Nordmazedonien','MD'=>'Moldau','BY'=>'Belarus',
    'GE'=>'Georgien','AD'=>'Andorra','MC'=>'Monaco','SM'=>'San Marino','XK'=>'Kosovo','local'=>'Lokal',
] : [
    'AF'=>'Afghanistan','AL'=>'Albania','DZ'=>'Algeria','AR'=>'Argentina','AU'=>'Australia',
    'AT'=>'Austria','BE'=>'Belgium','BR'=>'Brazil','BG'=>'Bulgaria','CA'=>'Canada',
    'CL'=>'Chile','CN'=>'China','CO'=>'Colombia','HR'=>'Croatia','CZ'=>'Czechia',
    'DK'=>'Denmark','EG'=>'Egypt','FI'=>'Finland','FR'=>'France','DE'=>'Germany',
    'GR'=>'Greece','HK'=>'Hong Kong','HU'=>'Hungary','IN'=>'India','ID'=>'Indonesia',
    'IE'=>'Ireland','IL'=>'Israel','IT'=>'Italy','JP'=>'Japan','KZ'=>'Kazakhstan',
    'KE'=>'Kenya','KR'=>'South Korea','MY'=>'Malaysia','MX'=>'Mexico','MA'=>'Morocco',
    'NL'=>'Netherlands','NZ'=>'New Zealand','NG'=>'Nigeria','NO'=>'Norway','PK'=>'Pakistan',
    'PH'=>'Philippines','PL'=>'Poland','PT'=>'Portugal','RO'=>'Romania','RU'=>'Russia',
    'SA'=>'Saudi Arabia','RS'=>'Serbia','SG'=>'Singapore','SK'=>'Slovakia','ZA'=>'South Africa',
    'ES'=>'Spain','SE'=>'Sweden','CH'=>'Switzerland','TW'=>'Taiwan','TH'=>'Thailand',
    'TR'=>'Turkey','UA'=>'Ukraine','AE'=>'UAE','GB'=>'United Kingdom','US'=>'United States',
    'VN'=>'Vietnam','LI'=>'Liechtenstein','LU'=>'Luxembourg','SI'=>'Slovenia','EE'=>'Estonia',
    'LV'=>'Latvia','LT'=>'Lithuania','IS'=>'Iceland','MT'=>'Malta','CY'=>'Cyprus',
    'BA'=>'Bosnia and Herzegovina','ME'=>'Montenegro','MK'=>'North Macedonia','MD'=>'Moldova','BY'=>'Belarus',
    'GE'=>'Georgia','AD'=>'Andorra','MC'=>'Monaco','SM'=>'San Marino','XK'=>'Kosovo','local'=>'Local',
];
function countryName(string $code, array $map): string {
    return $map[$code] ?? $code;
}
function countryFlag(string $code): string {
    if (strlen($code) !== 2) return '';
    $code = strtoupper($code);
    $o1 = 0x1F1E6 + ord($code[0]) - ord('A');
    $o2 = 0x1F1E6 + ord($code[1]) - ord('A');
    return mb_chr($o1) . mb_chr($o2);
}

$langNames = $lang === 'de' ? [
    'af'=>'Afrikaans','ar'=>'Arabisch','bg'=>'Bulgarisch','bn'=>'Bengalisch',
    'cs'=>'Tschechisch','da'=>'Dänisch','de'=>'Deutsch','el'=>'Griechisch',
    'en'=>'Englisch','es'=>'Spanisch','et'=>'Estnisch','fa'=>'Persisch',
    'fi'=>'Finnisch','fr'=>'Französisch','gu'=>'Gujarati','he'=>'Hebräisch',
    'hi'=>'Hindi','hr'=>'Kroatisch','hu'=>'Ungarisch','hy'=>'Armenisch',
    'id'=>'Indonesisch','it'=>'Italienisch','ja'=>'Japanisch','ka'=>'Georgisch',
    'kn'=>'Kannada','ko'=>'Koreanisch','lt'=>'Litauisch','lv'=>'Lettisch',
    'mk'=>'Mazedonisch','ml'=>'Malayalam','mr'=>'Marathi','ms'=>'Malaiisch',
    'nl'=>'Niederländisch','no'=>'Norwegisch','pl'=>'Polnisch','pt'=>'Portugiesisch',
    'ro'=>'Rumänisch','ru'=>'Russisch','sk'=>'Slowakisch','sl'=>'Slowenisch',
    'sq'=>'Albanisch','sr'=>'Serbisch','sv'=>'Schwedisch','sw'=>'Suaheli',
    'ta'=>'Tamil','te'=>'Telugu','th'=>'Thailändisch','tr'=>'Türkisch',
    'uk'=>'Ukrainisch','ur'=>'Urdu','vi'=>'Vietnamesisch',
    'zh'=>'Chinesisch','zu'=>'Zulu',
] : [
    'af'=>'Afrikaans','ar'=>'Arabic','bg'=>'Bulgarian','bn'=>'Bengali',
    'cs'=>'Czech','da'=>'Danish','de'=>'German','el'=>'Greek',
    'en'=>'English','es'=>'Spanish','et'=>'Estonian','fa'=>'Persian',
    'fi'=>'Finnish','fr'=>'French','gu'=>'Gujarati','he'=>'Hebrew',
    'hi'=>'Hindi','hr'=>'Croatian','hu'=>'Hungarian','hy'=>'Armenian',
    'id'=>'Indonesian','it'=>'Italian','ja'=>'Japanese','ka'=>'Georgian',
    'kn'=>'Kannada','ko'=>'Korean','lt'=>'Lithuanian','lv'=>'Latvian',
    'mk'=>'Macedonian','ml'=>'Malayalam','mr'=>'Marathi','ms'=>'Malay',
    'nl'=>'Dutch','no'=>'Norwegian','pl'=>'Polish','pt'=>'Portuguese',
    'ro'=>'Romanian','ru'=>'Russian','sk'=>'Slovak','sl'=>'Slovenian',
    'sq'=>'Albanian','sr'=>'Serbian','sv'=>'Swedish','sw'=>'Swahili',
    'ta'=>'Tamil','te'=>'Telugu','th'=>'Thai','tr'=>'Turkish',
    'uk'=>'Ukrainian','ur'=>'Urdu','vi'=>'Vietnamese',
    'zh'=>'Chinese','zu'=>'Zulu',
];
function langName(string $code, array $map): string {
    return $map[strtolower($code)] ?? strtoupper($code);
}

function dashboardDate(int $timestamp, string $lang): string {
    $months = $lang === 'de'
        ? [1=>'Januar','Februar','März','April','Mai','Juni','Juli','August','September','Oktober','November','Dezember']
        : [1=>'January','February','March','April','May','June','July','August','September','October','November','December'];
    return date($lang === 'de' ? 'j.' : 'j', $timestamp) . ' ' . $months[(int) date('n', $timestamp)] . ' ' . date('Y', $timestamp);
}

function dashboardNumber(int $n, string $lang): string {
    return number_format($n, 0, '', $lang === 'de' ? '.' : ',');
}

function dashboardMonthShort(int $timestamp, string $lang): string {
    $months = $lang === 'de'
        ? [1=>'Jan','Feb','Mär','Apr','Mai','Jun','Jul','Aug','Sep','Okt','Nov','Dez']
        : [1=>'Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    return $months[(int) date('n', $timestamp)];
}

// Largest-remainder rounding keeps displayed category totals at exactly 100%.
function wholePercentages(array $counts): array {
    $total = array_sum($counts);
    $result = array_fill_keys(array_keys($counts), 0);
    if ($total <= 0) return $result;

    $remainders = [];
    foreach ($counts as $key => $count) {
        $exact = max(0, (float) $count) / $total * 100;
        $result[$key] = (int) floor($exact);
        $remainders[$key] = $exact - $result[$key];
    }
    arsort($remainders);
    $missing = 100 - array_sum($result);
    foreach (array_keys($remainders) as $key) {
        if ($missing-- <= 0) break;
        $result[$key]++;
    }
    return $result;
}

$decSep     = $lang === 'de' ? ',' : '.';
$rangeLabel = $t['range_' . $range];
$arrowUp    = '<svg viewBox="0 0 10 10" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 8V2M5 2L2 5M5 2L8 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
$arrowDown  = '<svg viewBox="0 0 10 10" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 2V8M5 8L2 5M5 8L8 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
$deviceIcons = [
    'desktop' => '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
    'mobile'  => '<svg width="12" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="2" width="14" height="20" rx="2"/><circle cx="12" cy="17" r="1" fill="currentColor"/></svg>',
    'tablet'  => '<svg width="12" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="2" width="16" height="20" rx="2"/><circle cx="12" cy="17" r="1" fill="currentColor"/></svg>',
];
// Indexed like SQLite's strftime('%w'): 0 = Sunday.
$weekdaysShort = $lang === 'de' ? ['So', 'Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa'] : ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function formatDuration(int $secs): string {
    return $secs < 60 ? $secs . ' s' : sprintf('%d:%02d min', intdiv($secs, 60), $secs % 60);
}

// Change against the previous period. Rates compare in percentage points;
// for the bounce rate a decrease is the good direction.
function growthPill(?float $cur, ?float $prev, string $mode, bool $lowerIsBetter, array $t, string $arrowUp, string $arrowDown): string {
    $wrap = function (string $class, string $label) use ($t): string {
        return '<div class="kpi-delta"><span class="pill ' . $class . '">' . $label . '</span>'
             . '<span class="kpi-cmp">' . htmlspecialchars($t['vs_prev']) . '</span></div>';
    };
    if ($cur === null || $prev === null || ($mode === 'pct' && $prev <= 0)) return $wrap('same', '—');
    $diff  = $mode === 'pp' ? (int) round($cur - $prev) : (int) round(($cur - $prev) / $prev * 100);
    $unit  = $mode === 'pp' ? ' ' . $t['pp'] : '%';
    if ($diff === 0) return $wrap('same', '±0' . $unit);
    $good  = $lowerIsBetter ? $diff < 0 : $diff > 0;
    $label = ($diff > 0 ? '+' : '−') . abs($diff) . $unit;
    return $wrap($good ? 'up' : 'down', ($diff > 0 ? $arrowUp : $arrowDown) . $label);
}

$cur  = $stats['cur'];
$prev = $stats['prev'];
$rate = function (array $p, string $part) { return $p['sessions'] > 0 ? $p[$part] / $p['sessions'] : null; };
$kpis = [
    [
        'label' => $t['kpi_visitors'],
        'value' => dashboardNumber($cur['visitors'], $lang),
        // Over several days the same person counts once per day.
        'note'  => $hourly ? '' : $t['counted_daily'],
        'tip'   => $t['tip_visitors'],
        'pill'  => growthPill($cur['visitors'], $prev['visitors'], 'pct', false, $t, $arrowUp, $arrowDown),
    ],
    [
        'label' => $t['sessions'],
        'value' => dashboardNumber($cur['sessions'], $lang),
        'tip'   => $t['tip_sessions'],
        'pill'  => growthPill($cur['sessions'], $prev['sessions'], 'pct', false, $t, $arrowUp, $arrowDown),
    ],
    [
        'label' => $t['kpi_views'],
        'value' => dashboardNumber($cur['views'], $lang),
        'tip'   => $t['tip_views'],
        'pill'  => growthPill($cur['views'], $prev['views'], 'pct', false, $t, $arrowUp, $arrowDown),
    ],
    [
        'label' => $t['bounce_rate'],
        'value' => $cur['sessions'] > 0 ? round($rate($cur, 'bounces') * 100) . '%' : '—',
        'tip'   => $t['tip_bounce'],
        'pill'  => growthPill(
            $cur['sessions'] > 0 ? $rate($cur, 'bounces') * 100 : null,
            $prev['sessions'] > 0 ? $rate($prev, 'bounces') * 100 : null,
            'pp', true, $t, $arrowUp, $arrowDown
        ),
    ],
    [
        'label' => $t['views_per_session'],
        'value' => $cur['sessions'] > 0 ? number_format($rate($cur, 'session_views'), 1, $decSep, '') : '—',
        'tip'   => $t['tip_views_per_session'],
        'pill'  => growthPill($rate($cur, 'session_views'), $rate($prev, 'session_views'), 'pct', false, $t, $arrowUp, $arrowDown),
    ],
    [
        'label' => $t['session_duration'],
        'value' => $cur['sessions'] > 0 ? formatDuration((int) round($rate($cur, 'session_secs'))) : '—',
        'tip'   => $t['tip_duration'],
        'pill'  => growthPill($rate($cur, 'session_secs'), $rate($prev, 'session_secs'), 'pct', false, $t, $arrowUp, $arrowDown),
    ],
];

if (!$hasPrev) {
    foreach ($kpis as $k => $kpi) {
        $kpis[$k]['pill'] = '<div class="kpi-delta"><span class="kpi-cmp">' . htmlspecialchars($t['no_prev']) . '</span></div>';
    }
}

// Chart data for the inline renderer.
$chartLabels = [];
foreach ($bucketKeys as $i => $key) {
    if ($hourly) {
        $tip = $key . ':00–' . sprintf('%02d', ((int) $key + 1) % 24) . ':00';
        $chartLabels[] = ['tick' => $key . ':00', 'tip' => $tip, 'prevTip' => $tip];
        continue;
    }
    $ts     = strtotime(max($key, $from));
    $prevTs = strtotime(max($prevBucketKeys[$i], $prevFrom));
    $dayFmt = function (int $ts) use ($lang, $weekdaysShort): string {
        return $weekdaysShort[(int) date('w', $ts)] . ', ' . date('j', $ts) . ($lang === 'de' ? '. ' : ' ') . dashboardMonthShort($ts, $lang);
    };
    $shortFmt = function (int $ts) use ($lang): string {
        return date('j', $ts) . ($lang === 'de' ? '. ' : ' ') . dashboardMonthShort($ts, $lang);
    };
    $chartLabels[] = [
        'tick'    => $shortFmt($ts),
        'tip'     => $bucketStep === 1 ? $dayFmt($ts) : sprintf($t['week_of'], $shortFmt($ts)),
        'prevTip' => $bucketStep === 1 ? $dayFmt($prevTs) : sprintf($t['week_of'], $shortFmt($prevTs)),
    ];
}
$chartCurValues = array_map('array_values', $chartCur);
if ($range === 'today') {
    // Hours that have not happened yet are unknown, not zero.
    foreach ($chartCurValues as $metric => $values) {
        for ($h = (int) date('G') + 1; $h < 24; $h++) $chartCurValues[$metric][$h] = null;
    }
}
if (!$hourly && $stats['first_date'] !== '') {
    // Days or weeks that began before tracking did are incomplete, not low.
    // The newest one always stays, so a fresh install still shows a point.
    $lastBucket = count($bucketKeys) - 1;
    foreach ($bucketKeys as $i => $key) {
        if ($key >= $stats['first_date'] || $i === $lastBucket) break;
        foreach ($chartCurValues as $metric => $values) $chartCurValues[$metric][$i] = null;
    }
}
$chartData = [
    'labels'   => $chartLabels,
    'cur'      => $chartCurValues,
    'prev'     => $hasPrev ? array_map('array_values', $chartPrev) : ['views' => [], 'visitors' => [], 'sessions' => []],
    'names'    => ['views' => $t['kpi_views'], 'visitors' => $t['kpi_visitors'], 'sessions' => $t['sessions']],
    'curName'  => $rangeLabel,
    'prevName' => $t['prev_period'],
];

$hourMax = max(1, max($stats['hours']));
$heatMax = 1;
foreach ($stats['heatmap'] as $heatRow) $heatMax = max($heatMax, max($heatRow));

$filterLabels = ['page' => $t['f_page'], 'ref' => $t['f_ref'], 'country' => $t['f_country'], 'device' => $t['f_device'], 'lang' => $t['f_lang']];

$lockRemaining = '';
if ($isLocked) {
    $secs = $lockedUntil - time();
    $lockRemaining = $secs > 60 ? round($secs/60).' min' : $secs.' sec';
}
?><!DOCTYPE html>
<html lang="<?= htmlspecialchars($lang) ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars($brandName) ?> · <?= htmlspecialchars($t['dashboard']) ?> · <?= dashboardDate(time(), $lang) ?></title>
<script>try{var th=localStorage.getItem('pima-theme');if(th==='light'||th==='dark')document.documentElement.setAttribute('data-theme',th);}catch(e){}</script>
<?php
  // Dark tokens apply for a dark system theme unless the viewer picked light,
  // and always when the viewer picked dark.
  $darkTokens = '
    --bg:        #0f1318;
    --surface:   #171c23;
    --border:    #29313b;
    --text:      #e5e8ec;
    --muted:     #8d97a5;
    --danger:    #f0857a;
    --good-bg:   #15301f;
    --good-text: #74d39b;
    --bad-bg:    #3a1916;
    --bad-text:  #f39a90;
    --error-bg:  #3a1916;
    --error-border: #5a2a25;
    --error-text: #f39a90;
    --tip-bg:    #e5e8ec;
    --tip-text:  #11151a;
    --danger-bg: #241514;
    --danger-border: #5a2a25;
    --code-bg:   #20262e;
    --header-bg: #0b0e12;
    --header-border: #1f252d;
    color-scheme: dark;';
?>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --accent:  <?= htmlspecialchars($brandColor) ?>;
    --bg:      #f5f7fa;
    --surface: #ffffff;
    --border:  #e2e6ed;
    --text:    #1a202c;
    --muted:   #6b7686;
    --danger:  #c0392b;
    --good-bg:   #e8f5e9;
    --good-text: #2d6a4f;
    --bad-bg:    #fdecea;
    --bad-text:  #c0392b;
    --error-bg:  #fdecea;
    --error-border: #f5c6c2;
    --error-text: #b42318;
    --tip-bg:    #1a202c;
    --tip-text:  #ffffff;
    --danger-bg: #fff9f9;
    --danger-border: #f5c6c2;
    --code-bg:   #f5f0eb;
    --header-bg: #333333;
    --header-border: #444444;
    --font:    <?= htmlspecialchars($brandFont) ?>;
    --sans:    system-ui, -apple-system, sans-serif;
    color-scheme: light;
  }
  @media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {<?= $darkTokens ?> } }
  :root[data-theme="dark"] {<?= $darkTokens ?> }
  body { font-family: var(--sans); background: var(--bg); color: var(--text); min-height: 100vh; }

  .logo-dark { display:none !important; }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) .logo-dark { display:block !important; }
    :root:not([data-theme="light"]) .logo-light { display:none !important; }
  }
  :root[data-theme="dark"] .logo-dark { display:block !important; }
  :root[data-theme="dark"] .logo-light { display:none !important; }

  @keyframes login-up { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }

  .login-wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:1.5rem; background:radial-gradient(ellipse at 30% 40%, <?= htmlspecialchars($brandColor) ?>0f, transparent 60%), var(--bg); }
  .login-box { width:100%; max-width:340px; animation:login-up .45s ease-out; background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:2rem; box-shadow:0 4px 24px rgba(26,32,44,.06); }
  .login-title { margin:0; }
  .login-box .sub { font-size:.8rem; color:var(--muted); margin:.25rem 0 2rem; text-transform:none; letter-spacing:0; }
  .login-error { padding:.6rem .85rem; background:var(--error-bg); border:1px solid var(--error-border); border-radius:7px; color:var(--error-text); font-size:.84rem; margin-bottom:1rem; }
  .login-error.blocking { background:#f87171; border-color:#f87171; color:#fff; }
  .login-locked { padding:.6rem .85rem; background:var(--error-bg); border:1px solid var(--error-border); border-radius:7px; color:var(--error-text); font-size:.84rem; margin-bottom:1rem; }
  .login-box input[type=password] { width:100%; padding:.8rem 1rem; background:var(--surface); border:1px solid var(--border); border-radius:10px; color:var(--text); font-family:inherit; font-size:.93rem; outline:0; transition:border-color .2s, box-shadow .2s; }
  .login-box input[type=password]:focus { border-color:var(--accent); box-shadow:0 0 0 3px <?= htmlspecialchars($brandColor) ?>22; }
  .login-box input[type=password]::placeholder { color:var(--muted); }
  .login-box input:disabled, .login-box button:disabled { opacity:.4; cursor:not-allowed; }
  .login-box button { width:100%; padding:.8rem; margin-top:.75rem; background:var(--accent); color:#fff; border:0; border-radius:10px; font-family:inherit; font-size:.93rem; font-weight:600; cursor:pointer; transition:opacity .15s, transform .1s; }
  .login-box button:hover:not(:disabled) { opacity:.88; }
  .login-box button:active:not(:disabled) { transform:scale(.98); }
  .login-help { font-size:.75rem; color:var(--muted); text-align:center; margin-top:1.25rem; line-height:1.5; }
  .attempts-hint { font-size:.72rem; color:var(--muted); margin-top:.4rem; }

  header { background:var(--header-bg); border-bottom:1px solid var(--header-border); padding:1rem 1.5rem; display:flex; align-items:center; justify-content:space-between; gap:1rem; flex-wrap:wrap; }
  .header-pima { display:flex; flex-direction:column; justify-content:center; }
  .header-tagline { font-size:.65rem; color:#aaaaaa; letter-spacing:.04em; margin-top:.1rem; }
  .header-actions { display:flex; align-items:center; gap:.75rem; flex-wrap:wrap; }
  .header-actions form { display:inline; margin:0; }
  .btn-ghost { background:none; border:1px solid #555555; border-radius:8px; padding:.3rem .75rem; font-family:inherit; font-size:.78rem; color:#aaaaaa; cursor:pointer; transition:all .15s; text-decoration:none; display:inline-block; }
  .btn-ghost:hover { border-color:#fff; color:#fff; }
  .btn-icon { width:2rem; height:1.85rem; padding:0; display:inline-flex; align-items:center; justify-content:center; }
  .btn-icon svg { width:15px; height:15px; }
  .btn-export { background:var(--accent); color:#fff; border:none; border-radius:8px; padding:.3rem .75rem; font-size:.78rem; cursor:pointer; text-decoration:none; display:inline-block; transition:opacity .15s; }
  .btn-export:hover { opacity:.85; }

  .live-badge { display:inline-flex; align-items:center; gap:.45rem; font-size:.78rem; color:#d6d9de; padding:.3rem .7rem; border:1px solid #555555; border-radius:20px; cursor:default; }
  .live-dot { width:8px; height:8px; border-radius:50%; background:#3ddc84; animation:live-pulse 2s infinite; }
  .live-badge.idle .live-dot { background:#777; animation:none; }
  @keyframes live-pulse { 0% { box-shadow:0 0 0 0 rgba(61,220,132,.55); } 70% { box-shadow:0 0 0 7px rgba(61,220,132,0); } 100% { box-shadow:0 0 0 0 rgba(61,220,132,0); } }

  .site-name { text-align:center; font-family:var(--font); font-size:1.15rem; font-weight:600; color:var(--text); padding:.5rem 0 0; }
  .site-name img { max-height:80px; max-width:320px; }

  .range-bar { display:flex; gap:.35rem; overflow-x:auto; padding:.15rem .1rem .35rem; margin-top:1.25rem; scrollbar-width:thin; }
  .range-bar a { flex-shrink:0; font-size:.8rem; color:var(--muted); text-decoration:none; padding:.4rem .8rem; border-radius:20px; border:1px solid var(--border); background:var(--surface); transition:border-color .15s, color .15s; }
  .range-bar a:hover { color:var(--text); border-color:var(--muted); }
  .range-bar a[aria-current="page"] { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }

  .filter-bar { display:flex; align-items:center; gap:.4rem; flex-wrap:wrap; margin:.6rem 0 0; }
  .filter-label { font-size:.68rem; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-right:.2rem; }
  .chip { display:inline-flex; align-items:center; gap:.35rem; font-size:.8rem; color:var(--text); text-decoration:none; background:var(--surface); border:1px solid var(--accent); border-radius:20px; padding:.3rem .55rem .3rem .75rem; max-width:100%; }
  .chip:hover { background:var(--bg); }
  .chip-key { color:var(--muted); }
  .chip-x { font-size:1rem; line-height:1; color:var(--muted); }
  .chip-clear { font-size:.78rem; color:var(--muted); margin-left:.25rem; }

  .summary { padding:1rem 0 .5rem; }
  .summary-sentence { font-size:1.1rem; color:var(--text); line-height:1.6; }
  .summary-sentence strong { color:var(--accent); }
  .summary-date { font-size:.78rem; color:var(--muted); margin-top:.25rem; }

  main { max-width:1160px; margin:0 auto; padding:2rem 1.5rem; }

  .kpi-row { display:grid; grid-template-columns:repeat(6, minmax(0, 1fr)); gap:14px; margin:1rem 0 1.5rem; }
  @media (max-width:1100px) { .kpi-row { grid-template-columns:repeat(3, minmax(0, 1fr)); } }
  .kpi { background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1.1rem 1.1rem 1rem; min-width:0; display:flex; flex-direction:column; }
  .kpi-label { display:flex; align-items:center; gap:.4rem; font-size:.65rem; text-transform:uppercase; letter-spacing:.08em; color:var(--accent); margin-bottom:.5rem; }
  .kpi-value { font-family:var(--font); font-size:1.75rem; font-weight:700; line-height:1.1; white-space:nowrap; }

  /* Delta pills */
  .kpi-delta { display:flex; align-items:center; flex-wrap:wrap; gap:.2rem .4rem; margin-top:auto; padding-top:.55rem; }
  .kpi-cmp { font-size:.68rem; color:var(--muted); white-space:nowrap; }
  .kpi-note { font-size:.72rem; color:var(--muted); margin-top:.25rem; }
  .pill { display:inline-flex; align-items:center; gap:.25rem; padding:.2rem .55rem; border-radius:20px; font-size:.7rem; font-weight:600; white-space:nowrap; }
  .pill.up   { background:var(--good-bg); color:var(--good-text); }
  .pill.down { background:var(--bad-bg); color:var(--bad-text); }
  .pill.same { background:var(--bg); color:var(--muted); }
  .pill svg  { width:10px; height:10px; flex-shrink:0; }

  /* Rank delta pills */
  .delta-pill { display:inline-flex; align-items:center; justify-content:center; min-width:3rem; gap:.2rem; padding:.15rem .45rem; border-radius:20px; font-size:.65rem; font-weight:600; flex-shrink:0; }
  .delta-pill.up   { background:var(--good-bg); color:var(--good-text); }
  .delta-pill.down { background:var(--bad-bg); color:var(--bad-text); }
  .delta-pill.same { background:var(--bg); color:var(--muted); }

  .card { background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1.5rem; margin-bottom:14px; }
  .card h2 { font-family:var(--font); font-size:.95rem; font-weight:700; margin-bottom:1rem; padding-bottom:.75rem; border-bottom:1px solid var(--border); }
  .card-head { display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; margin-bottom:1rem; padding-bottom:.75rem; border-bottom:1px solid var(--border); }
  .card .card-head h2 { margin:0; padding:0; border:0; }
  .card-head h2 .card-window { margin-left:.35rem; }
  .card-head .seg { margin-left:auto; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:14px; }
  .grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; margin-bottom:14px; }
  .grid-2 > .card, .grid-3 > .card { min-width:0; margin-bottom:0; }
  @media (max-width:900px) { .grid-3 { grid-template-columns:1fr 1fr; } }
  @media (max-width:640px) { .grid-2, .grid-3 { grid-template-columns:1fr; } }

  /* Trend chart */
  .seg { display:inline-flex; background:var(--bg); border:1px solid var(--border); border-radius:9px; padding:2px; font-family:var(--sans); }
  .seg button { background:none; border:0; border-radius:7px; padding:.3rem .65rem; font-family:inherit; font-size:.75rem; font-weight:500; color:var(--muted); cursor:pointer; }
  .seg button[aria-pressed="true"] { background:var(--surface); color:var(--text); box-shadow:0 1px 2px rgba(0,0,0,.08); }
  .chart { position:relative; height:240px; touch-action:pan-y; }
  .chart svg { display:block; width:100%; height:100%; overflow:visible; }
  .chart .grid-line { stroke:var(--border); stroke-width:1; }
  .chart .axis-label { fill:var(--muted); font-size:10px; font-family:var(--sans); }
  .chart .line-cur { fill:none; stroke:var(--accent); stroke-width:2; stroke-linejoin:round; stroke-linecap:round; }
  .chart .area-cur { fill:var(--accent); opacity:.12; }
  .chart .line-prev { fill:none; stroke:var(--muted); stroke-width:1.5; stroke-dasharray:4 4; opacity:.7; }
  .chart .cursor { stroke:var(--muted); stroke-width:1; opacity:.6; }
  .chart .dot-cur { fill:var(--accent); stroke:var(--surface); stroke-width:2; }
  .chart .dot-prev { fill:var(--muted); stroke:var(--surface); stroke-width:2; }
  .chart-tip { position:absolute; top:0; pointer-events:none; background:var(--tip-bg); color:var(--tip-text); font-size:.72rem; line-height:1.5; padding:.45rem .65rem; border-radius:7px; white-space:nowrap; display:none; z-index:5; }
  .chart-tip b { font-weight:700; }
  .chart-tip .muted-line { opacity:.7; }
  .legend { display:flex; gap:1rem; font-size:.72rem; color:var(--muted); margin-top:.6rem; }
  .legend span { display:inline-flex; align-items:center; gap:.4rem; }
  .legend i { display:inline-block; width:16px; height:0; border-top:2px solid var(--accent); }
  .legend i.key-prev { border-top:2px dashed var(--muted); }

  /* Weekday × hour heatmap */
  .heatmap { display:flex; flex-direction:column; gap:3px; }
  .hm-row { display:grid; grid-template-columns:2.2rem repeat(24, minmax(0, 1fr)); gap:3px; align-items:center; }
  .hm-head span { font-size:.6rem; color:var(--muted); }
  .hm-day { font-size:.7rem; color:var(--muted); }
  .hm-cell { height:20px; border-radius:3px; background:var(--accent); }
  .hm-cell.hm-zero { background:var(--bg); }
  @media (max-width:640px) { .hm-cell { height:14px; border-radius:2px; } .hm-row { gap:2px; grid-template-columns:1.8rem repeat(24, minmax(0, 1fr)); } }

  .hours-chart { display:flex; align-items:flex-end; gap:2px; height:96px; }
  .hour-col { flex:1; display:flex; flex-direction:column; align-items:center; height:100%; justify-content:flex-end; gap:2px; }
  .hour-col .bar { width:100%; background:var(--accent); opacity:.65; border-radius:2px 2px 0 0; min-height:2px; transition:opacity .15s; }
  .hour-col:hover .bar { opacity:1; }
  .hour-col .lbl { font-size:.48rem; color:var(--muted); }

  .rank-list { list-style:none; }
  .rank-list li { display:flex; align-items:center; gap:.6rem; padding:.45rem 0; border-bottom:1px solid var(--border); font-size:.82rem; }
  .rank-list li:last-child { border-bottom:none; }
  .rank-n { font-size:.68rem; color:var(--muted); width:1.2rem; text-align:right; flex-shrink:0; }
  .rank-label { flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .rank-label > span { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .rank-title { font-weight:600; font-size:.82rem; line-height:1.3; }
  .rank-sub { font-size:.7rem; color:var(--muted); line-height:1.3; }
  .rank-link { color:inherit; text-decoration:none; border-radius:4px; }
  .rank-link:hover { color:var(--accent); }
  .rank-link:hover .rank-title, .rank-link:hover .rank-sub { text-decoration:underline; text-underline-offset:2px; }
  .rank-track { width:60px; height:5px; background:var(--bg); border-radius:3px; overflow:hidden; flex-shrink:0; }
  .rank-fill { height:100%; background:var(--accent); opacity:.6; border-radius:3px; }
  .rank-count { font-size:.8rem; font-weight:600; width:2.2rem; text-align:right; flex-shrink:0; }

  .dev-row { display:flex; align-items:center; gap:.75rem; padding:.4rem 0; }
  .dev-label { font-size:.8rem; width:4.5rem; flex-shrink:0; }
  .dev-label.wide { width:8rem; }
  .dev-label.icon { display:flex; align-items:center; gap:.4rem; width:5.5rem; }
  .dev-track { flex:1; height:7px; background:var(--bg); border-radius:4px; overflow:hidden; }
  .dev-fill { height:100%; background:var(--accent); border-radius:4px; }
  .dev-fill.mobile { opacity:.7; }
  .dev-fill.tablet { opacity:.45; }
  .dev-pct { font-size:.75rem; color:var(--muted); width:2.5rem; text-align:right; flex-shrink:0; }

  /* Latest sessions */
  .session-list { list-style:none; }
  .session-list li { display:grid; grid-template-columns:8.5rem minmax(0, 1fr) auto; gap:.4rem 1rem; align-items:center; padding:.6rem 0; border-bottom:1px solid var(--border); font-size:.8rem; }
  .session-list li:last-child { border-bottom:none; }
  .sess-meta { display:flex; flex-direction:column; gap:.15rem; }
  .sess-time { font-weight:600; }
  .sess-icons { display:inline-flex; align-items:center; gap:.35rem; color:var(--muted); }
  .sess-path { display:flex; align-items:center; flex-wrap:wrap; gap:.3rem; min-width:0; }
  .sess-source { font-size:.72rem; color:var(--accent); background:var(--bg); border-radius:20px; padding:.1rem .5rem; }
  .sess-arrow { color:var(--muted); font-size:.72rem; }
  .sess-page { max-width:14rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .sess-more { color:var(--muted); font-size:.72rem; }
  .sess-stats { display:flex; flex-direction:column; align-items:flex-end; gap:.15rem; color:var(--muted); font-size:.72rem; white-space:nowrap; }
  @media (max-width:640px) {
    .session-list li { grid-template-columns:1fr auto; }
    .sess-path { grid-column:1 / -1; grid-row:2; }
  }

  .danger-zone { border:1px solid var(--danger-border); border-radius:14px; padding:1.5rem; margin-bottom:14px; background:var(--danger-bg); }
  .danger-zone h2 { font-family:var(--font); font-size:.95rem; font-weight:700; color:var(--danger); margin-bottom:.5rem; }
  .danger-zone p { font-size:.82rem; color:var(--muted); margin-bottom:1rem; }
  .danger-zone .db-info { font-size:.78rem; color:var(--muted); margin-bottom:1rem; font-family:monospace; background:var(--code-bg); padding:.5rem .75rem; border-radius:6px; }
  .btn-danger { background:var(--danger); color:#fff; border:none; border-radius:8px; padding:.5rem 1rem; font-size:.82rem; cursor:pointer; transition:opacity .15s; }
  .btn-danger:hover { opacity:.85; }
  .confirm-box { margin-top:.75rem; display:none; }
  .confirm-box.visible { display:block; }
  .confirm-box p { font-size:.8rem; color:var(--danger); margin-bottom:.5rem; }

  .pw-card { max-width:440px; margin:1rem auto 14px; }
  .pw-card > p { font-size:.82rem; color:var(--muted); line-height:1.5; margin-bottom:1rem; }
  .pw-form label { display:block; font-size:.78rem; font-weight:600; margin:.9rem 0 .35rem; }
  .pw-form input[type=password] { width:100%; padding:.65rem .85rem; background:var(--surface); border:1px solid var(--border); border-radius:8px; color:var(--text); font-family:inherit; font-size:.9rem; outline:0; transition:border-color .2s, box-shadow .2s; }
  .pw-form input[type=password]:focus { border-color:var(--accent); box-shadow:0 0 0 3px <?= htmlspecialchars($brandColor) ?>22; }
  .pw-form button { margin-top:1.25rem; padding:.65rem 1.25rem; background:var(--accent); color:#fff; border:0; border-radius:8px; font-family:inherit; font-size:.88rem; font-weight:600; cursor:pointer; transition:opacity .15s; }
  .pw-form button:hover { opacity:.88; }
  .pw-hint { font-size:.72rem; color:var(--muted); margin-top:.5rem; line-height:1.5; }
  .pw-back { margin-top:1rem; font-size:.8rem; }
  .pw-back a { color:var(--accent); }
  .alert-success { background:var(--good-bg); border:1px solid var(--good-text); color:var(--good-text); padding:.6rem 1rem; border-radius:8px; font-size:.82rem; margin-bottom:1rem; }
  .recent summary { cursor:pointer; list-style:none; justify-content:space-between; }
  .recent summary::-webkit-details-marker { display:none; }
  .recent:not([open]) summary { margin-bottom:0; padding-bottom:0; border-bottom:0; }
  .toggle { border:1px solid var(--border); border-radius:8px; padding:.3rem .75rem; font-size:.78rem; color:var(--muted); }
  .recent[open] .when-closed, .recent:not([open]) .when-open { display:none; }
  @media (max-width:640px) {
    .rank-track { display:none; }
    main { padding:1.25rem 1rem; }
    .card { padding:1.15rem; }
  }
  @media (max-width:560px) {
    .kpi-row { grid-template-columns:repeat(2, minmax(0, 1fr)); gap:10px; }
    .kpi { padding:.9rem .9rem .8rem; }
    .kpi-value { font-size:1.5rem; }
    .kpi-cmp { display:none; }
  }
  .file-info { font-size:.72rem; color:var(--muted); margin-top:.75rem; }
  .section-note { font-size:.72rem; color:var(--muted); margin-top:.5rem; }
  .empty { text-align:center; padding:2.5rem; color:var(--muted); font-size:.85rem; }
  .no-data { color:var(--muted); font-size:.82rem; padding:.5rem 0; }

  /* Info tooltips */
  .card-window { font-size:.72rem; font-weight:400; color:var(--muted); }
  .info-btn {
    display:inline-flex; align-items:center; justify-content:center;
    width:15px; height:15px; border-radius:50%;
    border:1px solid var(--border); color:var(--muted);
    font-size:.55rem; font-weight:700; cursor:default;
    position:relative; flex-shrink:0; font-style:normal;
    line-height:1; font-family:var(--sans); opacity:.6; background:none; padding:0;
    text-transform:none; letter-spacing:0;
  }
  .info-btn:hover, .info-btn.active { opacity:1; border-color:var(--muted); cursor:pointer; }
  .info-btn::after {
    content: attr(data-tip);
    position:absolute; bottom:calc(100% + 6px); left:50%;
    transform:translateX(-50%);
    background:var(--tip-bg); color:var(--tip-text);
    font-size:.72rem; font-weight:400; font-style:normal;
    padding:.4rem .6rem; border-radius:6px;
    white-space:normal; width:max-content; max-width:200px;
    pointer-events:none; display:none;
    z-index:10; line-height:1.4;
  }
  @media (hover: hover) { .info-btn:hover::after { display:block; } }
  .info-btn:focus-visible::after { display:block; }
  .tooltip-float {
    display:none; position:fixed;
    background:var(--tip-bg); color:var(--tip-text);
    font-size:.72rem; font-weight:400; font-style:normal;
    padding:.4rem .6rem; border-radius:6px;
    max-width:200px; line-height:1.4;
    z-index:1000; pointer-events:none; white-space:normal;
  }
  a:focus-visible, button:focus-visible, input:focus-visible, summary:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation:none !important; transition:none !important; } }
</style>
</head>
<body>

<?php if (!$authed): ?>
<div class="login-wrap">
  <div class="login-box">
    <h1 class="login-title">
    <?php if ($brandLogo): ?>
      <img src="<?= htmlspecialchars($brandLogo) ?>" alt="<?= htmlspecialchars($brandName) ?>" style="height:42px;width:auto;display:block;margin-bottom:.15rem;">
    <?php else: ?>
      <img class="logo-light" src="<?= $pimaLogoLight ?>" alt="pima Analytics" style="height:42px;width:auto;display:block;margin-bottom:.15rem;">
      <img class="logo-dark" src="<?= $pimaLogoDark ?>" alt="" style="height:42px;width:auto;display:block;margin-bottom:.15rem;">
    <?php endif; ?>
    </h1>
    <p class="sub"><?= htmlspecialchars($brandName) ?></p>
    <?php if ($defaultPassword): ?>
      <div class="login-error blocking"><?= htmlspecialchars($t[$pwOverride === '' ? 'pw_err_file' : 'warn_default_pw']) ?></div>
    <?php endif; ?>
    <?php if (!empty($authUnavailable)): ?>
      <div class="login-error"><?= htmlspecialchars($t['auth_unavailable']) ?></div>
    <?php elseif ($isLocked): ?>
      <div class="login-locked"><?= sprintf($t['locked_out'], $lockRemaining) ?></div>
    <?php elseif (!empty($authError)): ?>
      <div class="login-error"><?= htmlspecialchars($t['wrong_password']) ?></div>
      <?php
        $rem = $maxAttempts - $attempts;
        if ($rem <= 2 && $rem > 0):
          $pluralSuffix = $rem === 1 ? '' : ($lang === 'de' ? 'e' : 's');
      ?>
        <div class="attempts-hint"><?= sprintf($t['attempts_left'], $rem, $pluralSuffix) ?></div>
      <?php endif; ?>
    <?php endif; ?>
    <form method="POST">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
      <input type="password" name="password" placeholder="<?= htmlspecialchars($t['password_ph']) ?>" autofocus autocomplete="current-password" <?= $isLocked || $defaultPassword ? 'disabled' : '' ?>>
      <button type="submit" <?= $isLocked || $defaultPassword ? 'disabled' : '' ?>><?= $t['login_btn'] ?></button>
    </form>
    <p class="login-help"><?= htmlspecialchars($t['login_help']) ?></p>
  </div>
</div>

<?php else: ?>

<header>
  <div class="header-pima">
    <img src="<?= $pimaLogoDark ?>" alt="pima Analytics" style="height:28px;width:auto;display:block;">
    <div class="header-tagline"><?= htmlspecialchars($t['tagline']) ?></div>
  </div>
  <div class="header-actions">
    <span class="live-badge<?= $stats['active_now'] === 0 ? ' idle' : '' ?>" id="live-badge" title="<?= htmlspecialchars($t['tip_live']) ?>" data-label="<?= htmlspecialchars($t['live_label']) ?>">
      <span class="live-dot" aria-hidden="true"></span>
      <span id="live-text"><?= htmlspecialchars(sprintf($t['live_label'], $stats['active_now'])) ?></span>
    </span>
    <a href="/" target="_blank" rel="noopener noreferrer" class="btn-ghost"><?= htmlspecialchars($t['back_to_site']) ?></a>
    <a href="?export=1" class="btn-export"><?= $t['export'] ?></a>
    <a href="<?= htmlspecialchars(dashUrl()) ?>" class="btn-ghost"><?= $t['refresh'] ?></a>
    <?php if ($pwChange): ?><a href="?password=1" class="btn-ghost"><?= htmlspecialchars($t['pw_link']) ?></a><?php endif; ?>
    <button type="button" class="btn-ghost btn-icon" id="theme-toggle" aria-label="<?= htmlspecialchars($t['theme_toggle']) ?>" title="<?= htmlspecialchars($t['theme_toggle']) ?>">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
    </button>
    <form method="POST">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
      <button type="submit" name="logout" value="1" class="btn-ghost"><?= $t['logout'] ?></button>
    </form>
  </div>
</header>

<main>

<h1 class="site-name">
  <?php if ($brandLogo): ?>
    <img src="<?= htmlspecialchars($brandLogo) ?>" alt="<?= htmlspecialchars($brandName) ?>">
  <?php else: ?>
    <?= htmlspecialchars($brandName) ?>
  <?php endif; ?>
</h1>

<?php if ($pwView): ?>
<div class="card pw-card">
  <h2><?= htmlspecialchars($t['pw_title']) ?></h2>
  <?php if ($pwMsg): ?><div class="<?= $pwMsgType === 'success' ? 'alert-success' : 'login-error' ?>" role="status"><?= htmlspecialchars($pwMsg) ?></div><?php endif; ?>
  <?php if ($pwMsgType !== 'success'): ?>
  <form method="POST" action="?password=1" class="pw-form">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
    <input type="hidden" name="pw_change" value="1">
    <label for="pw_cur"><?= htmlspecialchars($t['pw_current']) ?></label>
    <input type="password" id="pw_cur" name="pw_current" autocomplete="current-password" required>
    <label for="pw_new"><?= htmlspecialchars($t['pw_new']) ?></label>
    <input type="password" id="pw_new" name="pw_new" autocomplete="new-password" minlength="10" required aria-describedby="pw_new_h">
    <p class="pw-hint" id="pw_new_h"><?= htmlspecialchars($t['pw_rule']) ?></p>
    <label for="pw_rep"><?= htmlspecialchars($t['pw_repeat']) ?></label>
    <input type="password" id="pw_rep" name="pw_repeat" autocomplete="new-password" minlength="10" required>
    <button type="submit"><?= htmlspecialchars($t['pw_btn']) ?></button>
  </form>
  <?php endif; ?>
  <p class="pw-back"><a href="?"><?= htmlspecialchars($t['pw_back']) ?></a></p>
</div>
<?php else: ?>

<?php if (!empty($clearSuccess)): ?>
  <div class="alert-success"><?= $t['cleared'] ?></div>
<?php endif; ?>

<?php if ($stats['total'] === 0): ?>
  <div class="card"><div class="empty"><?= $t['no_data'] ?></div></div>
<?php else: ?>

<nav class="range-bar" aria-label="<?= htmlspecialchars($t['range_nav']) ?>">
  <?php foreach ($rangeIds as $rangeId): ?>
    <a href="<?= htmlspecialchars(dashUrl(['range' => $rangeId])) ?>"<?= $rangeId === $range ? ' aria-current="page"' : '' ?>><?= htmlspecialchars($t['range_' . $rangeId]) ?></a>
  <?php endforeach; ?>
</nav>

<?php if ($filters): ?>
<div class="filter-bar">
  <span class="filter-label"><?= htmlspecialchars($t['filter_label']) ?></span>
  <?php foreach ($filters as $fKey => $fValue):
    if ($fKey === 'country')    $fShown = trim(countryFlag($fValue) . ' ' . countryName($fValue, $countryNames));
    elseif ($fKey === 'device') $fShown = $t['device_' . $fValue];
    elseif ($fKey === 'lang')   $fShown = langName($fValue, $langNames);
    else                        $fShown = $fValue;
  ?>
    <a class="chip" href="<?= htmlspecialchars(dashUrl([], [$fKey])) ?>" title="<?= htmlspecialchars($t['filter_remove']) ?>">
      <span class="chip-key"><?= htmlspecialchars($filterLabels[$fKey]) ?></span> <?= htmlspecialchars($fShown) ?> <span class="chip-x" aria-hidden="true">×</span>
    </a>
  <?php endforeach; ?>
  <?php if (count($filters) > 1): ?>
    <a class="chip-clear" href="<?= htmlspecialchars(dashUrl([], array_keys($filters))) ?>"><?= htmlspecialchars($t['filter_clear']) ?></a>
  <?php endif; ?>
</div>
<?php endif; ?>

<?php
  $avgPerDay = number_format($cur['views'] / max(1, $stats['covered_days']), 1, $decSep, '');
  $daySuffix = $stats['covered_days'] === 1 ? '' : ($lang === 'de' ? 'e' : 's');
?>
<div class="summary">
  <div class="summary-sentence">
    <?= sprintf($t['summary'], dashboardNumber($cur['views'], $lang), htmlspecialchars($t['phrase_' . $range])) ?>
  </div>
  <?php if (!$hourly): ?>
  <div class="summary-sentence" style="margin-top:.3rem;">
    <?= $stats['covered_days'] < $rangeDays
        ? sprintf($t['summary_avg_partial'], $avgPerDay, $stats['covered_days'], $daySuffix)
        : sprintf($t['summary_avg_full'], $avgPerDay) ?>
  </div>
  <?php endif; ?>
  <div class="summary-date"><?= dashboardDate(time(), $lang) ?> · <?= htmlspecialchars(TIMEZONE) ?> · <?= sprintf($t['all_time_total'], dashboardNumber($stats['total'], $lang)) ?></div>
</div>

<div class="kpi-row">
  <?php foreach ($kpis as $kpi): ?>
  <div class="kpi">
    <div class="kpi-label"><?= htmlspecialchars($kpi['label']) ?> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($kpi['tip']) ?>" aria-label="<?= htmlspecialchars($kpi['tip']) ?>">i</button></div>
    <div class="kpi-value"><?= $kpi['value'] ?></div>
    <?php if (!empty($kpi['note'])): ?><div class="kpi-note"><?= htmlspecialchars($kpi['note']) ?></div><?php endif; ?>
    <?= $kpi['pill'] ?>
  </div>
  <?php endforeach; ?>
</div>

<div class="card">
  <div class="card-head">
    <h2><?= $t['chart_title'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_chart']) ?>" aria-label="<?= htmlspecialchars($t['tip_chart']) ?>">i</button>
    <span class="seg" role="group" aria-label="<?= htmlspecialchars($t['chart_metric']) ?>">
      <?php foreach (['visitors', 'sessions', 'views'] as $metric): ?>
        <button type="button" data-metric="<?= $metric ?>" aria-pressed="<?= $metric === 'views' ? 'true' : 'false' ?>"><?= htmlspecialchars($chartData['names'][$metric]) ?></button>
      <?php endforeach; ?>
    </span>
  </div>
  <div id="chart" class="chart" data-metric="views" role="img" aria-label="<?= htmlspecialchars(sprintf($t['chart_aria'], $rangeLabel)) ?>"></div>
  <div class="legend">
    <span><i></i><?= htmlspecialchars($rangeLabel) ?></span>
    <?php if ($hasPrev): ?><span><i class="key-prev"></i><?= htmlspecialchars($t['prev_period']) ?></span><?php endif; ?>
  </div>
  <script type="application/json" id="chart-data"><?= json_encode($chartData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?></script>
</div>

<div class="grid-3">
  <div class="card">
    <div class="card-head"><h2><?= $t['channels'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_channels']) ?>" aria-label="<?= htmlspecialchars($t['tip_channels']) ?>">i</button></div>
    <?php
      $chTotal = array_sum($stats['channels']);
      $chLabels = ['direct' => $t['ch_direct'], 'organic' => $t['ch_organic'], 'social' => $t['ch_social'], 'referral' => $t['ch_referral']];
      arsort($stats['channels']);
      $chPercentages = wholePercentages($stats['channels']);
    ?>
    <?php if ($chTotal === 0): ?>
      <p class="no-data"><?= htmlspecialchars($t['no_channels']) ?></p>
    <?php else: foreach ($stats['channels'] as $chKey => $chVal):
      $chPct = $chPercentages[$chKey]; ?>
      <div class="dev-row">
        <span class="dev-label wide"><?= $chLabels[$chKey] ?></span>
        <div class="dev-track"><div class="dev-fill" style="width:<?= $chPct ?>%;opacity:<?= $chKey === 'organic' ? '1' : ($chKey === 'social' ? '.75' : ($chKey === 'referral' ? '.5' : '.35')) ?>"></div></div>
        <span class="dev-pct"><?= $chPct ?>%</span>
      </div>
    <?php endforeach; endif; ?>
  </div>

  <div class="card">
    <div class="card-head"><h2><?= $t['device_type'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_device']) ?>" aria-label="<?= htmlspecialchars($t['tip_device']) ?>">i</button></div>
    <?php $devicePercentages = wholePercentages($stats['devices']); ?>
    <?php $deviceOrder = $stats['devices']; arsort($deviceOrder);
      foreach (array_keys($deviceOrder) as $type):
        if (!isset($deviceIcons[$type])) continue;
      $pct = $devicePercentages[$type]; ?>
      <div class="dev-row">
        <a class="dev-label icon rank-link" href="<?= htmlspecialchars(dashUrl(['device' => $type])) ?>" title="<?= htmlspecialchars($t['filter_by'] . ': ' . $t['device_' . $type]) ?>"><?= $deviceIcons[$type] ?><?= htmlspecialchars($t['device_' . $type]) ?></a>
        <div class="dev-track"><div class="dev-fill <?= $type ?>" style="width:<?= $pct ?>%"></div></div>
        <span class="dev-pct"><?= $pct ?>%</span>
      </div>
    <?php endforeach; ?>
  </div>

  <div class="card">
    <div class="card-head"><h2><?= $t['time_of_day'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_tod']) ?>" aria-label="<?= htmlspecialchars($t['tip_tod']) ?>">i</button></div>
    <div class="hours-chart">
      <?php for ($h = 0; $h < 24; $h++):
        $hh = max(2, round($stats['hours'][$h] / $hourMax * 100)); ?>
        <div class="hour-col" title="<?= sprintf('%02d', $h) ?>:00 — <?= dashboardNumber($stats['hours'][$h], $lang) ?> <?= $t['views'] ?>">
          <div class="bar" style="height:<?= $hh ?>%"></div>
          <div class="lbl"><?= $h % 6 === 0 ? sprintf('%02d', $h) : '' ?></div>
        </div>
      <?php endfor; ?>
    </div>
    <?php
      $peakHour  = (int) array_search(max($stats['hours']), $stats['hours'], true);
      $peakViews = $stats['hours'][$peakHour];
    ?>
    <?php if ($peakViews > 0): ?>
      <p class="section-note" style="margin-top:.6rem;"><?= $t['peak'] ?>: <?= sprintf('%02d', $peakHour) ?>:00 – <?= sprintf('%02d', ($peakHour + 1) % 24) ?>:00 · <?= dashboardNumber($peakViews, $lang) ?> <?= $t['views'] ?></p>
    <?php endif; ?>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <div class="card-head"><h2><?= $t['top_pages'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_pages']) ?>" aria-label="<?= htmlspecialchars($t['tip_pages']) ?>">i</button></div>
    <?php if (empty($stats['pages'])): ?>
      <p class="no-data"><?= $t['no_pages'] ?></p>
    <?php else:
      $maxP = max(array_column($stats['pages'], 'c')); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['pages'] as $p => $pageData):
        $p      = (string) $p;
        $c      = $pageData['c'];
        $ptitle = $pageData['title'];
        $prevC  = $stats['pages_prev'][$p] ?? 0;
        $diff   = $c - $prevC;
        $dClass = $diff > 0 ? 'up' : ($diff < 0 ? 'down' : 'same');
        $dLabel = $diff > 0 ? '+' . $diff : ($diff < 0 ? (string)$diff : '—');
        if (!$hasPrev) { $dClass = 'same'; $dLabel = '—'; }
      ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <a class="rank-label rank-link" href="<?= htmlspecialchars(dashUrl(['page' => $p])) ?>" title="<?= htmlspecialchars($t['filter_by'] . ': ' . $p) ?>">
            <?php if (!empty($ptitle)): ?>
              <span class="rank-title"><?= htmlspecialchars($ptitle) ?></span>
              <span class="rank-sub"><?= htmlspecialchars($p) ?></span>
            <?php else: ?>
              <?= htmlspecialchars($p) ?>
            <?php endif; ?>
          </a>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxP*100) ?>%"></div></div>
          <span class="rank-count"><?= dashboardNumber($c, $lang) ?></span>
          <span class="delta-pill <?= $dClass ?>"><?= $dLabel ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>

  <div class="card">
    <div class="card-head"><h2><?= $t['entry_pages'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_entry']) ?>" aria-label="<?= htmlspecialchars($t['tip_entry']) ?>">i</button></div>
    <?php if (empty($stats['entry_pages'])): ?>
      <p class="no-data"><?= $t['no_external'] ?></p>
    <?php else:
      $maxE = max(array_column($stats['entry_pages'], 'c')); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['entry_pages'] as $p => $entryData):
        $p      = (string) $p;
        $c      = $entryData['c'];
        $etitle = $entryData['title'];
      ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <a class="rank-label rank-link" href="<?= htmlspecialchars(dashUrl(['page' => $p])) ?>" title="<?= htmlspecialchars($t['filter_by'] . ': ' . $p) ?>">
            <?php if (!empty($etitle)): ?>
              <span class="rank-title"><?= htmlspecialchars($etitle) ?></span>
              <span class="rank-sub"><?= htmlspecialchars($p) ?></span>
            <?php else: ?>
              <?= htmlspecialchars($p) ?>
            <?php endif; ?>
          </a>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxE*100) ?>%"></div></div>
          <span class="rank-count"><?= dashboardNumber($c, $lang) ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <div class="card-head"><h2><?= $t['exit_pages'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_exit']) ?>" aria-label="<?= htmlspecialchars($t['tip_exit']) ?>">i</button></div>
    <?php if (empty($stats['exit_pages'])): ?>
      <p class="no-data"><?= $t['no_sessions'] ?></p>
    <?php else:
      $maxX = max(array_column($stats['exit_pages'], 'c')); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['exit_pages'] as $p => $exitData):
        $p      = (string) $p;
        $c      = $exitData['c'];
        $xtitle = $exitData['title'];
      ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <a class="rank-label rank-link" href="<?= htmlspecialchars(dashUrl(['page' => $p])) ?>" title="<?= htmlspecialchars($t['filter_by'] . ': ' . $p) ?>">
            <?php if (!empty($xtitle)): ?>
              <span class="rank-title"><?= htmlspecialchars($xtitle) ?></span>
              <span class="rank-sub"><?= htmlspecialchars($p) ?></span>
            <?php else: ?>
              <?= htmlspecialchars($p) ?>
            <?php endif; ?>
          </a>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxX*100) ?>%"></div></div>
          <span class="rank-count"><?= dashboardNumber($c, $lang) ?></span>
          <span class="delta-pill same"><?= $exitData['rate'] ?>%</span>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>

  <div class="card">
    <div class="card-head"><h2><?= $t['session_depth'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_depth']) ?>" aria-label="<?= htmlspecialchars($t['tip_depth']) ?>">i</button></div>
    <?php if ($cur['sessions'] === 0): ?>
      <p class="no-data"><?= $t['no_sessions'] ?></p>
    <?php else:
      $depthPercentages = wholePercentages($stats['session_depth']);
      foreach (['1', '2', '3', '5'] as $depthKey):
        $depthPct = $depthPercentages[$depthKey]; ?>
      <div class="dev-row">
        <span class="dev-label wide"><?= htmlspecialchars($t['depth_' . $depthKey]) ?></span>
        <div class="dev-track"><div class="dev-fill" style="width:<?= $depthPct ?>%"></div></div>
        <span class="dev-pct"><?= $depthPct ?>%</span>
      </div>
    <?php endforeach; endif; ?>
  </div>
</div>

<?php if ($rangeDays >= 7): ?>
<div class="card">
  <div class="card-head"><h2><?= $t['heatmap_title'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_heatmap']) ?>" aria-label="<?= htmlspecialchars($t['tip_heatmap']) ?>">i</button></div>
  <?php
    $peakDay = 1; $peakHour = 0; $peakViews = 0;
    foreach ($stats['heatmap'] as $wd => $heatRow) {
        foreach ($heatRow as $h => $v) {
            if ($v > $peakViews) { $peakViews = $v; $peakDay = $wd; $peakHour = $h; }
        }
    }
  ?>
  <div class="heatmap" role="img" aria-label="<?= htmlspecialchars($t['heatmap_title']) ?>">
    <div class="hm-row hm-head">
      <span></span>
      <?php for ($h = 0; $h < 24; $h++): ?><span><?= $h % 6 === 0 ? sprintf('%02d', $h) : '' ?></span><?php endfor; ?>
    </div>
    <?php foreach ([1, 2, 3, 4, 5, 6, 0] as $wd): ?>
    <div class="hm-row">
      <span class="hm-day"><?= $weekdaysShort[$wd] ?></span>
      <?php for ($h = 0; $h < 24; $h++):
        $v = $stats['heatmap'][$wd][$h]; ?>
        <span class="hm-cell<?= $v === 0 ? ' hm-zero' : '' ?>"<?= $v > 0 ? ' style="opacity:' . round(.15 + .85 * $v / $heatMax, 2) . '"' : '' ?> title="<?= $weekdaysShort[$wd] ?> <?= sprintf('%02d', $h) ?>:00 · <?= dashboardNumber($v, $lang) ?> <?= htmlspecialchars($t['views']) ?>"></span>
      <?php endfor; ?>
    </div>
    <?php endforeach; ?>
  </div>
  <?php if ($peakViews > 0): ?>
    <p class="section-note" style="margin-top:.6rem;"><?= $t['peak'] ?>: <?= $weekdaysShort[$peakDay] ?> <?= sprintf('%02d', $peakHour) ?>:00 – <?= sprintf('%02d', ($peakHour + 1) % 24) ?>:00 · <?= dashboardNumber($peakViews, $lang) ?> <?= $t['views'] ?></p>
  <?php endif; ?>
</div>
<?php endif; ?>

<div class="grid-3">
  <div class="card">
    <div class="card-head"><h2><?= $t['referrers'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_referrers']) ?>" aria-label="<?= htmlspecialchars($t['tip_referrers']) ?>">i</button></div>
    <?php if (empty($stats['referrers'])): ?>
      <p class="no-data"><?= $t['no_referrers'] ?></p>
    <?php else:
      $maxR = max($stats['referrers']); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['referrers'] as $r => $c): $r = (string) $r; ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <a class="rank-label rank-link" href="<?= htmlspecialchars(dashUrl(['ref' => $r])) ?>" title="<?= htmlspecialchars($t['filter_by'] . ': ' . $r) ?>"><?= htmlspecialchars($r) ?></a>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxR*100) ?>%"></div></div>
          <span class="rank-count"><?= dashboardNumber($c, $lang) ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>

  <div class="card">
    <div class="card-head"><h2><?= $t['top_countries'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_countries']) ?>" aria-label="<?= htmlspecialchars($t['tip_countries']) ?>">i</button></div>
    <?php if (empty($stats['countries'])): ?>
      <p class="no-data"><?= $t['no_geo'] ?></p>
    <?php else:
      $maxC = max($stats['countries']); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['countries'] as $co => $c): $co = (string) $co; ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <a class="rank-label rank-link" href="<?= htmlspecialchars(dashUrl(['country' => $co])) ?>" title="<?= htmlspecialchars($t['filter_by'] . ': ' . countryName($co, $countryNames)) ?>"><?= countryFlag($co) ?> <?= htmlspecialchars(countryName($co, $countryNames)) ?></a>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxC*100) ?>%"></div></div>
          <span class="rank-count"><?= dashboardNumber($c, $lang) ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>

  <div class="card">
    <div class="card-head"><h2><?= $t['browser_lang'] ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2><button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_lang']) ?>" aria-label="<?= htmlspecialchars($t['tip_lang']) ?>">i</button></div>
    <?php if (empty($stats['languages'])): ?>
      <p class="no-data"><?= $t['no_lang'] ?></p>
    <?php else:
      $maxL = max($stats['languages']); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['languages'] as $l => $c): $l = (string) $l; ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <a class="rank-label rank-link" href="<?= htmlspecialchars(dashUrl(['lang' => $l])) ?>" title="<?= htmlspecialchars($t['filter_by'] . ': ' . langName($l, $langNames)) ?>"><?= htmlspecialchars(langName($l, $langNames)) ?></a>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxL*100) ?>%"></div></div>
          <span class="rank-count"><?= dashboardNumber($c, $lang) ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>
</div>

<details class="card recent">
  <summary class="card-head">
    <h2><?= sprintf($t['recent_sessions'], count($stats['recent'])) ?> <span class="card-window"><?= htmlspecialchars($rangeLabel) ?></span></h2>
    <span class="toggle"><span class="when-closed"><?= htmlspecialchars($t['show']) ?></span><span class="when-open"><?= htmlspecialchars($t['hide']) ?></span></span>
  </summary>
  <?php if (empty($stats['recent'])): ?>
    <p class="no-data"><?= $t['no_sessions'] ?></p>
  <?php else: ?>
  <ul class="session-list">
    <?php
      $todayStr     = date('Y-m-d');
      $yesterdayStr = date('Y-m-d', strtotime('-1 day'));
      foreach ($stats['recent'] as $s):
        $sTs  = strtotime($s['date']);
        $when = $s['date'] === $todayStr ? $t['today_short']
              : ($s['date'] === $yesterdayStr ? $t['yesterday_short']
              : date('j', $sTs) . ($lang === 'de' ? '. ' : ' ') . dashboardMonthShort($sTs, $lang));
        $pages  = $s['pages'];
        $hidden = 0;
        if ($s['views'] > 5) {
            $hidden = $s['views'] - 4;
            $pages  = array_merge(array_slice($pages, 0, 2), [null], $s['tail']);
        }
        $sDevice = in_array($s['device'], ['desktop', 'mobile', 'tablet'], true) ? $s['device'] : 'desktop';
    ?>
    <li>
      <div class="sess-meta">
        <span class="sess-time"><?= htmlspecialchars($when) ?> <?= sprintf('%02d:%02d', intdiv($s['first'], 3600), intdiv($s['first'] % 3600, 60)) ?></span>
        <span class="sess-icons" title="<?= htmlspecialchars($t['device_' . $sDevice] . ($s['country'] !== '' ? ' · ' . countryName($s['country'], $countryNames) : '')) ?>"><?= $deviceIcons[$sDevice] ?> <?= $s['country'] !== '' ? countryFlag($s['country']) : '' ?></span>
      </div>
      <div class="sess-path">
        <span class="sess-source"><?= htmlspecialchars($s['source'] !== '' ? $s['source'] : $t['ch_direct']) ?></span>
        <?php foreach ($pages as $pg): ?>
          <span class="sess-arrow" aria-hidden="true">→</span>
          <?php if ($pg === null): ?>
            <span class="sess-more"><?= sprintf($t['more_pages'], $hidden) ?></span>
          <?php else: ?>
            <span class="sess-page" title="<?= htmlspecialchars($pg) ?>"><?= htmlspecialchars($pg) ?></span>
          <?php endif; ?>
        <?php endforeach; ?>
      </div>
      <div class="sess-stats">
        <span><?= $s['views'] === 1 ? htmlspecialchars($t['depth_1']) : sprintf($t['pages_count'], $s['views']) ?></span>
        <span><?= $s['views'] > 1 ? formatDuration($s['last'] - $s['first']) : '—' ?></span>
      </div>
    </li>
    <?php endforeach; ?>
  </ul>
  <?php endif; ?>
  <?php if ($advancedMode): ?><p class="file-info">analytics.db · <?= $stats['db_size'] ?> KB · <?= dashboardNumber($stats['db_rows'], $lang) ?> <?= htmlspecialchars($t['rows']) ?></p><?php endif; ?>
</details>

<?php endif; // total > 0 ?>

<?php if ($advancedMode): ?>
<div class="danger-zone">
  <h2><?= $t['danger_title'] ?></h2>
  <p><?= $t['danger_desc'] ?></p>
  <div class="db-info">analytics.db · <?= $stats['db_size'] ?> KB · <?= dashboardNumber($stats['db_rows'], $lang) ?> <?= htmlspecialchars($t['rows']) ?></div>
  <button class="btn-danger" onclick="document.getElementById('confirm-clear').classList.toggle('visible')"><?= $t['clear_btn'] ?></button>
  <div class="confirm-box" id="confirm-clear">
    <p><?= sprintf($t['confirm_msg'], dashboardNumber($stats['db_rows'], $lang)) ?></p>
    <form method="POST">
      <input type="hidden" name="clear_data" value="1">
      <input type="hidden" name="confirm_clear" value="yes">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf'] ?? '') ?>">
      <button type="submit" class="btn-danger"><?= $t['confirm_btn'] ?></button>
    </form>
  </div>
</div>
<?php endif; ?>

<?php endif; // pwView ?>

</main>

<footer style="text-align:center;padding:1.5rem 1rem;font-size:.75rem;color:var(--muted);border-top:1px solid var(--border);margin-top:1rem;">
  pima Analytics <?= PIMA_VERSION ?> · <a href="https://ludescher.studio" target="_blank" rel="noopener noreferrer" style="color:var(--accent);text-decoration:none;">ludescher.studio</a>
</footer>

<?php endif; // authed ?>
<script>
(function() {
  var tip = document.createElement('div');
  tip.className = 'tooltip-float';
  document.body.appendChild(tip);

  function showTip(btn) {
    tip.textContent = btn.getAttribute('data-tip');
    tip.style.display = 'block';
    var r = btn.getBoundingClientRect();
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    var top = r.top - th - 8;
    var left = r.left + r.width / 2 - tw / 2;
    if (left < 8) left = 8;
    if (left + tw > window.innerWidth - 8) left = window.innerWidth - tw - 8;
    if (top < 8) top = r.bottom + 8;
    tip.style.top = top + 'px';
    tip.style.left = left + 'px';
  }

  function hideTip() { tip.style.display = 'none'; }

  document.querySelectorAll('.info-btn').forEach(function(btn) {
    btn.addEventListener('touchstart', function(e) {
      e.preventDefault();
      var wasActive = btn.classList.contains('active');
      document.querySelectorAll('.info-btn.active').forEach(function(b) { b.classList.remove('active'); });
      hideTip();
      if (!wasActive) { btn.classList.add('active'); showTip(btn); }
    }, { passive: false });
  });

  document.addEventListener('touchstart', function(e) {
    if (!e.target.classList.contains('info-btn')) {
      document.querySelectorAll('.info-btn.active').forEach(function(b) { b.classList.remove('active'); });
      hideTip();
    }
  });

  // ---- Theme toggle: remembers an explicit choice, otherwise follows the system ----
  var themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', function() {
      var root = document.documentElement;
      var current = root.getAttribute('data-theme')
        || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('pima-theme', next); } catch (e) {}
      if (window.pimaRenderChart) window.pimaRenderChart();
    });
  }

  // ---- Keep the selected range visible when the range bar scrolls ----
  var activeRange = document.querySelector('.range-bar [aria-current="page"]');
  if (activeRange) {
    var bar = activeRange.parentNode;
    bar.scrollLeft = activeRange.offsetLeft - bar.offsetLeft - (bar.clientWidth - activeRange.offsetWidth) / 2;
  }

  // ---- Active visitors: polled every minute while the tab is visible ----
  var badge = document.getElementById('live-badge');
  if (badge && window.fetch) {
    var liveTimer = setInterval(function() {
      if (document.hidden) return;
      fetch('?live=1', { credentials: 'same-origin', cache: 'no-store' })
        .then(function(r) {
          if (r.status === 401) { clearInterval(liveTimer); badge.classList.add('idle'); return null; }
          return r.json();
        })
        .then(function(data) {
          if (!data || typeof data.active !== 'number') return;
          document.getElementById('live-text').textContent = badge.getAttribute('data-label').replace('%d', data.active);
          badge.classList.toggle('idle', data.active === 0);
        })
        .catch(function() {});
    }, 60000);
  }

  // ---- Trend chart (inline SVG, no library) ----
  var box = document.getElementById('chart');
  var dataEl = document.getElementById('chart-data');
  if (!box || !dataEl) return;
  var data = JSON.parse(dataEl.textContent);
  var NS = 'http://www.w3.org/2000/svg';
  var locale = document.documentElement.lang === 'de' ? 'de-DE' : 'en-US';
  var fmt = function(v) { return new Intl.NumberFormat(locale).format(v); };

  function el(name, attrs, parent) {
    var node = document.createElementNS(NS, name);
    for (var k in attrs) node.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(node);
    return node;
  }

  function niceMax(v) {
    if (v <= 4) return 4;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var steps = [1, 2, 2.5, 5, 10];
    for (var i = 0; i < steps.length; i++) if (steps[i] * p >= v) return steps[i] * p;
    return 10 * p;
  }

  function render() {
    var metric = box.getAttribute('data-metric');
    var cur = data.cur[metric], prev = data.prev[metric];
    var hasPrev = prev.length > 0;
    var n = cur.length;
    var W = box.clientWidth, H = box.clientHeight;
    var padL = 34, padR = 10, padT = 10, padB = 24;
    var known = function(v) { return v !== null; };
    var max = niceMax(Math.max.apply(null, cur.filter(known).concat(prev, [0])));
    var first = 0, last = cur.length - 1;
    while (first < last && cur[first] === null) first++;
    while (last > first && cur[last] === null) last--;
    var x = function(i) { return padL + (n === 1 ? (W - padL - padR) / 2 : i * (W - padL - padR) / (n - 1)); };
    var y = function(v) { return padT + (1 - v / max) * (H - padT - padB); };

    box.innerHTML = '';
    var svg = el('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, 'aria-hidden': 'true' }, box);

    for (var g = 0; g <= 4; g++) {
      var gv = max * g / 4, gy = y(gv);
      el('line', { x1: padL, x2: W - padR, y1: gy, y2: gy, 'class': 'grid-line' }, svg);
      var lbl = el('text', { x: padL - 6, y: gy + 3, 'text-anchor': 'end', 'class': 'axis-label' }, svg);
      lbl.textContent = fmt(Math.round(gv * 10) / 10);
    }

    var step = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - padL - padR) / 64))));
    for (var t = 0; t < n; t += step) {
      var anchor = x(t) > W - padR - 24 ? 'end' : 'middle';
      var tx = el('text', { x: x(t), y: H - 6, 'text-anchor': anchor, 'class': 'axis-label' }, svg);
      tx.textContent = data.labels[t].tick;
    }

    var path = function(series) {
      var from = series === cur ? first : 0, to = series === cur ? last : series.length - 1, d = [];
      for (var i = from; i <= to; i++) d.push((i === from ? 'M' : 'L') + x(i).toFixed(1) + ' ' + y(series[i]).toFixed(1));
      return d.join(' ');
    };
    el('path', { d: path(prev), 'class': 'line-prev' }, svg);
    el('path', { d: path(cur) + ' L' + x(last).toFixed(1) + ' ' + y(0) + ' L' + x(first).toFixed(1) + ' ' + y(0) + ' Z', 'class': 'area-cur' }, svg);
    el('path', { d: path(cur), 'class': 'line-cur' }, svg);

    var cursor = el('line', { y1: padT, y2: H - padB, 'class': 'cursor', visibility: 'hidden' }, svg);
    var dotPrev = el('circle', { r: 3.5, 'class': 'dot-prev', visibility: 'hidden' }, svg);
    var dotCur = el('circle', { r: 4.5, 'class': 'dot-cur', visibility: 'hidden' }, svg);
    var tipBox = document.createElement('div');
    tipBox.className = 'chart-tip';
    box.appendChild(tipBox);

    function show(clientX) {
      var r = box.getBoundingClientRect();
      var px = clientX - r.left;
      var i = n === 1 ? 0 : Math.round((px - padL) / ((W - padL - padR) / (n - 1)));
      i = Math.max(0, Math.min(n - 1, i));
      var cx = x(i);
      cursor.setAttribute('x1', cx); cursor.setAttribute('x2', cx);
      dotCur.setAttribute('cx', cx); dotCur.setAttribute('cy', y(cur[i] === null ? 0 : cur[i]));
      dotPrev.setAttribute('cx', cx); dotPrev.setAttribute('cy', y(prev[i]));
      [cursor, dotCur, dotPrev].forEach(function(node) { node.setAttribute('visibility', 'visible'); });
      if (!hasPrev) dotPrev.setAttribute('visibility', 'hidden');
      if (cur[i] === null) dotCur.setAttribute('visibility', 'hidden');
      tipBox.textContent = '';
      var head = document.createElement('div');
      head.innerHTML = '<b></b>';
      head.firstChild.textContent = data.labels[i].tip + ': ' + (cur[i] === null ? '—' : fmt(cur[i]) + ' ' + data.names[metric]);
      var sub = document.createElement('div');
      sub.className = 'muted-line';
      sub.textContent = data.prevName + ' (' + data.labels[i].prevTip + '): ' + fmt(prev[i]);
      tipBox.appendChild(head);
      if (hasPrev) tipBox.appendChild(sub);
      tipBox.style.display = 'block';
      var left = cx + 12;
      if (left + tipBox.offsetWidth > W) left = cx - tipBox.offsetWidth - 12;
      tipBox.style.left = Math.max(0, left) + 'px';
    }
    function hide() {
      tipBox.style.display = 'none';
      [cursor, dotCur, dotPrev].forEach(function(node) { node.setAttribute('visibility', 'hidden'); });
    }
    svg.addEventListener('mousemove', function(e) { show(e.clientX); });
    svg.addEventListener('mouseleave', hide);
    svg.addEventListener('touchstart', function(e) { show(e.touches[0].clientX); }, { passive: true });
    svg.addEventListener('touchmove', function(e) { show(e.touches[0].clientX); }, { passive: true });
  }

  document.querySelectorAll('.seg button').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.seg button').forEach(function(b) { b.setAttribute('aria-pressed', b === btn ? 'true' : 'false'); });
      box.setAttribute('data-metric', btn.getAttribute('data-metric'));
      render();
    });
  });

  var resizeTimer;
  window.addEventListener('resize', function() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(render, 120);
  });
  window.pimaRenderChart = render;
  render();
})();
</script>
</body>
</html>
