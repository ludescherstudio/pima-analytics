<?php
// ============================================================
// pima — pima.php
// ============================================================

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
session_start();

// Expire idle sessions and sessions created with an older dashboard password.
$sessionIdle = defined('SESSION_IDLE_SECONDS') ? max(60, (int) SESSION_IDLE_SECONDS) : 1800;
$authKey     = hash('sha256', (string) STATS_PASSWORD);
if (!empty($_SESSION['pima_auth'])) {
    $expired = empty($_SESSION['pima_last_activity'])
        || (int) $_SESSION['pima_last_activity'] < time() - $sessionIdle;
    $passwordChanged = !isset($_SESSION['pima_auth_key'])
        || !hash_equals($authKey, (string) $_SESSION['pima_auth_key']);
    if ($expired || $passwordChanged) {
        unset($_SESSION['pima_auth'], $_SESSION['pima_auth_key'], $_SESSION['pima_last_activity']);
    } else {
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

// ---- Auth ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if (!$csrfOk) {
        // Invalid cross-site posts do not consume another person's IP quota.
        $authError = true;
        sleep(1);
    } else {
        $fh = @fopen($lockFile, 'c+');
        if (!$fh || !@flock($fh, LOCK_EX)) {
            if ($fh) fclose($fh);
            $authUnavailable = true;
        } else {
            $decoded = json_decode((string) stream_get_contents($fh), true);
            $attempts = is_array($decoded) ? (int) ($decoded['attempts'] ?? 0) : 0;
            $lockedUntil = is_array($decoded) ? (int) ($decoded['locked_until'] ?? 0) : 0;
            if ($lockedUntil > 0 && $lockedUntil <= time()) {
                $attempts = 0;
                $lockedUntil = 0;
            }

            if (time() < $lockedUntil) {
                $isLocked = true;
            } else {
                $pw     = is_scalar($_POST['password']) ? (string) $_POST['password'] : '';
                $stored = (string) STATS_PASSWORD;
                $pwOk   = (strlen($stored) > 3 && $stored[0] === '$')
                    ? password_verify($pw, $stored)
                    : hash_equals($stored, $pw);
                if ($pwOk) {
                    $attempts = 0;
                    $lockedUntil = 0;
                    session_regenerate_id(true);
                    $_SESSION['pima_auth']          = true;
                    $_SESSION['pima_auth_key']      = $authKey;
                    $_SESSION['pima_last_activity'] = time();
                    $_SESSION['csrf']               = bin2hex(random_bytes(16));
                    $csrf = $_SESSION['csrf'];
                } else {
                    $attempts++;
                    if ($attempts >= $maxAttempts) $lockedUntil = time() + $lockoutSecs;
                    $isLocked = time() < $lockedUntil;
                    $authError = true;
                }
            }

            $json = (string) json_encode(['attempts' => $attempts, 'locked_until' => $lockedUntil]);
            rewind($fh);
            ftruncate($fh, 0);
            if (fwrite($fh, $json) !== strlen($json)) $authUnavailable = true;
            fflush($fh);
            flock($fh, LOCK_UN);
            fclose($fh);
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
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
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
        'dashboard'        => 'Analytics Dashboard',
        'tagline'          => 'measure more. manage less.',
        'login_btn'        => 'Login',
        'wrong_password'   => '✗ Wrong password',
        'auth_unavailable' => 'Login protection is temporarily unavailable. Check that pima-cache is writable.',
        'attempts_left'    => '%d attempt%s remaining before lockout.',
        'locked_out'       => 'Too many failed attempts. Try again in %s.',
        'summary'                => 'Your site had <strong>%s pageviews</strong> in the last 30 days.',
        'summary_avg_full'        => 'An average of <strong>%s views</strong> per calendar day in this period.',
        'summary_avg_partial'     => 'An average of <strong>%s views</strong> per calendar day since tracking began (%d day%s).',
        'total_views'      => 'Total Views',
        'all_time'         => 'all time',
        'today'            => 'Today',
        'visitors'         => 'visitors',
        'tip_daily_visitors' => 'Estimated visitors today. Multiple pageviews with the same daily anonymous identifier count once.',
        'win_7'            => 'Last 7 Days',
        'win_30'           => 'Last 30 Days',
        'vs_prev_7'        => 'vs previous 7 days',
        'vs_prev_30'       => 'vs previous 30 days',
        'visitor_days'     => 'visitor-days',
        'tip_visitor_days' => 'Counted per day: someone who visits on three different days counts three times. The visitor hash is re-salted every night, so nobody is recognised across days — which is exactly why this is not a headcount.',
        'trend'            => '-Day Trend',
        'top_pages'        => 'Top Pages',
        'win_30_label'     => 'last 30 days',
        'change_label'     => 'Last 30 days · absolute change in pageviews vs. previous 30 days',
        'referrers'        => 'Referrers',
        'entry_pages'      => 'Entry Pages',
        'browser_lang'     => 'Browser Language',
        'time_of_day'      => 'Time of Day',
        'peak'             => 'Peak',
        'views'            => 'views',
        'device_type'      => 'Device Type',
        'top_countries'    => 'Top Countries',
        'channels'         => 'Traffic Channels',
        'ch_direct'        => 'Direct',
        'ch_organic'       => 'Organic Search',
        'ch_social'        => 'Social',
        'ch_referral'      => 'Referral',
        'tip_channels'     => 'Share of entries in the last 30 days: direct, search, social media, or another website. Internal navigation is excluded.',
        'recent_hits'      => 'Recent %d Hits',
        'th_date'          => 'Date',
        'th_time'          => 'Time',
        'th_page'          => 'Page',
        'th_referrer'      => 'Referrer',
        'th_device'        => 'Device',
        'th_country'       => 'Country',
        'show'             => 'Show ↓',
        'hide'             => 'Hide ↑',
        'no_data'          => 'No data yet — add the tracking snippet to your site to get started.',
        'no_pages'         => 'No data yet',
        'no_referrers'     => 'No referrers yet',
        'no_external'      => 'No external traffic yet',
        'no_channels'      => 'No classified entries yet',
        'no_lang'          => 'No data yet',
        'no_geo'           => 'Geo disabled or no data',
        'entry_note'       => 'External entries in the last 30 days; reloads can count again',
        'visitor_days_note'=> 'Visitor-days in the last 30 days; one visitor can count once per day.',
        'known_values_note'=> 'Visitor-days with a detected value; unknown values are excluded.',
        'device_desktop'   => 'Desktop',
        'device_mobile'    => 'Mobile',
        'device_tablet'    => 'Tablet',
        'refresh'          => 'Refresh',
        'logout'           => 'Logout',
        'back_to_site'     => '← Back to site',
        'export'           => '↓ Export CSV',
        'cleared'          => 'All data cleared successfully.',
        'danger_title'     => '⚠ Danger Zone',
        'danger_desc'      => 'These actions are irreversible. Only visible because ADVANCED_MODE is enabled in pima-core.php.',
        'clear_btn'        => 'Clear all data',
        'confirm_msg'      => 'This will permanently delete all %s rows. Are you sure?',
        'confirm_btn'      => 'Yes, delete everything',
        'powered_by'       => 'Powered by',
        'tip_trend'        => 'Daily pageviews and estimated daily visitors over the last %d days.',
        'tip_pages'        => 'Most visited pages in the last 30 days, with change vs. the previous 30 days.',
        'tip_referrers'    => 'External websites that generated entries in the last 30 days. Counts are entries, not people.',
        'tip_entry'        => 'Pages opened with an external referrer in the last 30 days. Direct entries are not included.',
        'tip_lang'         => 'Browser language by visitor-day in the last 30 days. Unknown values are excluded.',
        'tip_tod'          => 'Pageviews by local server hour over the last 30 days. Hover over a bar for the exact count.',
        'tip_device'       => 'Device distribution by visitor-day over the last 30 days.',
        'tip_countries'    => 'Detected country by visitor-day over the last 30 days. Unknown values are excluded.',
        'warn_default_pw'  => '⚠ Default password in use — change it in pima-core.php immediately.',
    ],
    'de' => [
        'dashboard'        => 'Analyse-Dashboard',
        'tagline'          => 'mehr messen. weniger verwalten.',
        'login_btn'        => 'Anmelden',
        'wrong_password'   => '✗ Falsches Passwort',
        'auth_unavailable' => 'Der Anmeldeschutz ist vorübergehend nicht verfügbar. Prüfe die Schreibrechte von pima-cache.',
        'attempts_left'    => 'Noch %d Versuch%s bis zur Sperre.',
        'locked_out'       => 'Zu viele Fehlversuche. Bitte in %s erneut versuchen.',
        'summary'                => 'Deine Website hatte in den letzten 30 Tagen <strong>%s Seitenaufrufe</strong>.',
        'summary_avg_full'        => 'Im Schnitt <strong>%s Aufrufe</strong> pro Kalendertag in diesem Zeitraum.',
        'summary_avg_partial'     => 'Im Schnitt <strong>%s Aufrufe</strong> pro Kalendertag seit Aufzeichnungsbeginn (%d Kalendertag%s).',
        'total_views'      => 'Seitenaufrufe',
        'all_time'         => 'gesamt',
        'today'            => 'Heute',
        'visitors'         => 'Besucher',
        'tip_daily_visitors' => 'Geschätzte Besucher heute. Mehrere Aufrufe mit derselben täglichen anonymen Kennung zählen einmal.',
        'win_7'            => 'Letzte 7 Tage',
        'win_30'           => 'Letzte 30 Tage',
        'vs_prev_7'        => 'vs. vorherige 7 Tage',
        'vs_prev_30'       => 'vs. vorherige 30 Tage',
        'visitor_days'     => 'Besuchertage',
        'tip_visitor_days' => 'Pro Tag gezählt: Wer an drei verschiedenen Tagen kommt, zählt dreifach. Der Besucher-Hash wird jede Nacht neu gesalzen, niemand wird über Tage hinweg wiedererkannt — genau deshalb ist das keine Personenzahl.',
        'trend'            => '-Tage-Verlauf',
        'top_pages'        => 'Meistbesuchte Seiten',
        'win_30_label'     => 'letzte 30 Tage',
        'change_label'     => 'Letzte 30 Tage · absolute Änderung der Aufrufe vs. vorherige 30 Tage',
        'referrers'        => 'Quellen',
        'entry_pages'      => 'Einstiegsseiten',
        'browser_lang'     => 'Browsersprache',
        'time_of_day'      => 'Tageszeit',
        'peak'             => 'Spitzenzeit',
        'views'            => 'Aufrufe',
        'device_type'      => 'Gerätetyp',
        'top_countries'    => 'Länder',
        'channels'         => 'Traffic-Quellen',
        'ch_direct'        => 'Direkt',
        'ch_organic'       => 'Organische Suche',
        'ch_social'        => 'Social Media',
        'ch_referral'      => 'Verweise',
        'tip_channels'     => 'Anteil der Einstiege der letzten 30 Tage: direkt, Suche, Social Media oder andere Websites. Interne Navigation ist ausgeschlossen.',
        'recent_hits'      => 'Letzte %d Aufrufe',
        'th_date'          => 'Datum',
        'th_time'          => 'Uhrzeit',
        'th_page'          => 'Seite',
        'th_referrer'      => 'Quelle',
        'th_device'        => 'Gerät',
        'th_country'       => 'Land',
        'show'             => 'Anzeigen ↓',
        'hide'             => 'Ausblenden ↑',
        'no_data'          => 'Noch keine Daten — füge das Tracking-Snippet auf deiner Website ein.',
        'no_pages'         => 'Noch keine Daten',
        'no_referrers'     => 'Noch keine Quellen',
        'no_external'      => 'Noch kein externer Traffic',
        'no_channels'      => 'Noch keine klassifizierten Einstiege',
        'no_lang'          => 'Noch keine Daten',
        'no_geo'           => 'Geo deaktiviert oder keine Daten',
        'entry_note'       => 'Externe Einstiege der letzten 30 Tage; Neuladen kann erneut zählen',
        'visitor_days_note'=> 'Besuchertage der letzten 30 Tage; ein Besucher kann pro Tag einmal zählen.',
        'known_values_note'=> 'Besuchertage mit erkanntem Wert; unbekannte Werte sind ausgeschlossen.',
        'device_desktop'   => 'Desktop',
        'device_mobile'    => 'Mobil',
        'device_tablet'    => 'Tablet',
        'refresh'          => 'Aktualisieren',
        'logout'           => 'Abmelden',
        'back_to_site'     => '← Zurück zur Website',
        'export'           => '↓ CSV exportieren',
        'cleared'          => 'Alle Daten wurden erfolgreich gelöscht.',
        'danger_title'     => '⚠ Gefahrenzone',
        'danger_desc'      => 'Diese Aktionen sind unwiderruflich. Nur sichtbar weil ADVANCED_MODE in pima-core.php aktiviert ist.',
        'clear_btn'        => 'Alle Daten löschen',
        'confirm_msg'      => 'Dadurch werden alle %s Einträge dauerhaft gelöscht. Bist du sicher?',
        'confirm_btn'      => 'Ja, alles löschen',
        'powered_by'       => 'Erstellt mit',
        'tip_trend'        => 'Tägliche Seitenaufrufe und geschätzte tägliche Besucher der letzten %d Tage.',
        'tip_pages'        => 'Meistbesuchte Seiten der letzten 30 Tage, mit Änderung vs. vorherige 30 Tage.',
        'tip_referrers'    => 'Externe Websites, die in den letzten 30 Tagen Einstiege erzeugt haben. Gezählt werden Einstiege, nicht Personen.',
        'tip_entry'        => 'Seiten, die in den letzten 30 Tagen mit externem Referrer geöffnet wurden. Direkte Einstiege sind nicht enthalten.',
        'tip_lang'         => 'Browsersprache nach Besuchertagen der letzten 30 Tage. Unbekannte Werte sind ausgeschlossen.',
        'tip_tod'          => 'Seitenaufrufe nach lokaler Server-Uhrzeit in den letzten 30 Tagen. Der Balken zeigt die genaue Anzahl.',
        'tip_device'       => 'Geräteverteilung nach Besuchertagen der letzten 30 Tage.',
        'tip_countries'    => 'Erkanntes Herkunftsland nach Besuchertagen der letzten 30 Tage. Unbekannte Werte sind ausgeschlossen.',
        'warn_default_pw'  => '⚠ Standard-Passwort aktiv — bitte in pima-core.php sofort ändern.',
    ],
];
$lang = defined('LANG') ? LANG : 'en';
$t = $strings[$lang] ?? $strings['en'];

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

// ---- Data ----
$stats = [
    'total'       => 0,
    'today'       => 0,
    'uniq_today'  => 0,
    'uniq_7'        => 0,
    'uniq_30'       => 0,
    'views_7'       => 0,
    'views_7_prev'  => 0,
    'views_30'      => 0,
    'views_30_prev' => 0,
    'window_days'   => 1,
    'pages'       => [],
    'pages_prev'  => [],
    'referrers'   => [],
    'devices'     => ['desktop' => 0, 'mobile' => 0, 'tablet' => 0],
    'countries'   => [],
    'trend'       => [],
    'hours'       => array_fill(0, 24, ['views' => 0, 'uniq' => 0]),
    'languages'   => [],
    'entry_pages' => [],
    'channels'    => ['direct' => 0, 'organic' => 0, 'social' => 0, 'referral' => 0],
    'recent'      => [],
    'db_size'     => 0,
    'db_rows'     => 0,
];

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

        $today      = date('Y-m-d');
        $trendFrom  = date('Y-m-d', strtotime('-' . (TREND_DAYS - 1) . ' days'));

        // Rolling windows, each including today.
        $win7From   = date('Y-m-d', strtotime('-6 days'));
        $prev7To    = date('Y-m-d', strtotime('-7 days'));
        $prev7From  = date('Y-m-d', strtotime('-13 days'));
        $win30From  = date('Y-m-d', strtotime('-29 days'));
        $prev30To   = date('Y-m-d', strtotime('-30 days'));
        $prev30From = date('Y-m-d', strtotime('-59 days'));

        $stats['total']      = (int) $db->querySingle('SELECT COUNT(*) FROM hits');
        $stats['today']      = (int) $db->querySingle("SELECT COUNT(*) FROM hits WHERE date = '$today'");
        // The visitor-hash salt rotates nightly: vids are comparable within a
        // single day only, so there is no all-time unique count.
        $stats['uniq_today'] = (int) $db->querySingle("SELECT COUNT(DISTINCT vid) FROM hits WHERE date = '$today' AND vid != ''");
        // Visitor-days, not people.
        $stats['uniq_7']        = (int) $db->querySingle("SELECT COUNT(DISTINCT vid) FROM hits WHERE date >= '$win7From' AND vid != ''");
        $stats['uniq_30']       = (int) $db->querySingle("SELECT COUNT(DISTINCT vid) FROM hits WHERE date >= '$win30From' AND vid != ''");
        $stats['views_7']       = (int) $db->querySingle("SELECT COUNT(*) FROM hits WHERE date >= '$win7From'");
        $stats['views_7_prev']  = (int) $db->querySingle("SELECT COUNT(*) FROM hits WHERE date >= '$prev7From' AND date <= '$prev7To'");
        $stats['views_30']      = (int) $db->querySingle("SELECT COUNT(*) FROM hits WHERE date >= '$win30From'");
        $stats['views_30_prev'] = (int) $db->querySingle("SELECT COUNT(*) FROM hits WHERE date >= '$prev30From' AND date <= '$prev30To'");

        // Days the 30-day window actually covers.
        $firstDate = (string) $db->querySingle("SELECT MIN(date) FROM hits");
        $coveredDays = 1;
        if ($firstDate) {
            $firstDay = DateTimeImmutable::createFromFormat('!Y-m-d', $firstDate);
            $todayDay = DateTimeImmutable::createFromFormat('!Y-m-d', $today);
            if ($firstDay && $todayDay) {
                // Calendar-date difference stays correct across DST changes.
                $coveredDays = (int) $firstDay->diff($todayDay)->format('%r%a') + 1;
            }
        }
        $stats['window_days'] = max(1, min(30, $coveredDays));

        // Top pages — subquery takes the most recent non-empty title.
        $res = $db->query("
            SELECT h.page,
                   COUNT(*) AS c,
                   (SELECT h2.title FROM hits h2
                    WHERE h2.page = h.page
                      AND h2.title IS NOT NULL AND h2.title != ''
                      AND h2.date >= '$win30From'
                    ORDER BY h2.id DESC LIMIT 1) AS title
            FROM hits h
            WHERE h.date >= '$win30From'
            GROUP BY h.page
            ORDER BY c DESC
            LIMIT 8
        ");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stats['pages'][$row['page']] = ['c' => $row['c'], 'title' => $row['title'] ?? ''];
        }

        // Previous-window counts for exactly the pages listed above.
        if ($stats['pages']) {
            $names = array_keys($stats['pages']);
            $holes = implode(',', array_fill(0, count($names), '?'));
            $stmt  = $db->prepare(
                "SELECT page, COUNT(*) AS c FROM hits
                 WHERE date >= ? AND date <= ? AND page IN ($holes)
                 GROUP BY page"
            );
            if ($stmt) {
                $stmt->bindValue(1, $prev30From);
                $stmt->bindValue(2, $prev30To);
                foreach ($names as $i => $n) $stmt->bindValue($i + 3, $n);
                $res = $stmt->execute();
                while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                    $stats['pages_prev'][$row['page']] = $row['c'];
                }
            }
        }

        // Roll up to the host first, rank and cap afterwards.
        $res = $db->query("SELECT referrer, COUNT(*) as c FROM hits WHERE $entryWhere AND referrer != '' AND date >= '$win30From' GROUP BY referrer");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $ref = preg_replace('/^www\./', '', parse_url($row['referrer'], PHP_URL_HOST) ?: $row['referrer']);
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
        $resC = $db->query("SELECT referrer, COUNT(*) as c FROM hits WHERE $entryWhere AND date >= '$win30From' GROUP BY referrer");
        while ($rowC = $resC->fetchArray(SQLITE3_ASSOC)) {
            $ref = strtolower($rowC['referrer'] ?? '');
            $c   = $rowC['c'];
            if (empty($ref)) {
                $stats['channels']['direct'] += $c;
            } else {
                $host = parse_url($ref, PHP_URL_HOST) ?: $ref;
                $host = preg_replace('/^www\./', '', $host);
                if      ($isSearchEngine($host))              $stats['channels']['organic']  += $c;
                elseif  ($hostMatches($host, $socialNets))    $stats['channels']['social']   += $c;
                else                                          $stats['channels']['referral'] += $c;
            }
        }

        // Devices
        $res = $db->query("SELECT device, COUNT(DISTINCT vid) as c FROM hits WHERE vid != '' AND date >= '$win30From' GROUP BY device");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $dev = $row['device'] ?: 'desktop';
            $stats['devices'][$dev] = ($stats['devices'][$dev] ?? 0) + $row['c'];
        }

        // Countries
        $res = $db->query("SELECT country, COUNT(DISTINCT vid) as c FROM hits WHERE vid != '' AND country != '' AND date >= '$win30From' GROUP BY country ORDER BY c DESC LIMIT 8");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stats['countries'][$row['country']] = $row['c'];
        }

        // Trend
        for ($i = TREND_DAYS - 1; $i >= 0; $i--) {
            $d = date('Y-m-d', strtotime("-{$i} days"));
            $stats['trend'][$d] = ['views' => 0, 'uniq' => 0];
        }
        $res = $db->query("SELECT date, COUNT(*) as views, COUNT(DISTINCT vid) as uniq FROM hits WHERE date >= '$trendFrom' GROUP BY date");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            if (isset($stats['trend'][$row['date']])) {
                $stats['trend'][$row['date']] = ['views' => $row['views'], 'uniq' => $row['uniq']];
            }
        }

        // Hours
        $res = $db->query("SELECT CAST(substr(time,1,2) AS INTEGER) as h, COUNT(*) as views, COUNT(DISTINCT vid) as uniq FROM hits WHERE date >= '$win30From' GROUP BY h");
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $h = (int) $row['h'];
            if ($h >= 0 && $h < 24) {
                $stats['hours'][$h] = ['views' => $row['views'], 'uniq' => $row['uniq']];
            }
        }

        // Browser languages
        $res = $db->query("SELECT lang, COUNT(DISTINCT vid) as c FROM hits WHERE vid != '' AND lang IS NOT NULL AND lang != '' AND date >= '$win30From' GROUP BY lang ORDER BY c DESC LIMIT 8");
        if ($res) {
            while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                $stats['languages'][$row['lang']] = $row['c'];
            }
        }

        // Entry pages reached from an external referrer.
        $res = $db->query("
            SELECT h.page,
                   COUNT(*) AS c,
                   (SELECT h2.title FROM hits h2
                    WHERE h2.page = h.page
                      AND h2.title IS NOT NULL AND h2.title != ''
                      AND h2.date >= '$win30From'
                    ORDER BY h2.id DESC LIMIT 1) AS title
            FROM hits h
            WHERE $entryWhereH
              AND h.referrer != ''
              AND h.date >= '$win30From'
            GROUP BY h.page
            ORDER BY c DESC
            LIMIT 8
        ");
        if ($res) {
            while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
                $stats['entry_pages'][$row['page']] = ['c' => $row['c'], 'title' => $row['title'] ?? ''];
            }
        }

        // Recent hits
        $res = $db->query("SELECT date,time,page,referrer,device,country FROM hits ORDER BY id DESC LIMIT " . RECENT_ENTRIES);
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stats['recent'][] = $row;
        }

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
    'VN'=>'Vietnam','local'=>'Lokal',
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
    'VN'=>'Vietnam','local'=>'Local',
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
    return date('d.', $timestamp) . ' ' . $months[(int) date('n', $timestamp)] . ' ' . date('Y', $timestamp);
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

$trendMax = 1;
foreach ($stats['trend'] as $trendItem) $trendMax = max($trendMax, $trendItem['views']);
$hourMax  = max(array_merge([1], array_column($stats['hours'], 'views')));

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
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --accent:  <?= htmlspecialchars($brandColor) ?>;
    --bg:      #f5f7fa;
    --surface: #ffffff;
    --border:  #e2e6ed;
    --text:    #1a202c;
    --muted:   #718096;
    --danger:  #c0392b;
    --font:    <?= htmlspecialchars($brandFont) ?>;
    --sans:    system-ui, -apple-system, sans-serif;
  }
  body { font-family: var(--sans); background: var(--bg); color: var(--text); min-height: 100vh; }

  @keyframes login-up { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }

  .login-wrap { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:1.5rem; background:radial-gradient(ellipse at 30% 40%, <?= htmlspecialchars($brandColor) ?>0f, transparent 60%), var(--bg); }
  .login-box { width:100%; max-width:340px; animation:login-up .45s ease-out; background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:2rem; box-shadow:0 4px 24px rgba(26,32,44,.06); }
  .login-logo { margin-bottom:1.5rem; }
  .login-logo img { max-height:36px; max-width:160px; }
  .login-box .sub { font-size:.8rem; color:var(--muted); margin:.25rem 0 2rem; text-transform:none; letter-spacing:0; }
  .login-error { padding:.6rem .85rem; background:#f871710f; border:1px solid #f8717118; border-radius:7px; color:#f87171; font-size:.84rem; margin-bottom:1rem; }
  .login-locked { padding:.6rem .85rem; background:#f871710f; border:1px solid #f8717118; border-radius:7px; color:#f87171; font-size:.84rem; margin-bottom:1rem; }
  .login-box input[type=password] { width:100%; padding:.8rem 1rem; background:var(--surface); border:1px solid var(--border); border-radius:10px; color:var(--text); font-family:inherit; font-size:.93rem; outline:0; transition:border-color .2s, box-shadow .2s; }
  .login-box input[type=password]:focus { border-color:var(--accent); box-shadow:0 0 0 3px <?= htmlspecialchars($brandColor) ?>22; }
  .login-box input[type=password]::placeholder { color:var(--muted); }
  .login-box input:disabled, .login-box button:disabled { opacity:.4; cursor:not-allowed; }
  .login-box button { width:100%; padding:.8rem; margin-top:.75rem; background:var(--accent); color:#fff; border:0; border-radius:10px; font-family:inherit; font-size:.93rem; font-weight:600; cursor:pointer; transition:opacity .15s, transform .1s; }
  .login-box button:hover:not(:disabled) { opacity:.88; }
  .login-box button:active:not(:disabled) { transform:scale(.98); }
  .attempts-hint { font-size:.72rem; color:var(--muted); margin-top:.4rem; }

  header { background:#333333; border-bottom:1px solid #444444; padding:1rem 1.5rem; display:flex; align-items:center; justify-content:space-between; gap:1rem; flex-wrap:wrap; }
  .header-pima { display:flex; flex-direction:column; justify-content:center; }
  .header-pima-name { font-size:1rem; font-weight:700; color:#fff; letter-spacing:.02em; }
  .header-tagline { font-size:.65rem; color:#aaaaaa; letter-spacing:.04em; margin-top:.1rem; }
  .header-actions { display:flex; align-items:center; gap:.75rem; flex-wrap:wrap; }
  .header-actions form { display:inline; margin:0; }
  .btn-ghost { background:none; border:1px solid #555555; border-radius:8px; padding:.3rem .75rem; font-family:inherit; font-size:.78rem; color:#aaaaaa; cursor:pointer; transition:all .15s; text-decoration:none; display:inline-block; }
  .btn-ghost:hover { border-color:#fff; color:#fff; }
  .btn-export { background:var(--accent); color:#fff; border:none; border-radius:8px; padding:.3rem .75rem; font-size:.78rem; cursor:pointer; text-decoration:none; display:inline-block; transition:opacity .15s; }
  .btn-export:hover { opacity:.85; }

  .summary { padding:1.75rem 0 .5rem; }
  .summary-sentence { font-size:1.1rem; color:var(--text); line-height:1.6; }
  .summary-sentence strong { color:var(--accent); }
  .summary-date { font-size:.78rem; color:var(--muted); margin-top:.25rem; }

  main { max-width:1160px; margin:0 auto; padding:2rem 1.5rem; }

  .kpi-row { display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:14px; margin-bottom:1.5rem; }
  .kpi { background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1.25rem 1.25rem 1rem; }
  .kpi.highlight { border-left:3px solid var(--accent); }
  .kpi-label { font-size:.65rem; text-transform:uppercase; letter-spacing:.12em; color:var(--accent); margin-bottom:.5rem; }
  .kpi-value { font-family:var(--font); font-size:1.9rem; font-weight:700; line-height:1; }
  .kpi-sub { font-size:.72rem; color:var(--muted); margin-top:.3rem; }
  .kpi-delta { font-size:.72rem; margin-top:.3rem; font-weight:500; }
  .kpi-delta.up   { color:#2d6a4f; }
  .kpi-delta.down { color:#c0392b; }
  .kpi-delta.same { color:var(--muted); }

  /* Delta pills */
  .pill { display:inline-flex; align-items:center; gap:.25rem; padding:.2rem .55rem; border-radius:20px; font-size:.72rem; font-weight:600; margin-top:.4rem; }
  .pill.up   { background:#e8f5e9; color:#2d6a4f; }
  .pill.down { background:#fdecea; color:#c0392b; }
  .pill.same { background:var(--bg); color:var(--muted); }
  .pill svg  { width:10px; height:10px; flex-shrink:0; }

  /* Rank delta pills */
  .delta-pill { display:inline-flex; align-items:center; gap:.2rem; padding:.15rem .45rem; border-radius:20px; font-size:.65rem; font-weight:600; flex-shrink:0; }
  .delta-pill.up   { background:#e8f5e9; color:#2d6a4f; }
  .delta-pill.down { background:#fdecea; color:#c0392b; }
  .delta-pill.same { background:var(--bg); color:var(--muted); }

  .card { background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:1.5rem; margin-bottom:14px; }
  .card h2 { font-family:var(--font); font-size:.95rem; font-weight:700; margin-bottom:1rem; padding-bottom:.75rem; border-bottom:1px solid var(--border); }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:14px; }
  .grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; margin-bottom:14px; }
  .grid-2 > .card, .grid-3 > .card { min-width:0; }
  @media (max-width:900px) { .grid-3 { grid-template-columns:1fr 1fr; } }
  @media (max-width:640px) { .grid-2, .grid-3 { grid-template-columns:1fr; } }

  .trend-chart { display:flex; align-items:flex-end; gap:3px; height:80px; }
  .bar-col { flex:1; display:flex; flex-direction:column; align-items:center; height:100%; justify-content:flex-end; gap:3px; cursor:default; }
  .bar-views { width:100%; background:var(--accent); border-radius:3px 3px 0 0; min-height:2px; opacity:.75; transition:opacity .15s; }
  .bar-col:hover .bar-views { opacity:1; }
  .bar-col .lbl { font-size:.52rem; color:var(--muted); text-align:center; }

  .hours-chart { display:flex; align-items:flex-end; gap:2px; height:60px; }
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
  .rank-track { width:60px; height:5px; background:var(--bg); border-radius:3px; overflow:hidden; flex-shrink:0; }
  .rank-fill { height:100%; background:var(--accent); opacity:.6; border-radius:3px; }
  .rank-count { font-size:.8rem; font-weight:600; width:2.2rem; text-align:right; flex-shrink:0; }

  .dev-row { display:flex; align-items:center; gap:.75rem; padding:.4rem 0; }
  .dev-label { font-size:.8rem; width:4.5rem; flex-shrink:0; }
  .dev-track { flex:1; height:7px; background:var(--bg); border-radius:4px; overflow:hidden; }
  .dev-fill { height:100%; background:var(--accent); border-radius:4px; }
  .dev-fill.mobile { opacity:.7; }
  .dev-fill.tablet { opacity:.45; }
  .dev-pct { font-size:.75rem; color:var(--muted); width:2.5rem; text-align:right; flex-shrink:0; }

  .tbl-wrap { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:.8rem; }
  thead th { text-align:left; padding:.5rem .75rem; font-size:.65rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); border-bottom:2px solid var(--border); background:var(--bg); white-space:nowrap; }
  tbody tr:hover { background:var(--bg); }
  tbody td { padding:.42rem .75rem; border-bottom:1px solid var(--border); max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  tbody tr:last-child td { border-bottom:none; }
  .muted { color:var(--muted); }
  .badge { display:inline-block; padding:.15rem .5rem; border-radius:20px; font-size:.65rem; text-transform:uppercase; letter-spacing:.05em; }
  .badge-desktop { background:rgba(13,148,136,.1); color:var(--accent); }
  .badge-mobile  { background:rgba(13,148,136,.07); color:var(--accent); }
  .badge-tablet  { background:rgba(13,148,136,.05); color:var(--accent); }

  .danger-zone { border:1px solid #f5c6c2; border-radius:14px; padding:1.5rem; margin-bottom:14px; background:#fff9f9; }
  .danger-zone h2 { font-family:var(--font); font-size:.95rem; font-weight:700; color:var(--danger); margin-bottom:.5rem; }
  .danger-zone p { font-size:.82rem; color:var(--muted); margin-bottom:1rem; }
  .danger-zone .db-info { font-size:.78rem; color:var(--muted); margin-bottom:1rem; font-family:monospace; background:#f5f0eb; padding:.5rem .75rem; border-radius:6px; }
  .btn-danger { background:var(--danger); color:#fff; border:none; border-radius:8px; padding:.5rem 1rem; font-size:.82rem; cursor:pointer; transition:opacity .15s; }
  .btn-danger:hover { opacity:.85; }
  .confirm-box { margin-top:.75rem; display:none; }
  .confirm-box.visible { display:block; }
  .confirm-box p { font-size:.8rem; color:var(--danger); margin-bottom:.5rem; }

  .alert-success { background:#e8f5e9; border:1px solid #a5d6a7; color:#2d6a4f; padding:.6rem 1rem; border-radius:8px; font-size:.82rem; margin-bottom:1rem; }
  .file-info { font-size:.72rem; color:var(--muted); margin-top:.75rem; }
  .section-note { font-size:.72rem; color:var(--muted); margin-top:.5rem; }
  .empty { text-align:center; padding:2.5rem; color:var(--muted); font-size:.85rem; }
  .no-data { color:var(--muted); font-size:.82rem; padding:.5rem 0; }

  /* Info tooltips */
  .card-title { display:flex; align-items:center; gap:.5rem; overflow:visible; }
  .card h2 { overflow:visible; }
  .card-window { font-size:.72rem; font-weight:400; color:var(--muted); }
  .info-btn {
    display:inline-flex; align-items:center; justify-content:center;
    width:12px; height:12px; border-radius:50%;
    border:1px solid var(--border); color:var(--muted);
    font-size:.5rem; font-weight:700; cursor:default;
    position:relative; flex-shrink:0; font-style:normal;
    line-height:1; font-family:var(--sans); opacity:.6; background:none; padding:0;
  }
  .info-btn:hover, .info-btn.active { opacity:1; border-color:var(--muted); cursor:pointer; }
  .info-btn::after {
    content: attr(data-tip);
    position:absolute; bottom:calc(100% + 6px); left:50%;
    transform:translateX(-50%);
    background:var(--text); color:#fff;
    font-size:.72rem; font-weight:400; font-style:normal;
    padding:.4rem .6rem; border-radius:6px;
    white-space:nowrap; max-width:220px; white-space:normal;
    width:max-content; max-width:200px;
    pointer-events:none; display:none;
    z-index:10; line-height:1.4;
  }
  @media (hover: hover) { .info-btn:hover::after { display:block; } }
  .info-btn:focus-visible::after { display:block; }
  .tooltip-float {
    display:none; position:fixed;
    background:var(--text); color:#fff;
    font-size:.72rem; font-weight:400; font-style:normal;
    padding:.4rem .6rem; border-radius:6px;
    max-width:200px; line-height:1.4;
    z-index:1000; pointer-events:none; white-space:normal;
  }
  a:focus-visible, button:focus-visible, input:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation:none !important; transition:none !important; } }
</style>
</head>
<body>

<?php if (!$authed): ?>
<div class="login-wrap">
  <div class="login-box">
    <?php if ($brandLogo): ?>
      <img src="<?= htmlspecialchars($brandLogo) ?>" alt="<?= htmlspecialchars($brandName) ?>" style="height:42px;width:auto;display:block;margin-bottom:.15rem;">
    <?php else: ?>
      <img src="<?= $pimaLogoLight ?>" alt="pima Analytics" style="height:42px;width:auto;display:block;margin-bottom:.15rem;">
    <?php endif; ?>
    <p class="sub"><?= htmlspecialchars($brandName) ?></p>
    <?php if (STATS_PASSWORD === 'change-me-please'): ?>
      <div class="login-error" style="background:#f87171;color:#fff;border-color:#f87171"><?= $t['warn_default_pw'] ?></div>
    <?php endif; ?>
    <?php if (!empty($authUnavailable)): ?>
      <div class="login-error"><?= htmlspecialchars($t['auth_unavailable']) ?></div>
    <?php elseif ($isLocked): ?>
      <div class="login-locked"><?= sprintf($t['locked_out'], $lockRemaining) ?></div>
    <?php elseif (!empty($authError)): ?>
      <div class="login-error"><?= $t['wrong_password'] ?></div>
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
      <input type="password" name="password" placeholder="<?= $lang === 'de' ? 'Passwort' : 'Password' ?>" autofocus autocomplete="current-password" <?= $isLocked ? 'disabled' : '' ?>>
      <button type="submit" <?= $isLocked ? 'disabled' : '' ?>><?= $t['login_btn'] ?></button>
    </form>
  </div>
</div>

<?php else: ?>

<header>
  <div class="header-pima">
    <img src="<?= $pimaLogoDark ?>" alt="pima Analytics" style="height:28px;width:auto;display:block;">
    <div class="header-tagline"><?= htmlspecialchars($t['tagline']) ?></div>
  </div>
  <div class="header-actions">
    <a href="/" class="btn-ghost"><?= $t['back_to_site'] ?></a>
    <a href="?export=1" class="btn-export"><?= $t['export'] ?></a>
    <a href="?" class="btn-ghost"><?= $t['refresh'] ?></a>
    <form method="POST">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
      <button type="submit" name="logout" value="1" class="btn-ghost"><?= $t['logout'] ?></button>
    </form>
  </div>
</header>

<?php if (STATS_PASSWORD === 'change-me-please'): ?>
<div style="background:#f87171;color:#fff;padding:.65rem 1.5rem;font-size:.85rem;font-weight:600;text-align:center"><?= $t['warn_default_pw'] ?></div>
<?php endif; ?>

<main>

<?php if (!empty($clearSuccess)): ?>
  <div class="alert-success"><?= $t['cleared'] ?></div>
<?php endif; ?>

<?php if ($stats['total'] === 0): ?>
  <div class="card"><div class="empty"><?= $t['no_data'] ?></div></div>
<?php else: ?>

<?php
  $weekDiff   = $stats['views_7']  - $stats['views_7_prev'];
  $monthDiff  = $stats['views_30'] - $stats['views_30_prev'];
  $weekDelta  = $weekDiff  > 0 ? '+' . $weekDiff  : ($weekDiff  < 0 ? (string)$weekDiff  : '—');
  $monthDelta = $monthDiff > 0 ? '+' . $monthDiff : ($monthDiff < 0 ? (string)$monthDiff : '—');
  $weekClass  = $weekDiff  > 0 ? 'up' : ($weekDiff  < 0 ? 'down' : 'same');
  $monthClass = $monthDiff > 0 ? 'up' : ($monthDiff < 0 ? 'down' : 'same');
?>

<?php if ($brandLogo || (!empty($brandName) && $brandName !== 'pima')): ?>
<div style="text-align:center;padding:1.5rem 0 .5rem;margin-bottom:1rem;">
  <?php if ($brandLogo): ?>
    <img src="<?= htmlspecialchars($brandLogo) ?>" alt="<?= htmlspecialchars($brandName) ?>" style="max-height:80px;max-width:320px;">
  <?php else: ?>
    <span style="font-size:1.1rem;font-weight:600;color:var(--text);"><?= htmlspecialchars($brandName) ?></span>
  <?php endif; ?>
</div>
<?php endif; ?>

<?php
  $decSep = $lang === 'de' ? ',' : '.';
  $avgPerDay = number_format($stats['views_30'] / max(1, (int) $stats['window_days']), 1, $decSep, '');
  $daySuffix = $stats['window_days'] === 1 ? '' : ($lang === 'de' ? 'e' : 's');
?>
<div class="summary">
  <div class="summary-sentence">
    <?= sprintf($t['summary'], number_format($stats['views_30'])) ?>
  </div>
  <div class="summary-sentence" style="margin-top:.3rem;">
    <?= $stats['window_days'] < 30
        ? sprintf($t['summary_avg_partial'], $avgPerDay, $stats['window_days'], $daySuffix)
        : sprintf($t['summary_avg_full'], $avgPerDay) ?>
  </div>
  <div class="summary-date"><?= dashboardDate(time(), $lang) ?> · <?= htmlspecialchars(TIMEZONE) ?></div>
</div>

<?php
  $arrowUp   = '<svg viewBox="0 0 10 10" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 8V2M5 2L2 5M5 2L8 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  $arrowDown = '<svg viewBox="0 0 10 10" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 2V8M5 8L2 5M5 8L8 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  $weekArrow  = $weekDiff  > 0 ? $arrowUp : ($weekDiff  < 0 ? $arrowDown : '');
  $monthArrow = $monthDiff > 0 ? $arrowUp : ($monthDiff < 0 ? $arrowDown : '');
?>
<div class="kpi-row">
  <div class="kpi highlight">
    <div class="kpi-label"><?= $t['total_views'] ?></div>
    <div class="kpi-value"><?= number_format($stats['total']) ?></div>
    <div style="font-size:.82rem;color:var(--accent);opacity:.7;margin-top:.3rem;font-weight:500;"><?= $t['all_time'] ?></div>
  </div>
  <div class="kpi">
    <div class="kpi-label"><?= $t['today'] ?></div>
    <div class="kpi-value"><?= number_format($stats['today']) ?></div>
    <div style="font-size:.82rem;color:var(--accent);opacity:.7;margin-top:.3rem;font-weight:500;display:flex;align-items:center;gap:.35rem;">
      <?= number_format($stats['uniq_today']) ?> <?= $t['visitors'] ?>
      <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_daily_visitors']) ?>" aria-label="<?= htmlspecialchars($t['tip_daily_visitors']) ?>">i</button>
    </div>
  </div>
  <div class="kpi">
    <div class="kpi-label"><?= $t['win_7'] ?></div>
    <div class="kpi-value"><?= number_format($stats['views_7']) ?></div>
    <div style="font-size:.82rem;color:var(--accent);opacity:.7;margin-top:.3rem;font-weight:500;display:flex;align-items:center;gap:.35rem;">
      <?= number_format($stats['uniq_7']) ?> <?= $t['visitor_days'] ?>
      <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_visitor_days']) ?>" aria-label="<?= htmlspecialchars($t['tip_visitor_days']) ?>">i</button>
    </div>
    <div class="pill <?= $weekClass ?>"><?= $weekArrow ?><?= $weekDelta ?> <?= $t['vs_prev_7'] ?></div>
  </div>
  <div class="kpi">
    <div class="kpi-label"><?= $t['win_30'] ?></div>
    <div class="kpi-value"><?= number_format($stats['views_30']) ?></div>
    <div style="font-size:.82rem;color:var(--accent);opacity:.7;margin-top:.3rem;font-weight:500;display:flex;align-items:center;gap:.35rem;">
      <?= number_format($stats['uniq_30']) ?> <?= $t['visitor_days'] ?>
      <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_visitor_days']) ?>" aria-label="<?= htmlspecialchars($t['tip_visitor_days']) ?>">i</button>
    </div>
    <div class="pill <?= $monthClass ?>"><?= $monthArrow ?><?= $monthDelta ?> <?= $t['vs_prev_30'] ?></div>
  </div>
</div>

<div class="card">
  <h2><span class="card-title"><?= TREND_DAYS ?><?= $t['trend'] ?> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars(sprintf($t['tip_trend'], TREND_DAYS)) ?>" aria-label="<?= htmlspecialchars(sprintf($t['tip_trend'], TREND_DAYS)) ?>">i</button></span></h2>
  <div class="trend-chart">
    <?php foreach ($stats['trend'] as $d => $trendItem):
      $hv = $trendMax > 0 ? max(2, round($trendItem['views'] / $trendMax * 100)) : 2;
    ?>
    <div class="bar-col" title="<?= $d ?>&#10;<?= $t['views'] ?>: <?= $trendItem['views'] ?>&#10;<?= $t['visitors'] ?>: <?= $trendItem['uniq'] ?>">
      <div class="bar-views" style="height:<?= $hv ?>%"></div>
      <div class="lbl">
        <span style="display:block"><?= date('d', strtotime($d)) ?></span>
        <span style="display:block;font-size:.45rem;color:var(--muted)"><?= dashboardMonthShort(strtotime($d), $lang) ?></span>
      </div>
    </div>
    <?php endforeach; ?>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <h2><span class="card-title"><?= $t['top_pages'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_pages']) ?>" aria-label="<?= htmlspecialchars($t['tip_pages']) ?>">i</button></span></h2>
    <?php if (empty($stats['pages'])): ?>
      <p class="no-data"><?= $t['no_pages'] ?></p>
    <?php else:
      $maxP = max(array_column($stats['pages'], 'c')); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['pages'] as $p => $pageData):
        $c      = $pageData['c'];
        $ptitle = $pageData['title'];
        $prev   = $stats['pages_prev'][$p] ?? 0;
        $diff   = $c - $prev;
        $dClass = $diff > 0 ? 'up' : ($diff < 0 ? 'down' : 'same');
        $dLabel = $diff > 0 ? '+' . $diff : ($diff < 0 ? (string)$diff : '—');
      ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <span class="rank-label" title="<?= htmlspecialchars($p) ?>">
            <?php if (!empty($ptitle)): ?>
              <span style="display:block;font-weight:600;font-size:.82rem;line-height:1.3;"><?= htmlspecialchars($ptitle) ?></span>
              <span style="display:block;font-size:.7rem;color:var(--muted);line-height:1.3;"><?= htmlspecialchars($p) ?></span>
            <?php else: ?>
              <?= htmlspecialchars($p) ?>
            <?php endif; ?>
          </span>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxP*100) ?>%"></div></div>
          <span class="rank-count"><?= $c ?></span>
          <span class="delta-pill <?= $dClass ?>"><?= $dLabel ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
      <p class="section-note"><?= htmlspecialchars($t['change_label']) ?></p>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2><span class="card-title"><?= $t['referrers'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_referrers']) ?>" aria-label="<?= htmlspecialchars($t['tip_referrers']) ?>">i</button></span></h2>
    <?php if (empty($stats['referrers'])): ?>
      <p class="no-data"><?= $t['no_referrers'] ?></p>
    <?php else:
      $maxR = max($stats['referrers']); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['referrers'] as $r => $c): ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <span class="rank-label" title="<?= htmlspecialchars($r) ?>"><?= htmlspecialchars($r) ?></span>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxR*100) ?>%"></div></div>
          <span class="rank-count"><?= $c ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </div>
</div>

<div class="grid-3">
  <div class="card">
    <h2><span class="card-title"><?= $t['entry_pages'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_entry']) ?>" aria-label="<?= htmlspecialchars($t['tip_entry']) ?>">i</button></span></h2>
    <?php if (empty($stats['entry_pages'])): ?>
      <p class="no-data"><?= $t['no_external'] ?></p>
    <?php else:
      $maxE = max(array_column($stats['entry_pages'], 'c')); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['entry_pages'] as $p => $entryData):
        $c      = $entryData['c'];
        $etitle = $entryData['title'];
      ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <span class="rank-label" title="<?= htmlspecialchars($p) ?>">
            <?php if (!empty($etitle)): ?>
              <span style="display:block;font-weight:600;font-size:.82rem;line-height:1.3;"><?= htmlspecialchars($etitle) ?></span>
              <span style="display:block;font-size:.7rem;color:var(--muted);line-height:1.3;"><?= htmlspecialchars($p) ?></span>
            <?php else: ?>
              <?= htmlspecialchars($p) ?>
            <?php endif; ?>
          </span>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxE*100) ?>%"></div></div>
          <span class="rank-count"><?= $c ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
      <p class="section-note"><?= $t['entry_note'] ?></p>
    <?php endif; ?>
  </div>

    <div class="card">
    <h2><span class="card-title"><?= $t['channels'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_channels']) ?>" aria-label="<?= htmlspecialchars($t['tip_channels']) ?>">i</button></span></h2>
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
        <span class="dev-label" style="width:8rem;"><?= $chLabels[$chKey] ?></span>
        <div class="dev-track"><div class="dev-fill" style="width:<?= $chPct ?>%;opacity:<?= $chKey === 'organic' ? '1' : ($chKey === 'social' ? '.75' : ($chKey === 'referral' ? '.5' : '.35')) ?>"></div></div>
        <span class="dev-pct"><?= $chPct ?>%</span>
      </div>
    <?php endforeach; endif; ?>
  
  </div>

  <div class="card">
    <h2><span class="card-title"><?= $t['browser_lang'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_lang']) ?>" aria-label="<?= htmlspecialchars($t['tip_lang']) ?>">i</button></span></h2>
    <?php if (empty($stats['languages'])): ?>
      <p class="no-data"><?= $t['no_lang'] ?></p>
    <?php else:
      $maxL = max($stats['languages']); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['languages'] as $l => $c): ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <span class="rank-label"><?= htmlspecialchars(langName($l, $langNames)) ?></span>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxL*100) ?>%"></div></div>
          <span class="rank-count"><?= $c ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
      <p class="section-note"><?= htmlspecialchars($t['known_values_note']) ?></p>
    <?php endif; ?>
  </div>
</div>
<div class="grid-3">
  <div class="card">
    <h2><span class="card-title"><?= $t['time_of_day'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_tod']) ?>" aria-label="<?= htmlspecialchars($t['tip_tod']) ?>">i</button></span></h2>
    <div class="hours-chart">
      <?php for ($h = 0; $h < 24; $h++):
        $hh = $hourMax > 0 ? max(2, round($stats['hours'][$h]['views'] / $hourMax * 100)) : 2; ?>
        <div class="hour-col" title="<?= sprintf('%02d', $h) ?>:00 — <?= $stats['hours'][$h]['views'] ?> <?= $t['views'] ?>">
          <div class="bar" style="height:<?= $hh ?>%"></div>
          <div class="lbl"><?= $h % 6 === 0 ? sprintf('%02d', $h) : '' ?></div>
        </div>
      <?php endfor; ?>
    </div>
    <?php
      $peakHour = array_search(max(array_column($stats['hours'], 'views')), array_column($stats['hours'], 'views'));
      $peakViews = $stats['hours'][$peakHour]['views'];
    ?>
    <?php if ($peakViews > 0): ?>
      <p class="section-note" style="margin-top:.6rem;"><?= $t['peak'] ?>: <?= sprintf('%02d', $peakHour) ?>:00 – <?= sprintf('%02d', ($peakHour + 1) % 24) ?>:00 · <?= $peakViews ?> <?= $t['views'] ?></p>
    <?php endif; ?>
  </div>

  <div class="card">
    <h2><span class="card-title"><?= $t['device_type'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_device']) ?>" aria-label="<?= htmlspecialchars($t['tip_device']) ?>">i</button></span></h2>
    <?php
      $deviceIcons = [
        'desktop' => '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
        'mobile'  => '<svg width="12" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2"/><circle cx="12" cy="17" r="1" fill="currentColor"/></svg>',
        'tablet'  => '<svg width="12" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="2" width="16" height="20" rx="2"/><circle cx="12" cy="17" r="1" fill="currentColor"/></svg>',
      ];
      $devicePercentages = wholePercentages($stats['devices']);
    ?>
    <?php foreach (['desktop','mobile','tablet'] as $type):
      $pct = $devicePercentages[$type]; ?>
      <div class="dev-row">
        <span class="dev-label" style="display:flex;align-items:center;gap:.4rem;"><?= $deviceIcons[$type] ?><?= htmlspecialchars($t['device_' . $type]) ?></span>
        <div class="dev-track"><div class="dev-fill <?= $type ?>" style="width:<?= $pct ?>%"></div></div>
        <span class="dev-pct"><?= $pct ?>%</span>
      </div>
    <?php endforeach; ?>
    <p class="section-note"><?= htmlspecialchars($t['visitor_days_note']) ?></p>
  </div>

  <div class="card">
    <h2><span class="card-title"><?= $t['top_countries'] ?> <span class="card-window"><?= $t['win_30_label'] ?></span> <button type="button" class="info-btn" data-tip="<?= htmlspecialchars($t['tip_countries']) ?>" aria-label="<?= htmlspecialchars($t['tip_countries']) ?>">i</button></span></h2>
    <?php if (empty($stats['countries'])): ?>
      <p class="no-data"><?= $t['no_geo'] ?></p>
    <?php else:
      $maxC = max($stats['countries']); $i = 1; ?>
      <ul class="rank-list">
      <?php foreach ($stats['countries'] as $co => $c): ?>
        <li>
          <span class="rank-n"><?= $i++ ?></span>
          <span class="rank-label"><?= countryFlag($co) ?> <?= htmlspecialchars(countryName($co, $countryNames)) ?></span>
          <div class="rank-track"><div class="rank-fill" style="width:<?= round($c/$maxC*100) ?>%"></div></div>
          <span class="rank-count"><?= $c ?></span>
        </li>
      <?php endforeach; ?>
      </ul>
      <p class="section-note"><?= htmlspecialchars($t['known_values_note']) ?></p>
    <?php endif; ?>
  </div>
</div>

<div class="card">
  <div style="display:flex;align-items:center;justify-content:space-between;padding-bottom:.75rem;border-bottom:1px solid var(--border);margin-bottom:1rem;">
    <h2 style="border:none;padding:0;margin:0;"><?= sprintf($t['recent_hits'], RECENT_ENTRIES) ?></h2>
    <button onclick="var t=document.getElementById('recent-tbl');var b=this;t.style.display=t.style.display==='none'?'block':'none';b.textContent=t.style.display==='none'?'<?= addslashes($t['show']) ?>':'<?= addslashes($t['hide']) ?>';" style="background:none;border:1px solid var(--border);border-radius:8px;padding:.3rem .75rem;font-size:.78rem;color:var(--muted);cursor:pointer;"><?= $t['show'] ?></button>
  </div>
  <div id="recent-tbl" style="display:none;">
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th><?= $t['th_date'] ?></th><th><?= $t['th_time'] ?></th><th><?= $t['th_page'] ?></th><th><?= $t['th_referrer'] ?></th><th><?= $t['th_device'] ?></th><th><?= $t['th_country'] ?></th></tr>
        </thead>
        <tbody>
          <?php foreach ($stats['recent'] as $r): ?>
          <tr>
            <td class="muted"><?= htmlspecialchars($r['date']) ?></td>
            <td class="muted"><?= htmlspecialchars($r['time']) ?></td>
            <td><?= htmlspecialchars($r['page']) ?></td>
            <td class="muted"><?= !empty($r['referrer']) ? htmlspecialchars($r['referrer']) : '—' ?></td>
            <?php $recentDevice = in_array($r['device'], ['desktop','mobile','tablet'], true) ? $r['device'] : 'desktop'; ?>
            <td><span class="badge badge-<?= $recentDevice ?>"><?= htmlspecialchars($t['device_' . $recentDevice]) ?></span></td>
            <td><?= $r['country'] ? countryFlag($r['country']) . ' ' . htmlspecialchars(countryName($r['country'], $countryNames)) : '—' ?></td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
  <?php if ($advancedMode): ?><p class="file-info">analytics.db · <?= $stats['db_size'] ?> KB · <?= number_format($stats['db_rows']) ?> rows</p><?php endif; ?>
</div>

<?php endif; // total > 0 ?>

<?php if ($advancedMode): ?>
<div class="danger-zone">
  <h2><?= $t['danger_title'] ?></h2>
  <p><?= $t['danger_desc'] ?></p>
  <div class="db-info">analytics.db · <?= $stats['db_size'] ?> KB · <?= number_format($stats['db_rows']) ?> rows</div>
  <button class="btn-danger" onclick="document.getElementById('confirm-clear').classList.toggle('visible')"><?= $t['clear_btn'] ?></button>
  <div class="confirm-box" id="confirm-clear">
    <p><?= sprintf($t['confirm_msg'], number_format($stats['db_rows'])) ?></p>
    <form method="POST">
      <input type="hidden" name="clear_data" value="1">
      <input type="hidden" name="confirm_clear" value="yes">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf'] ?? '') ?>">
      <button type="submit" class="btn-danger"><?= $t['confirm_btn'] ?></button>
    </form>
  </div>
</div>
<?php endif; ?>

</main>

<footer style="text-align:center;padding:1.5rem 1rem;font-size:.75rem;color:var(--muted);border-top:1px solid var(--border);margin-top:1rem;">
  <?= $t['powered_by'] ?> <a href="https://ludescher.studio" target="_blank" rel="noopener noreferrer" style="color:var(--muted);text-decoration:underline;">pima Analytics</a> &mdash; <a href="https://github.com/ludescherstudio/pima-analytics" target="_blank" rel="noopener noreferrer" style="color:var(--muted);text-decoration:underline;">GitHub</a>
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
})();
</script>
</body>
</html>
