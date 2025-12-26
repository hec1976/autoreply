<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(0);

date_default_timezone_set('Europe/Zurich');


$cfgPath = __DIR__ . '/../../config/config.php';
$cfg = [];
if (is_file($cfgPath)) {
    $tmp = require $cfgPath;
    if (is_array($tmp)) $cfg = $tmp;
}

$httpsEnforce = (bool)($cfg['https_enforce'] ?? false);
$hstsEnable   = (bool)($cfg['hsts_enable'] ?? false);

$cookieSecure = (bool)($cfg['cookie_secure'] ?? false);
$cookieSameSite = (string)($cfg['cookie_samesite'] ?? 'Strict');
if (!in_array($cookieSameSite, ['Strict','Lax','None'], true)) {
    $cookieSameSite = 'Strict';
}

// HTTPS direkt erkennen (ohne Proxy Header)
$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
);

// Session Cookie Sicherheit
// Hinweis: Wenn cookie_secure=true und du rufst per HTTP auf, wirkt es wie "Session geht nicht".
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $cookieSecure,     // voll aus Config
    'httponly' => true,
    'samesite' => $cookieSameSite
]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// HTTPS Enforcement ueber Config
if ($httpsEnforce && !$isHttps) {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    $uri  = $_SERVER['REQUEST_URI'] ?? '/';
    if ($host !== '') {
        header('Location: https://' . $host . $uri, true, 301);
        exit();
    }
}

if (!headers_sent()) {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    // HSTS nur wenn config aktiv UND HTTPS wirklich aktiv ist
    if ($hstsEnable && $isHttps) {
        header('Strict-Transport-Security: max-age=15552000; includeSubDomains');
    }

    $csp = "default-src 'self'; "
         . "script-src 'self' 'unsafe-inline'; "
         . "style-src 'self' 'unsafe-inline'; "
         . "img-src 'self' data: https:; "
         . "font-src 'self'; "
         . "connect-src 'self'; "
         . "frame-ancestors 'none'; "
         . "form-action 'self'";

    header('Content-Security-Policy: ' . $csp);
}
