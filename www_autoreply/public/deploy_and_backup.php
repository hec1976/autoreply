<?php
declare(strict_types=1);

ob_start();

/*
 * SICHERHEIT
 */
require_once __DIR__ . '/includes/security-headers.php';

$csrf = $_SESSION['csrf_token'] ?? '';
if ($csrf === '') {
    http_response_code(500);
    echo "CSRF Token fehlt in Session.";
    exit;
}


/*
 * App Config
 */
$config = include __DIR__ . '/../config/config.php';
$token   = $config['apiToken'] ?? '';
$servers = $config['servers'] ?? [];

if (!$token || !$servers) {
    http_response_code(500);
    echo "Fehlende Konfiguration (apiToken/servers).";
    exit;
}

/*
 * array_key_first Fallback (alte PHP Version)
 */
if (!function_exists('array_key_first')) {
    function array_key_first(array $a) {
        foreach ($a as $k => $_) {
            return $k;
        }
        return null;
    }
}

$firstKey = array_key_first($servers) ?? '';
$origin   = $_POST['origin'] ?? ($_GET['origin'] ?? $firstKey);

/* -------------------------------------------------------------------------
 * HTTP Basics
 * ------------------------------------------------------------------------- */

function http_get(string $base, string $endpoint, string $token): array
{
    global $config;
    
    $ch = curl_init(rtrim($base, '/') . $endpoint);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTPHEADER     => ['X-API-Token: ' . $token],
        CURLOPT_SSL_VERIFYHOST => ($config['curl_ssl_verify_host'] ?? false) ? 2 : 0,
        CURLOPT_SSL_VERIFYPEER => $config['curl_ssl_verify_peer'] ?? false,
        CURLOPT_TIMEOUT        => 30,
    ]);

    $body = curl_exec($ch);
    $err  = curl_errno($ch) ? curl_error($ch) : '';
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    curl_close($ch);

    return [
        'ok'     => !$err && $code >= 200 && $code < 300,
        'status' => $code,
        'body'   => $err ?: (string)$body,
    ];
}

function http_post_file(
    string $base,
    string $endpoint,
    string $token,
    string $field,
    string $filename,
    string $content,
    string $mime = 'application/json'
): array {
    global $config;
    
    $tmp = tempnam(sys_get_temp_dir(), 'cfg_');
    file_put_contents($tmp, $content);

    $cfile = new CURLFile($tmp, $mime, $filename);
    $ch = curl_init(rtrim($base, '/') . $endpoint);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['X-API-Token: ' . $token],
        CURLOPT_SSL_VERIFYHOST => ($config['curl_ssl_verify_host'] ?? false) ? 2 : 0,
        CURLOPT_SSL_VERIFYPEER => $config['curl_ssl_verify_peer'] ?? false,
        CURLOPT_POSTFIELDS     => [$field => $cfile],
        CURLOPT_TIMEOUT        => 30,
    ]);

    $body = curl_exec($ch);
    $err  = curl_errno($ch) ? curl_error($ch) : '';
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    curl_close($ch);
    @unlink($tmp);

    return [
        'ok'     => !$err && $code >= 200 && $code < 300,
        'status' => $code,
        'body'   => $err ?: (string)$body,
    ];
}

/*
 * Backup holen: zuerst /backup, dann Fallback /backu
 * (das ist bewusst so drin, weil es die API offenbar mal falsch gab)
 */
function http_get_backup_file(string $base, string $file, string $token): array
{
    $file = rawurlencode($file);

    $r1 = http_get($base, '/autoreply/backup/' . $file, $token);
    if ($r1['ok']) {
        return $r1;
    }

    return http_get($base, '/autoreply/backu/' . $file, $token);
}

/* -------------------------------------------------------------------------
 * Utils
 * ------------------------------------------------------------------------- */

function json_try_decode(string $s): ?array
{
    $d = json_decode($s, true);
    return (json_last_error() === JSON_ERROR_NONE && is_array($d)) ? $d : null;
}

function pretty_json(string $s): string
{
    $d = json_try_decode($s);
    return $d ? json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : $s;
}

function short_hash(?string $h): string
{
    return $h ? substr($h, 0, 10) . '…' : '—';
}

function badge_http(int $code): string
{
    $cls = 'secondary';
    if ($code >= 200 && $code < 300) $cls = 'success';
    elseif ($code >= 300 && $code < 400) $cls = 'info';
    elseif ($code >= 400 && $code < 500) $cls = 'warning';
    elseif ($code >= 500) $cls = 'danger';

    return '<span class="badge bg-' . $cls . '">' . $code . '</span>';
}

function is_server_backup(string $filename): bool
{
    return (bool)preg_match('/^server_\d{8}_\d{6}\.json$/', $filename);
}
function is_user_backup(string $filename): bool
{
    return (bool)preg_match('/^user_\d{8}_\d{6}\.json$/', $filename);
}
function valid_backup_name(string $filename): bool
{
    return is_server_backup($filename) || is_user_backup($filename);
}

/*
 * JSON structural diff (pfadbasiert)
 */
function json_diff_struct($a, $b, string $path = ''): array
{
    $changes = [];
    $isAssoc = fn($x) => is_array($x) && array_values($x) !== $x;

    if (is_array($a) && is_array($b)) {
        if ($isAssoc($a) && $isAssoc($b)) {
            $keys = array_unique(array_merge(array_keys($a), array_keys($b)));
            foreach ($keys as $k) {
                $p = $path . '/' . str_replace('~', '~0', str_replace('/', '~1', (string)$k));

                if (!array_key_exists($k, $a)) {
                    $changes[] = ['type' => 'added', 'path' => $p, 'from' => null, 'to' => $b[$k]];
                } elseif (!array_key_exists($k, $b)) {
                    $changes[] = ['type' => 'removed', 'path' => $p, 'from' => $a[$k], 'to' => null];
                } else {
                    $changes = array_merge($changes, json_diff_struct($a[$k], $b[$k], $p));
                }
            }
        } else {
            $max = max(count($a), count($b));
            for ($i = 0; $i < $max; $i++) {
                $p = $path . '/' . $i;

                if (!array_key_exists($i, $a)) {
                    $changes[] = ['type' => 'added', 'path' => $p, 'from' => null, 'to' => $b[$i]];
                } elseif (!array_key_exists($i, $b)) {
                    $changes[] = ['type' => 'removed', 'path' => $p, 'from' => $a[$i], 'to' => null];
                } else {
                    $changes = array_merge($changes, json_diff_struct($a[$i], $b[$i], $p));
                }
            }
        }
    } else {
        if ($a !== $b) {
            $changes[] = ['type' => 'changed', 'path' => $path ?: '/', 'from' => $a, 'to' => $b];
        }
    }

    return $changes;
}

/* -------------------------------------------------------------------------
 * Download Proxy
 * Muss vor jeder HTML Ausgabe laufen
 * ------------------------------------------------------------------------- */

if (isset($_GET['dl'])) {
    $srv  = $_GET['srv'] ?? $firstKey;
    $file = basename((string)($_GET['file'] ?? ''));

    if (!$srv || !isset($servers[$srv])) {
        while (ob_get_level()) ob_end_clean();
        http_response_code(400);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Ungültiger Server.";
        exit;
    }

    if (!valid_backup_name($file)) {
        while (ob_get_level()) ob_end_clean();
        http_response_code(400);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Ungültiger Dateiname.";
        exit;
    }

    $res = http_get_backup_file($servers[$srv], $file, $token);

    while (ob_get_level()) ob_end_clean();

    if (empty($res['ok'])) {
        http_response_code(502);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Download fehlgeschlagen ($srv): HTTP " . ((int)$res['status']) . "\n" . (string)$res['body'];
        exit;
    }

    $body = (string)$res['body'];

    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $file . '"');
    header('Content-Length: ' . strlen($body));
    header('X-Served-By: Autoreply-Dashboard');

    echo $body;
    exit;
}

/* -------------------------------------------------------------------------
 * State und Aktionen
 * ------------------------------------------------------------------------- */

$alertsSync     = [];
$alertsCompare  = [];
$alertsBackups  = [];

$resultsSync    = [];   // label => [server => res]
$compareRows    = [];
$backups        = [];

$diffData       = null; // Daten fuer Diff Modal
$resultsRestore = null; // Restore Ergebnis

if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['csrf_token'])
    && hash_equals($csrf, $_POST['csrf_token'])
) {
    $action = $_POST['action'] ?? '';

    $originPost = $_POST['origin'] ?? $origin;
    $origin = isset($servers[$originPost]) ? $originPost : $firstKey;

    /*
     * Sync: Origin nach alle Server
     */
    if ($action === 'sync_server' || $action === 'sync_user') {
        $type = ($action === 'sync_server') ? 'server' : 'user';
        $ep   = ($type === 'server') ? '/autoreply/server/config' : '/autoreply/user/config';

        $originUrl = $servers[$origin] ?? null;
        if (!$originUrl) {
            $alertsSync[] = ['danger', "Ungültiger Origin: " . htmlspecialchars($origin)];
        } else {
            $pull = http_get($originUrl, $ep, $token);

            if (!$pull['ok']) {
                $alertsSync[] = ['danger', "Pull vom Origin fehlgeschlagen ($origin): HTTP " . $pull['status'] . " – " . htmlspecialchars($pull['body'])];
            } else {
                $content = (string)$pull['body'];

                if (json_try_decode($content) === null) {
                    $alertsSync[] = ['danger', "Antwort vom Origin ist keine gültige JSON ($origin). Abbruch."];
                } else {
                    $label = strtoupper($type) . "-Config";

                    foreach ($servers as $name => $base) {
                        if ($name === $origin) {
                            $resultsSync[$label][$name] = ['ok' => true, 'status' => 200, 'body' => '(origin)'];
                            continue;
                        }

                        $res = http_post_file(
                            $base,
                            $ep,
                            $token,
                            'config',
                            $type === 'server' ? 'autoreply_server.json' : 'autoreply_user.json',
                            $content
                        );

                        $resultsSync[$label][$name] = $res;
                    }

                    $ok  = array_sum(array_map(fn($r) => !empty($r['ok']) ? 1 : 0, $resultsSync[$label]));
                    $tot = count($resultsSync[$label]);

                    $cls = $ok === $tot ? 'success' : ($ok ? 'warning' : 'danger');
                    $alertsSync[] = [$cls, ($type === 'server' ? 'Server-' : 'User-') . "Config von <b>" . htmlspecialchars($origin) . "</b> an <b>$ok/$tot</b> Server verteilt."];
                }
            }
        }
    }

    /*
     * Vergleich: SHA-256 gegen Origin
     */
    if ($action === 'compare') {
        $sets = [
            'SERVER-Config' => '/autoreply/server/config',
            'USER-Config'   => '/autoreply/user/config',
        ];

        foreach ($sets as $label => $ep) {
            $hashes = [];

            foreach ($servers as $name => $base) {
                $r = http_get($base, $ep, $token);
                $hashes[$name] = $r['ok'] ? hash('sha256', (string)$r['body']) : null;
            }

            $ref = $hashes[$origin] ?? null;

            foreach ($servers as $name => $_) {
                $compareRows[] = [
                    'set'   => $label,
                    'srv'   => $name,
                    'hash'  => $hashes[$name],
                    'match' => ($hashes[$name] && $ref) ? ($hashes[$name] === $ref) : false,
                    'err'   => ($hashes[$name] === null),
                ];
            }
        }

        $alertsCompare[] = ['info', 'Vergleich durchgeführt (SHA-256 gegen Origin).'];
    }

    /*
     * Diff: Backup gegen aktuelle Origin Config
     */
    if ($action === 'backup_diff') {
        $file = basename((string)($_POST['file'] ?? ''));

        if (!$file || !valid_backup_name($file)) {
            $alertsBackups[] = ['danger', 'Kein oder ungültiges Backup ausgewählt.'];
        } else {
            $respB = http_get_backup_file($servers[$firstKey], $file, $token);

            if (!$respB['ok']) {
                $alertsBackups[] = ['danger', 'Backup konnte nicht geladen werden (HTTP ' . $respB['status'] . ').'];
            } else {
                $backupBody = (string)$respB['body'];
                $backupArr  = json_try_decode($backupBody);

                if (!$backupArr) {
                    $alertsBackups[] = ['danger', 'Backup-Datei enthält keine gültige JSON.'];
                } else {
                    $type = is_server_backup($file) ? 'server' : 'user';
                    $ep   = ($type === 'server') ? '/autoreply/server/config' : '/autoreply/user/config';

                    $respC = http_get($servers[$origin], $ep, $token);

                    if (!$respC['ok']) {
                        $alertsBackups[] = ['danger', 'Aktuelle Config vom Origin konnte nicht geladen werden (HTTP ' . $respC['status'] . ').'];
                    } else {
                        $currentBody = (string)$respC['body'];
                        $currentArr  = json_try_decode($currentBody);

                        if ($currentArr === null) {
                            $alertsBackups[] = ['danger', 'Aktuelle Config am Origin ist keine gültige JSON.'];
                        } else {
                            $changes = json_diff_struct($backupArr, $currentArr, '');

                            if (count($changes) > 500) {
                                $changes = array_slice($changes, 0, 500);
                                $alertsBackups[] = ['warning', 'Diff-Anzeige auf 500 Einträge gekürzt.'];
                            }

                            $diffData = [
                                'file'          => $file,
                                'type'          => $type,
                                'origin'        => $origin,
                                'backupPretty'  => pretty_json($backupBody),
                                'currentPretty' => pretty_json($currentBody),
                                'changes'       => $changes,
                                'hash_backup'   => hash('sha256', $backupBody),
                                'hash_current'  => hash('sha256', $currentBody),
                            ];
                        }
                    }
                }
            }
        }
    }

    /*
     * Restore: Backup an alle Server
     */
    if ($action === 'restore_from_backup') {
        $file = basename((string)($_POST['file'] ?? ''));

        if (!$file || !valid_backup_name($file)) {
            $alertsBackups[] = ['danger', 'Kein oder ungültiges Backup ausgewählt.'];
        } else {
            $respB = http_get_backup_file($servers[$firstKey], $file, $token);

            if (!$respB['ok']) {
                $alertsBackups[] = ['danger', 'Backup konnte nicht geladen werden (HTTP ' . $respB['status'] . ').'];
            } else {
                $content = (string)$respB['body'];

                if (json_try_decode($content) === null) {
                    $alertsBackups[] = ['danger', 'Backup enthält keine gültige JSON.'];
                } else {
                    $type     = is_server_backup($file) ? 'server' : 'user';
                    $endpoint = ($type === 'server') ? '/autoreply/server/config' : '/autoreply/user/config';

                    $resAll = [];
                    foreach ($servers as $name => $base) {
                        $resAll[$name] = http_post_file(
                            $base,
                            $endpoint,
                            $token,
                            'config',
                            $type === 'server' ? 'autoreply_server.json' : 'autoreply_user.json',
                            $content
                        );
                    }

                    $resultsRestore = ['file' => $file, 'type' => $type, 'results' => $resAll];

                    $ok  = array_sum(array_map(fn($r) => !empty($r['ok']) ? 1 : 0, $resAll));
                    $tot = count($resAll);
                    $cls = $ok === $tot ? 'success' : ($ok ? 'warning' : 'danger');

                    $alertsBackups[] = [$cls, "Restore von <b>" . htmlspecialchars($file) . "</b> auf <b>$ok/$tot</b> Server durchgeführt."];
                }
            }
        }
    }
}

/* -------------------------------------------------------------------------
 * Backups laden (vom FIRST)
 * ------------------------------------------------------------------------- */

if ($firstKey) {
    $r = http_get($servers[$firstKey], '/autoreply/backups', $token);
    if ($r['ok']) {
        $data    = json_try_decode((string)$r['body']);
        $backups = $data['backups'] ?? [];
    }
}

ob_end_flush();
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>Autoresponder Console</title>

<link href="assets/css/bootstrap.min.css" rel="stylesheet">
<link href="assets/css/bootstrap-icons.css" rel="stylesheet">
<link href="assets/css/dataTables.bootstrap5.min.css" rel="stylesheet">
<link href="assets/css/styles.css" rel="stylesheet">

<style>
  .spin{display:inline-block;animation:spin 1s linear infinite}
  @keyframes spin{100%{transform:rotate(360deg)}}
  pre.api {white-space:pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Courier New", monospace;}
  code.json {white-space:pre; display:block; overflow:auto; max-height:50vh;}
  .table-sticky thead th{position:sticky;top:0;background:#f8f9fa;z-index:1}
  .mini-bar{background:#f8f9fa;border:1px solid #e9ecef;border-radius:10px;padding:.25rem .5rem}
  .mini-vr{width:1px;align-self:stretch;background:#e9ecef;margin:0 .35rem}
</style>
</head>

<body>
<?php include __DIR__ . '/includes/navigation.php'; ?>
<?php include __DIR__ . '/includes/sidebar.php'; ?>

<div class="container mt-4" style="margin-left:270px;">

  <div class="d-flex align-items-center justify-content-between mb-2">
    <h2 class="mb-4">Deploy & Backup</h2>
  </div>

  <div class="mini-bar d-flex align-items-center flex-wrap gap-2 small mb-3">
    <i class="bi bi-cloud-arrow-down"></i>
    <span class="fw-semibold">Live-Quelle</span>
    <span class="badge text-bg-secondary"><?= htmlspecialchars($origin) ?></span>
    <span class="text-muted">(<?= htmlspecialchars($servers[$origin] ?? '-') ?>)</span>

    <span class="mini-vr"></span>

    <label class="m-0">Origin:</label>
    <select id="originSelect" class="form-select form-select-sm w-auto">
      <?php foreach ($servers as $name => $url): ?>
        <option value="<?= htmlspecialchars($name) ?>" <?= $name === $origin ? 'selected' : '' ?>>
          <?= htmlspecialchars($name) ?>
        </option>
      <?php endforeach; ?>
    </select>

    <span class="mini-vr"></span>

    <span class="text-muted"><i class="bi bi-broadcast me-1"></i>Verteilen: <b>an alle Server</b></span>
  </div>

  <ul class="nav nav-tabs" id="tabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#syncTab" type="button" role="tab">
        <i class="bi bi-arrows-expand me-1"></i>Sync
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" data-bs-toggle="tab" data-bs-target="#compareTab" type="button" role="tab">
        <i class="bi bi-intersect me-1"></i>Vergleich
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" data-bs-toggle="tab" data-bs-target="#backupsTab" type="button" role="tab">
        <i class="bi bi-hdd-stack me-1"></i>Backups / Diff / Restore
      </button>
    </li>
  </ul>

  <div class="tab-content pt-3">

    <div class="tab-pane fade show active" id="syncTab" role="tabpanel">
      <?php foreach ($alertsSync as [$type, $msg]): ?>
        <div class="alert alert-<?= htmlspecialchars($type) ?>"><?= $msg ?></div>
      <?php endforeach; ?>

      <div class="card shadow-sm rounded-3 mb-4">
        <div class="card-header bg-light d-flex justify-content-between align-items-center">
          <div class="d-flex align-items-center">
            <i class="bi bi-arrow-left-right me-2"></i>
            <span class="fw-semibold">Sync (Origin zu alle)</span>
          </div>

          <form method="post" class="d-flex align-items-center gap-2">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
            <input type="hidden" name="active_tab" value="#syncTab">

            <label class="form-label m-0">Origin:</label>
            <select name="origin" id="originSelectSync" class="form-select form-select-sm">
              <?php foreach ($servers as $name => $url): ?>
                <option value="<?= htmlspecialchars($name) ?>" <?= $name === $origin ? 'selected' : '' ?>>
                  <?= htmlspecialchars($name) ?> (<?= htmlspecialchars($url) ?>)
                </option>
              <?php endforeach; ?>
            </select>

            <button name="action" value="sync_server" class="btn btn-secondary btn-sm">
              <i class="bi bi-gear me-1"></i> Server-Config verteilen
            </button>
            <button name="action" value="sync_user" class="btn btn-secondary btn-sm">
              <i class="bi bi-person-gear me-1"></i> User-Config verteilen
            </button>
          </form>
        </div>

        <div class="card-body">
          <?php if ($resultsSync): foreach ($resultsSync as $label => $rows): ?>
            <h6 class="fw-bold mb-2"><i class="bi bi-activity me-1"></i><?= htmlspecialchars($label) ?></h6>
            <div class="table-responsive">
              <table class="table table-hover align-middle mb-3" id="syncResultTable_<?= htmlspecialchars(preg_replace('/\W+/', '_', $label)) ?>">
                <thead class="table-light">
                  <tr><th>Server</th><th>Status</th><th>HTTP</th><th>Antwort</th></tr>
                </thead>
                <tbody>
                  <?php foreach ($rows as $srv => $r): ?>
                    <tr class="<?= !empty($r['ok']) ? '' : 'table-danger' ?>">
                      <td class="fw-medium"><?= htmlspecialchars($srv) ?></td>
                      <td>
                        <span class="badge rounded-pill bg-<?= !empty($r['ok']) ? 'success' : 'danger' ?>">
                          <?= !empty($r['ok']) ? 'OK' : 'Fehler' ?>
                        </span>
                      </td>
                      <td><?= badge_http((int)($r['status'] ?? 0)) ?></td>
                      <td><pre class="api mb-0"><?= htmlspecialchars((string)($r['body'] ?? '')) ?></pre></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endforeach; else: ?>
            <div class="text-muted">Noch keine Sync-Aktion ausgeführt.</div>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <div class="tab-pane fade" id="compareTab" role="tabpanel">
      <?php foreach ($alertsCompare as [$type, $msg]): ?>
        <div class="alert alert-<?= htmlspecialchars($type) ?>"><?= $msg ?></div>
      <?php endforeach; ?>

      <div class="card shadow-sm rounded-3 mb-4">
        <div class="card-header bg-light d-flex justify-content-between align-items-center">
          <div class="d-flex align-items-center">
            <i class="bi bi-search me-2"></i>
            <span class="fw-semibold">Vergleich (SHA-256) gegen Origin</span>
          </div>

          <form method="post" class="d-flex align-items-center gap-2" id="compareForm">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
            <input type="hidden" name="active_tab" value="#compareTab">

            <label class="form-label m-0">Origin:</label>
            <select name="origin" class="form-select form-select-sm">
              <?php foreach ($servers as $name => $url): ?>
                <option value="<?= htmlspecialchars($name) ?>" <?= $name === $origin ? 'selected' : '' ?>>
                  <?= htmlspecialchars($name) ?> (<?= htmlspecialchars($url) ?>)
                </option>
              <?php endforeach; ?>
            </select>

            <button name="action" value="compare" class="btn btn-outline-secondary btn-sm">
              <i class="bi bi-search me-1"></i> Vergleichen
            </button>
          </form>
        </div>

        <div class="card-body">
          <?php if ($compareRows): ?>
            <div class="table-responsive table-sticky">
              <table class="table table-hover align-middle mb-0" id="compareTable">
                <thead class="table-light">
                  <tr><th>Set</th><th>Server</th><th>SHA-256</th><th>Match zu Origin (<?= htmlspecialchars($origin) ?>)</th></tr>
                </thead>
                <tbody>
                  <?php foreach ($compareRows as $row): ?>
                    <tr class="<?= ($row['err'] || !$row['match']) ? 'table-warning' : '' ?>">
                      <td><?= htmlspecialchars($row['set']) ?></td>
                      <td class="fw-medium"><?= htmlspecialchars($row['srv']) ?></td>
                      <td><code><?= htmlspecialchars(short_hash($row['hash'])) ?></code></td>
                      <td>
                        <?php if ($row['err']): ?>
                          <span class="badge bg-danger">Fehler</span>
                        <?php else: ?>
                          <span class="badge bg-<?= $row['match'] ? 'success' : 'warning' ?>">
                            <?= $row['match'] ? 'OK' : 'DIFF' ?>
                          </span>
                        <?php endif; ?>
                      </td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php else: ?>
            <div class="text-muted">Noch kein Vergleich durchgeführt.</div>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <div class="tab-pane fade" id="backupsTab" role="tabpanel">
      <?php foreach ($alertsBackups as [$type, $msg]): ?>
        <div class="alert alert-<?= htmlspecialchars($type) ?>"><?= $msg ?></div>
      <?php endforeach; ?>

      <?php if ($resultsRestore): ?>
        <div class="card shadow-sm rounded-3 mb-4">
          <div class="card-header bg-light d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
              <i class="bi bi-arrow-counterclockwise me-2"></i>
              <span class="fw-semibold">Restore Ergebnis: <?= htmlspecialchars($resultsRestore['file']) ?> (<?= htmlspecialchars(strtoupper($resultsRestore['type'])) ?>)</span>
            </div>
          </div>

          <div class="card-body">
            <div class="table-responsive">
              <table class="table table-hover align-middle mb-0" id="restoreResultTable">
                <thead class="table-light"><tr><th>Server</th><th>Status</th><th>HTTP</th><th>Antwort</th></tr></thead>
                <tbody>
                  <?php foreach ($resultsRestore['results'] as $srv => $r): ?>
                    <tr class="<?= !empty($r['ok']) ? '' : 'table-danger' ?>">
                      <td class="fw-medium"><?= htmlspecialchars($srv) ?></td>
                      <td>
                        <span class="badge rounded-pill bg-<?= !empty($r['ok']) ? 'success' : 'danger' ?>">
                          <?= !empty($r['ok']) ? 'OK' : 'Fehler' ?>
                        </span>
                      </td>
                      <td><?= badge_http((int)($r['status'] ?? 0)) ?></td>
                      <td><pre class="api mb-0"><?= htmlspecialchars((string)($r['body'] ?? '')) ?></pre></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <div class="card shadow-sm rounded-3 mb-4">
        <div class="card-header bg-light d-flex justify-content-between align-items-center">
          <div class="d-flex align-items-center">
            <i class="bi bi-hdd-stack me-2"></i>
            <span class="fw-semibold">Backups (Quelle: <?= htmlspecialchars($firstKey) ?>)</span>
          </div>

          <form method="post" class="d-flex align-items-center gap-2">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
            <input type="hidden" name="active_tab" value="#backupsTab">

            <label class="form-label m-0">Origin fuer Diff:</label>
            <select name="origin" class="form-select form-select-sm" id="originSelectBackups">
              <?php foreach ($servers as $name => $url): ?>
                <option value="<?= htmlspecialchars($name) ?>" <?= $name === $origin ? 'selected' : '' ?>>
                  <?= htmlspecialchars($name) ?> (<?= htmlspecialchars($url) ?>)
                </option>
              <?php endforeach; ?>
            </select>
          </form>
        </div>

        <div class="card-body">
          <?php if (!$firstKey): ?>
            <div class="alert alert-warning mb-0">Keine Server konfiguriert.</div>
          <?php elseif (!$backups): ?>
            <div class="alert alert-info mb-0">Keine Backups gefunden.</div>
          <?php else: ?>
            <div class="table-responsive">
              <table class="table table-hover align-middle mb-0" id="backupsTable">
                <thead class="table-light">
                  <tr><th>Datei</th><th>Typ</th><th>Erstellt</th><th class="text-end" style="width:320px">Aktion</th></tr>
                </thead>
                <tbody>
                  <?php foreach ($backups as $b):
                    $dt = '—';
                    $orderKey = '000000000000';
                    if (preg_match('/_(\d{8})_(\d{6})\.json$/', $b, $m)) {
                      $dtObj = DateTime::createFromFormat('Ymd His', $m[1] . ' ' . $m[2]);
                      if ($dtObj) {
                        $dt = $dtObj->format('d.m.Y H:i:s');
                      }
                      $orderKey = $m[1] . $m[2];
                    }
                    $type = is_server_backup($b) ? 'Server' : (is_user_backup($b) ? 'User' : '—');
                  ?>
                  <tr>
                    <td class="fst-italic"><?= htmlspecialchars($b) ?></td>
                    <td><span class="badge bg-<?= $type === 'Server' ? 'secondary' : 'info' ?>"><?= $type ?></span></td>
                    <td data-order="<?= htmlspecialchars($orderKey) ?>"><?= htmlspecialchars($dt) ?></td>
                    <td class="text-end d-flex justify-content-end gap-2">

                      <a class="btn btn-outline-secondary btn-sm d-inline-flex align-items-center"
                         href="?dl=1&srv=<?= urlencode($firstKey) ?>&file=<?= urlencode($b) ?>">
                        <i class="bi bi-download me-1"></i>Download
                      </a>

                      <form method="post" class="backup-action-form" onsubmit="return true;">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
                        <input type="hidden" name="origin" value="<?= htmlspecialchars($origin) ?>">
                        <input type="hidden" name="file" value="<?= htmlspecialchars($b) ?>">
                        <input type="hidden" name="active_tab" value="#backupsTab">
                        <button name="action" value="backup_diff" class="btn btn-outline-primary btn-sm">
                          <i class="bi bi-eyeglasses me-1"></i>Diff
                        </button>
                      </form>

                      <form method="post" class="backup-action-form"
                            onsubmit="return confirm('Backup <?= htmlspecialchars($b) ?> auf ALLE Server wiederherstellen?');">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
                        <input type="hidden" name="file" value="<?= htmlspecialchars($b) ?>">
                        <input type="hidden" name="active_tab" value="#backupsTab">
                        <button name="action" value="restore_from_backup" class="btn btn-danger btn-sm">
                          <i class="bi bi-arrow-counterclockwise me-1"></i>Restore
                        </button>
                      </form>

                    </td>
                  </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </div>

        <div class="card-footer small text-muted">
          <i class="bi bi-clock-history me-1"></i>
          Dateimuster: <code>server_YYYYMMDD_HHMMSS.json</code> oder <code>user_YYYYMMDD_HHMMSS.json</code>.<br>
          Download via Proxy: <code>?dl=1&amp;srv=&lt;server&gt;&amp;file=&lt;name&gt;</code>.
        </div>
      </div>

      <?php if ($diffData): ?>
        <div class="d-none" id="diffPayload"
             data-file="<?= htmlspecialchars($diffData['file']) ?>"
             data-type="<?= htmlspecialchars($diffData['type']) ?>"
             data-origin="<?= htmlspecialchars($diffData['origin']) ?>"
             data-hashb="<?= htmlspecialchars(short_hash($diffData['hash_backup'])) ?>"
             data-hashc="<?= htmlspecialchars(short_hash($diffData['hash_current'])) ?>">
          <pre id="diffBackupJson"><?= htmlspecialchars($diffData['backupPretty']) ?></pre>
          <pre id="diffCurrentJson"><?= htmlspecialchars($diffData['currentPretty']) ?></pre>
          <script id="diffChanges" type="application/json"><?= json_encode($diffData['changes'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?></script>
        </div>
      <?php endif; ?>

    </div>
  </div>
</div>

<div class="modal fade" id="diffModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header bg-light">
        <h6 class="modal-title">
          <i class="bi bi-eyedropper me-2"></i>
          <span id="diffTitle">Diff</span>
        </h6>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>

      <div class="modal-body">
        <div class="small mb-2 text-muted" id="diffMeta"></div>

        <ul class="nav nav-tabs" role="tablist">
          <li class="nav-item" role="presentation">
            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#diffTabSummary" type="button" role="tab">
              <i class="bi bi-list-check me-1"></i>Aenderungen <span class="badge bg-secondary" id="diffCount">0</span>
            </button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#diffTabBackup" type="button" role="tab">
              <i class="bi bi-file-earmark-text me-1"></i>Backup JSON
            </button>
          </li>
          <li class="nav-item" role="presentation">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#diffTabCurrent" type="button" role="tab">
              <i class="bi bi-file-earmark-text me-1"></i>Current JSON
            </button>
          </li>
        </ul>

        <div class="tab-content pt-3">
          <div class="tab-pane fade show active" id="diffTabSummary" role="tabpanel">
            <div id="diffSummaryContainer"></div>
          </div>
          <div class="tab-pane fade" id="diffTabBackup" role="tabpanel">
            <code class="json" id="diffBackupJsonCode"></code>
          </div>
          <div class="tab-pane fade" id="diffTabCurrent" role="tabpanel">
            <code class="json" id="diffCurrentJsonCode"></code>
          </div>
        </div>
      </div>

      <div class="modal-footer">
        <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">Schliessen</button>
      </div>
    </div>
  </div>
</div>

<script src="assets/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/jquery-3.7.1.js"></script>
<script src="assets/js/jquery.dataTables.min.js"></script>
<script src="assets/js/dataTables.bootstrap5.min.js"></script>

<script>
(function persistTabs(){
  const KEY = 'ar_active_tab';

  const restore = () => {
    const stored = localStorage.getItem(KEY);
    if (!stored) return;
    const trigger = document.querySelector(`[data-bs-toggle="tab"][data-bs-target="${stored}"]`);
    if (trigger) {
      try { new bootstrap.Tab(trigger).show(); } catch (_) {}
    }
  };

  const bind = () => {
    document.querySelectorAll('[data-bs-toggle="tab"]').forEach(el => {
      el.addEventListener('shown.bs.tab', (e) => {
        const target = e.target?.getAttribute('data-bs-target');
        if (target) localStorage.setItem(KEY, target);
      });
    });
  };

  document.querySelectorAll('form').forEach(f => {
    f.addEventListener('submit', () => {
      const tabPane = f.closest('.tab-pane');
      if (tabPane?.id) localStorage.setItem(KEY, '#' + tabPane.id);
    });
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { restore(); bind(); });
  } else {
    restore(); bind();
  }
})();

document.getElementById('originSelect')?.addEventListener('change', (e) => {
  const val = e.target.value;
  document.getElementById('originSelectSync')?.querySelectorAll('option').forEach(o => o.selected = (o.value === val));
  document.getElementById('originSelectBackups')?.querySelectorAll('option').forEach(o => o.selected = (o.value === val));
});

(function initTables(){
  const initDT = (sel, opts = {}) => {
    if (!window.jQuery || !jQuery.fn || !jQuery.fn.DataTable) return;
    if (jQuery.fn.DataTable.isDataTable(sel)) return;

    jQuery(sel).DataTable(Object.assign({
      paging: true,
      pagingType: "first_last_numbers",
      searching: true,
      lengthChange: true,
      info: true,
      order: [[0, 'asc']],
      pageLength: 15,
      lengthMenu: [[10, 15, 25, 50], [10, 15, 25, 50]],
      autoWidth: false,
      responsive: true,
      dom: '<"row mb-2"<"col-md-6"l><"col-md-6"f>>t<"row mt-2"<"col-md-6"i><"col-md-6"p>>'
    }, opts));
  };

  document.addEventListener('DOMContentLoaded', () => {
    initDT('#compareTable', { order: [[0, 'asc'], [1, 'asc']] });
    initDT('#backupsTable', { order: [[2, 'desc']] });
    document.querySelectorAll('[id^="syncResultTable_"]').forEach(t => initDT('#' + t.id));
    initDT('#restoreResultTable');
  });
})();

(function diffModalInit(){
  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
    }[c]));
  }

  function shortJson(v){
    try{
      if (v === null) return 'null';
      if (typeof v === 'boolean' || typeof v === 'number') return String(v);
      if (typeof v === 'string') return `"${v}"`;
      const j = JSON.stringify(v);
      return j.length > 200 ? j.slice(0, 200) + '…' : j;
    }catch(_){
      return String(v);
    }
  }

  function badgeForType(t){
    return t === 'added' ? 'info' : (t === 'removed' ? 'secondary' : 'warning');
  }

  function renderChangesTable(changes){
    if (!changes || !changes.length) {
      return '<div class="alert alert-success mb-0"><i class="bi bi-check2-circle me-1"></i>Keine Unterschiede.</div>';
    }

    const rows = changes.map(chg => {
      const badge = badgeForType(chg.type);
      const from  = (typeof chg.from === 'undefined') ? '' : escapeHtml(shortJson(chg.from));
      const to    = (typeof chg.to   === 'undefined') ? '' : escapeHtml(shortJson(chg.to));
      const path  = escapeHtml(chg.path || '/');

      return `<tr>
        <td><span class="badge bg-${badge}">${escapeHtml(chg.type)}</span></td>
        <td><code>${path}</code></td>
        <td><code>${from}</code></td>
        <td><code>${to}</code></td>
      </tr>`;
    }).join('');

    return `
      <div class="table-responsive table-sticky" style="max-height:50vh;">
        <table class="table table-sm table-hover align-middle mb-0">
          <thead class="table-light"><tr><th>Typ</th><th>Pfad</th><th>Backup</th><th>Current</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  const payload = document.getElementById('diffPayload');
  if (!payload) return;

  const file   = payload.dataset.file || '';
  const type   = payload.dataset.type || '';
  const origin = payload.dataset.origin || '';
  const hb     = payload.dataset.hashb || '';
  const hc     = payload.dataset.hashc || '';

  const changesEl = document.getElementById('diffChanges');
  let changes = [];
  try { changes = JSON.parse(changesEl?.textContent || '[]'); } catch(_) { changes = []; }

  const backupPretty  = document.getElementById('diffBackupJson')?.textContent || '';
  const currentPretty = document.getElementById('diffCurrentJson')?.textContent || '';

  document.getElementById('diffTitle').textContent = `Diff: ${file} vs. ${origin}`;
  document.getElementById('diffMeta').innerHTML =
    `Typ: <code>${(type || '').toUpperCase()}</code> &nbsp;|&nbsp; Backup: <code>${hb}</code> &nbsp;|&nbsp; Current: <code>${hc}</code>`;
  document.getElementById('diffCount').textContent = (changes || []).length;

  document.getElementById('diffSummaryContainer').innerHTML = renderChangesTable(changes);
  document.getElementById('diffBackupJsonCode').textContent  = backupPretty;
  document.getElementById('diffCurrentJsonCode').textContent = currentPretty;

  const modal = new bootstrap.Modal(document.getElementById('diffModal'), { backdrop: 'static' });
  localStorage.setItem('ar_active_tab', '#backupsTab');
  modal.show();
})();
</script>

</body>
</html>
