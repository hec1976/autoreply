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

$successMessage = '';
$errorMessage   = '';
$lastSaveTable  = [];

/*
 * App Konfiguration
 * Erwartet config/config.php mit:
 * - apiToken
 * - servers (Name => BaseURL)
 */
$configApp = include __DIR__ . '/../config/config.php';
$API_TOKEN = $configApp['apiToken'] ?? '';
$SERVERS   = $configApp['servers']  ?? [];

if (!$API_TOKEN || !$SERVERS) {
    http_response_code(500);
    echo "Fehlende Konfiguration (apiToken/servers) in config/config.php.";
    exit;
}

/*
 * array_key_first Fallback (alte PHP Versionen)
 */
if (!function_exists('array_key_first')) {
    function array_key_first(array $a) {
        foreach ($a as $k => $_) {
            return $k;
        }
        return null;
    }
}

$FIRST = array_key_first($SERVERS);

/*
 * Origin ist nur Anzeige und Pull Quelle.
 * Speichern verteilt immer an alle Server.
 */
$origin = $_GET['origin'] ?? $FIRST;
if (!isset($SERVERS[$origin])) {
    $origin = $FIRST;
}
$originBaseUrl = $SERVERS[$origin] ?? '';

/* -------------------------------------------------------------------------
 * HTTP Helpers
 * ------------------------------------------------------------------------- */

function http_get_remote(string $base, string $endpoint, string $token): array
{
    global $configApp;
    
    $ch = curl_init(rtrim($base, '/') . $endpoint);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTPHEADER     => ['X-API-Token: ' . $token],
        CURLOPT_SSL_VERIFYHOST => ($configApp['curl_ssl_verify_host'] ?? false) ? 2 : 0,
        CURLOPT_SSL_VERIFYPEER => $configApp['curl_ssl_verify_peer'] ?? false,
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

function http_post_file_remote(
    string $base,
    string $endpoint,
    string $token,
    string $field,
    string $filename,
    string $content,
    string $mime = 'application/json'
): array {
    global $configApp;
    
    $tmp = tempnam(sys_get_temp_dir(), 'cfg_');
    file_put_contents($tmp, $content);

    $cfile = new CURLFile($tmp, $mime, $filename);
    $ch = curl_init(rtrim($base, '/') . $endpoint);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => ['X-API-Token: ' . $token],
        CURLOPT_SSL_VERIFYHOST => ($configApp['curl_ssl_verify_host'] ?? false) ? 2 : 0,
        CURLOPT_SSL_VERIFYPEER => $configApp['curl_ssl_verify_peer'] ?? false,
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

function json_try_decode_array(string $s): ?array
{
    $d = json_decode($s, true);
    return (json_last_error() === JSON_ERROR_NONE && is_array($d)) ? $d : null;
}

function send_json(array $payload, int $status = 200): void
{
    if (!headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
    }
    http_response_code($status);
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function validate_csrf(array $data): void
{
    $token = $data['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        send_json(['success' => false, 'error' => 'Ungueltiges CSRF-Token'], 403);
    }
}

function badge_http_class(int $code): string
{
    if ($code >= 200 && $code < 300) return 'success';
    if ($code >= 300 && $code < 400) return 'info';
    if ($code >= 400 && $code < 500) return 'warning';
    if ($code >= 500) return 'danger';
    return 'secondary';
}

function truncate_middle(string $s, int $max = 160): string
{
    $s   = trim($s);
    $len = mb_strlen($s);

    if ($len <= $max) {
        return $s;
    }

    $half = intdiv($max - 1, 2);
    return mb_substr($s, 0, $half) . '…' . mb_substr($s, -$half);
}

/* -------------------------------------------------------------------------
 * API Requests (POST, ?api=...)
 * ------------------------------------------------------------------------- */

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['api'])) {
    while (ob_get_level()) ob_end_clean();

    $raw = file_get_contents('php://input');
    $payload = json_decode($raw, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        send_json(['success' => false, 'error' => 'Ungueltige JSON-Daten'], 400);
    }
    validate_csrf($payload);

    $servers = $SERVERS;
    $token   = $API_TOKEN;

    // Der Origin ist nur fuer den Passwort-Merge relevant
    $originName = $GLOBALS['origin'];

    // Speichern verteilt immer an alle Server
    $targetsEff = array_keys($servers);

    $push = function (string $endpoint, string $filename, string $content, array $targets) use ($servers, $token): array {
        $out = [];
        foreach ($targets as $name) {
            $base = $servers[$name] ?? null;
            if (!$base) continue;
            $out[$name] = http_post_file_remote($base, $endpoint, $token, 'config', $filename, $content);
        }
        return $out;
    };

    switch ($_GET['api']) {

        case 'save_server_config': {
            // Aktuelle Server Config nur vom Origin holen, damit Passwort bei leerem Input beibehalten wird
            $existing = [];
            if (!empty($servers[$originName])) {
                $pull = http_get_remote($servers[$originName], '/autoreply/server/config', $token);
                if ($pull['ok']) {
                    $tmp = json_decode((string)$pull['body'], true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($tmp)) {
                        $existing = $tmp;
                    }
                }
            }

            $cfg = [
                'SMTP'             => (string)$payload['SMTP'],
                'port'             => (int)$payload['port'],
                'ssl'              => (bool)($payload['ssl'] ?? false),
                'starttls'         => (bool)($payload['starttls'] ?? false),
                'smtpauth'         => (bool)($payload['smtpauth'] ?? false),
                'username'         => (string)($payload['username'] ?? ''),
                'logging'          => (bool)($payload['logging'] ?? false),
                'integration_mode' => (string)$payload['integration_mode'],
                'autoreply_checks' => (array)($payload['autoreply_checks'] ?? []),
            ];

            if (array_key_exists('password', $payload) && $payload['password'] !== '') {
                $cfg['password'] = (string)$payload['password'];
            } elseif (isset($existing['password']) && $existing['password'] !== '') {
                $cfg['password'] = (string)$existing['password'];
            }

            $json = json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $res  = $push('/autoreply/server/config', 'autoreply_server.json', $json, $targetsEff);

            $ok  = array_sum(array_map(fn($r) => !empty($r['ok']) ? 1 : 0, $res));
            $tot = count($res);

            $_SESSION['lastSaveResults'] = [
                'headline' => 'Server-Konfiguration an alle Server verteilt',
                'summary'  => "$ok / $tot OK",
                'rows'     => array_map(function ($name, $r) {
                    return [
                        'server' => $name,
                        'ok'     => !empty($r['ok']),
                        'status' => (int)($r['status'] ?? 0),
                        'body'   => truncate_middle((string)($r['body'] ?? ''), 300),
                    ];
                }, array_keys($res), array_values($res)),
            ];

            if ($ok === $tot) $_SESSION['successMessage'] = 'Server-Konfiguration erfolgreich verteilt.';
            else              $_SESSION['errorMessage']   = 'Server-Konfiguration: Es gab Fehler beim Verteilen.';

            send_json(['success' => true, 'message' => 'Server-Konfiguration gespeichert & an alle verteilt']);
        }

        case 'save_user_config': {
            $data = (array)($payload['data'] ?? []);
            $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $res  = $push('/autoreply/user/config', 'autoreply_user.json', $json, $targetsEff);

            $ok  = array_sum(array_map(fn($r) => !empty($r['ok']) ? 1 : 0, $res));
            $tot = count($res);

            $_SESSION['lastSaveResults'] = [
                'headline' => 'User-Konfiguration an alle Server verteilt',
                'summary'  => "$ok / $tot OK",
                'rows'     => array_map(function ($name, $r) {
                    return [
                        'server' => $name,
                        'ok'     => !empty($r['ok']),
                        'status' => (int)($r['status'] ?? 0),
                        'body'   => truncate_middle((string)($r['body'] ?? ''), 300),
                    ];
                }, array_keys($res), array_values($res)),
            ];

            if ($ok === $tot) $_SESSION['successMessage'] = 'User-Konfiguration erfolgreich verteilt.';
            else              $_SESSION['errorMessage']   = 'User-Konfiguration: Es gab Fehler beim Verteilen.';

            send_json(['success' => true, 'message' => 'User-Konfiguration gespeichert & an alle verteilt']);
        }

        default:
            send_json(['success' => false, 'error' => 'Unbekannte API'], 400);
    }
}

/* -------------------------------------------------------------------------
 * Anzeige: Remote laden (nur Origin)
 * ------------------------------------------------------------------------- */

$serverConfig = [];
$userConfig   = ['autoreply' => [], 'blacklist' => [], 'filters' => []];

$r1 = http_get_remote($SERVERS[$origin], '/autoreply/server/config', $API_TOKEN);
if ($r1['ok'] && ($a = json_try_decode_array((string)$r1['body']))) {
    $serverConfig = $a;
}

$r2 = http_get_remote($SERVERS[$origin], '/autoreply/user/config', $API_TOKEN);
if ($r2['ok'] && ($b = json_try_decode_array((string)$r2['body']))) {
    $userConfig = $b;
}

// Defaults, damit UI stabil bleibt, auch wenn Felder in alten Configs fehlen
foreach ($userConfig['autoreply'] as &$e) {
    if (!isset($e['max_replies_per_sender'])) $e['max_replies_per_sender'] = 5;
    if (!isset($e['reply_period_hours']))     $e['reply_period_hours'] = 1;
    if (!isset($e['html']))                   $e['html'] = false;
    if (!isset($e['body']))                   $e['body'] = '';
}
unset($e);

// Flash Messages aus Session
$successMessage = $_SESSION['successMessage'] ?? '';
unset($_SESSION['successMessage']);

$errorMessage = $_SESSION['errorMessage'] ?? '';
unset($_SESSION['errorMessage']);

if (!empty($_SESSION['lastSaveResults']) && is_array($_SESSION['lastSaveResults'])) {
    $lastSaveTable = $_SESSION['lastSaveResults'];
    unset($_SESSION['lastSaveResults']);
}

ob_end_flush();
?>
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <title>Autoresponder Console</title>

  <link href="assets/css/bootstrap.min.css" rel="stylesheet">
  <link href="assets/css/bootstrap-icons.css" rel="stylesheet">
  <link href="assets/css/dataTables.bootstrap5.min.css" rel="stylesheet">
  <link href="assets/css/styles.css" rel="stylesheet">

  <script>
    const CSRF_TOKEN      = '<?= htmlspecialchars($csrf) ?>';
    const ORIGIN          = '<?= htmlspecialchars($origin) ?>';
    const ORIGIN_BASE_URL = '<?= htmlspecialchars($originBaseUrl) ?>';
  </script>

  <script src="assets/js/ckeditor.js"></script>

  <style>
    .spin { display:inline-block; animation:spin 1s linear infinite; }
    @keyframes spin { 100% { transform: rotate(360deg); } }

    pre.api { white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Courier New", monospace; }

    .mini-bar { background:#f8f9fa; border:1px solid #e9ecef; border-radius:10px; padding:.25rem .5rem; }
    .mini-bar .form-select-sm { padding-top:.15rem; padding-bottom:.15rem; }
    .mini-vr { width:1px; align-self:stretch; background:#e9ecef; margin:0 .35rem; }
    .badge-pill { border-radius: 999px; }
    .textarea-auto { resize: vertical; }

    /* Modal Scroll: Body scrollbar, Header und Footer bleiben fix */
    #editModal .modal-body {
      max-height: calc(100vh - 12rem);
      overflow-y: auto;
    }
    #editModal .tab-pane { padding-top: .25rem; }

    /* CKEditor in scrollbaren Containern */
    #editModal .ck-editor__editable[role="textbox"] {
      min-height: 260px;
      max-height: 60vh;
      overflow-y: auto;
    }

    #editModal #fieldBody {
      min-height: 180px;
      max-height: 60vh;
      overflow-y: auto;
      resize: vertical;
    }

    .ck-balloon-panel { z-index: 20000 !important; }

    /* Links im CKEditor sichtbar machen */
    #editModal .ck-content a,
    #fieldHtmlEditor .ck-content a {
      color: var(--bs-link-color) !important;
      text-decoration: underline !important;
    }
    #editModal .ck-content a:hover,
    #fieldHtmlEditor .ck-content a:hover {
      text-decoration: underline !important;
      filter: brightness(0.9);
    }
  </style>
</head>

<body>
<?php @include __DIR__ . '/includes/navigation.php'; ?>
<?php @include __DIR__ . '/includes/sidebar.php'; ?>

<div class="container mt-4" style="margin-left:270px;">
  <div class="d-flex align-items-center justify-content-between mb-2">
    <h2 class="mb-4">Autoreply Verwaltung</h2>
  </div>

  <?php if (!empty($successMessage)): ?>
    <div class="alert alert-success alert-dismissible fade show" role="alert" id="autoDismissAlert">
      <div class="d-flex align-items-center gap-2">
        <i class="bi bi-check-circle"></i>
        <div><?= nl2br(htmlspecialchars($successMessage)) ?></div>
      </div>
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
    <script>
      setTimeout(() => {
        try { new bootstrap.Alert(document.getElementById('autoDismissAlert')).close(); } catch(e) {}
      }, 5000);
    </script>
  <?php endif; ?>

  <?php if (!empty($errorMessage)): ?>
    <div class="alert alert-danger alert-dismissible fade show" role="alert" id="autoDismissAlert2">
      <div class="d-flex align-items-center gap-2">
        <i class="bi bi-x-octagon"></i>
        <div><?= nl2br(htmlspecialchars($errorMessage)) ?></div>
      </div>
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
    <script>
      setTimeout(() => {
        try { new bootstrap.Alert(document.getElementById('autoDismissAlert2')).close(); } catch(e) {}
      }, 7000);
    </script>
  <?php endif; ?>

  <?php if (!empty($lastSaveTable)): ?>
    <div class="card border-0 shadow-sm mb-3">
      <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <div class="d-flex align-items-center gap-2">
          <i class="bi bi-send-check"></i>
          <span class="fw-semibold"><?= htmlspecialchars($lastSaveTable['headline'] ?? 'Verteilung') ?></span>
          <span class="badge text-bg-secondary ms-2"><?= htmlspecialchars($lastSaveTable['summary'] ?? '') ?></span>
        </div>
        <button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#saveResultsTable">
          Details anzeigen
        </button>
      </div>

      <div id="saveResultsTable" class="collapse show">
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
              <thead class="table-light">
                <tr>
                  <th>Server</th>
                  <th>Status</th>
                  <th>HTTP</th>
                  <th>Antwort (gekuerzt)</th>
                </tr>
              </thead>
              <tbody>
              <?php foreach (($lastSaveTable['rows'] ?? []) as $row): ?>
                <?php $cls = badge_http_class((int)$row['status']); ?>
                <tr class="<?= !empty($row['ok']) ? '' : 'table-danger' ?>">
                  <td class="fw-medium"><?= htmlspecialchars($row['server']) ?></td>
                  <td>
                    <span class="badge badge-pill text-bg-<?= !empty($row['ok']) ? 'success' : 'danger' ?>">
                      <?= !empty($row['ok']) ? 'OK' : 'Fehler' ?>
                    </span>
                  </td>
                  <td><span class="badge text-bg-<?= $cls ?>"><?= (int)$row['status'] ?></span></td>
                  <td><pre class="api mb-0"><?= htmlspecialchars((string)$row['body']) ?></pre></td>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  <?php endif; ?>

  <div class="mini-bar d-flex align-items-center flex-wrap gap-2 small mb-2">
    <i class="bi bi-cloud-arrow-down"></i>
    <span class="fw-semibold">Anzeige und Pull Quelle</span>
    <span class="badge text-bg-success"><?= htmlspecialchars($origin) ?></span>
    <span class="text-muted">(<?= htmlspecialchars($originBaseUrl) ?>)</span>

    <span class="mini-vr"></span>

    <label class="m-0">Origin:</label>
    <select id="originSelect" class="form-select form-select-sm w-auto"
            onchange="location.search='?origin='+encodeURIComponent(this.value)">
      <?php foreach ($SERVERS as $name => $url): ?>
        <option value="<?= htmlspecialchars($name) ?>" <?= $name === $origin ? 'selected' : '' ?>>
          <?= htmlspecialchars($name) ?>
        </option>
      <?php endforeach; ?>
    </select>

    <span class="mini-vr"></span>

    <span class="text-muted">
      <i class="bi bi-broadcast-pin me-1"></i>
      <b>Wichtig:</b> Speichern verteilt immer an <b>alle</b> Server.
    </span>
  </div>

  <ul class="nav nav-tabs" id="tabs" role="tablist">
    <li class="nav-item" role="presentation">
      <button class="nav-link active" id="users-tab" data-bs-toggle="tab" data-bs-target="#usersTab" type="button" role="tab">
        <i class="bi bi-envelope-paper me-1"></i>Autoreply Eintraege
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="filters-tab" data-bs-toggle="tab" data-bs-target="#filtersTab" type="button" role="tab">
        <i class="bi bi-slash-circle me-1"></i>Blacklist & Filter
      </button>
    </li>
    <li class="nav-item" role="presentation">
      <button class="nav-link" id="server-tab" data-bs-toggle="tab" data-bs-target="#serverTab" type="button" role="tab">
        <i class="bi bi-gear me-1"></i>Server Konfiguration
      </button>
    </li>
  </ul>

  <div class="tab-content pt-3">
    <div class="tab-pane fade show active" id="usersTab" role="tabpanel">
      <div class="card shadow-sm rounded-3">
        <div class="card-header bg-light d-flex justify-content-between align-items-center">
          <div class="d-flex align-items-center">
            <i class="bi bi-people me-2"></i>
            <span class="fw-semibold">Autoreply Liste (Anzeige von <?= htmlspecialchars($origin) ?>)</span>
          </div>
          <button class="btn btn-secondary btn-sm d-inline-flex align-items-center" onclick="openModal()">
            <i class="bi bi-plus-lg me-1"></i> Neuer Eintrag
          </button>
        </div>

        <div class="card-body p-3">
          <div class="table-responsive rounded-2">
            <table id="autoreplyTable" class="table table-hover align-middle mb-0" style="width:100%">
              <thead class="table-light">
              <tr>
                <th>Adresse</th>
                <th>From</th>
                <th>Subject</th>
                <th>HTML</th>
                <th class="text-end">Aktion</th>
              </tr>
              </thead>
              <tbody>
              <?php foreach ($userConfig['autoreply'] as $i => $e):
                  $addressVal = $e['email'] ?? ($e['domain'] ?? '');

                  if (is_array($addressVal)) {
                      $address = implode("\n", array_filter($addressVal, fn($x) => $x !== null && $x !== ''));
                  } else {
                      $address = (string)$addressVal;
                  }

                  $isHtml = !empty($e['html']);
              ?>
                <tr data-idx="<?= (int)$i ?>">
                  <td><?= nl2br(htmlspecialchars($address)) ?></td>
                  <td><?= htmlspecialchars($e['from'] ?? '') ?></td>
                  <td><?= htmlspecialchars($e['subject'] ?? '') ?></td>
                  <td><?= $isHtml ? '<span class="badge text-bg-success">Ja</span>' : '<span class="badge text-bg-secondary">Nein</span>' ?></td>
                  <td class="text-end">
                    <div class="d-inline-flex align-items-center gap-2">
                      <button type="button" class="btn btn-outline-success btn-sm" onclick="openModal(<?= (int)$i ?>)" data-bs-toggle="tooltip" data-bs-title="Bearbeiten">
                        <i class="bi bi-pencil"></i>
                      </button>
                      <button type="button" class="btn btn-outline-danger btn-sm" onclick="deleteEntry(<?= (int)$i ?>)" data-bs-toggle="tooltip" data-bs-title="Loeschen">
                        <i class="bi bi-trash"></i>
                      </button>
                    </div>
                  </td>
                </tr>
              <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>

        <div class="card-footer small text-muted">
          <i class="bi bi-info-circle me-1"></i> Tipp: Doppelklick auf eine Zeile oeffnet die Bearbeitung.
        </div>
      </div>
    </div>

    <div class="tab-pane fade" id="filtersTab" role="tabpanel">
      <form id="filterForm" class="mb-3">
        <div class="card shadow-sm border-1">
          <div class="card-header bg-body-tertiary d-flex align-items-center justify-content-between">
            <div class="d-flex align-items-center">
              <i class="bi bi-funnel me-2"></i>
              <span class="fw-semibold">Globale Filter &amp; Blacklist</span>
            </div>
          </div>

          <div class="card-body pb-0">
            <div class="row g-3">
              <div class="col-12">
                <label for="blacklistArea" class="form-label fw-semibold d-flex align-items-center">
                  <i class="bi bi-slash-circle me-2"></i>Globale Blacklist
                </label>
                <textarea class="form-control form-control-sm font-monospace textarea-auto"
                          id="blacklistArea" rows="4"
                          placeholder="Eine Adresse pro Zeile"><?= htmlspecialchars(implode("\n", $userConfig['blacklist'] ?? [])) ?></textarea>
                <div class="form-text">Eine Adresse pro Zeile eintragen.</div>
              </div>

              <hr class="mt-2">

              <div class="col-12">
                <h6 class="fw-bold mb-2 d-flex align-items-center">
                  <i class="bi bi-diagram-3 me-2"></i>Globale Filter
                </h6>
              </div>

              <div class="col-12 col-md-6">
                <label class="form-label d-flex align-items-center" for="f_headerblock_subject">
                  <code class="me-2">header_block.Subject</code>
                </label>
                <textarea class="form-control form-control-sm font-monospace textarea-auto"
                          id="f_headerblock_subject" rows="4" placeholder="Ein Regex pro Zeile"><?= isset($userConfig['filters']['header_block']['Subject']) ? htmlspecialchars(implode("\n", $userConfig['filters']['header_block']['Subject'])) : '' ?></textarea>
              </div>

              <div class="col-12 col-md-6">
                <label class="form-label d-flex align-items-center" for="f_headerblock_listid">
                  <code class="me-2">header_block.List-Id</code>
                </label>
                <textarea class="form-control form-control-sm font-monospace textarea-auto"
                          id="f_headerblock_listid" rows="4" placeholder="Ein Regex pro Zeile"><?= isset($userConfig['filters']['header_block']['List-Id']) ? htmlspecialchars(implode("\n", $userConfig['filters']['header_block']['List-Id'])) : '' ?></textarea>
              </div>

              <div class="col-12 col-md-6">
                <label class="form-label d-flex align-items-center" for="f_headerallow">
                  <code class="me-2">header_allow</code>
                </label>
                <textarea class="form-control form-control-sm font-monospace textarea-auto"
                          id="f_headerallow" rows="4" placeholder="Ein Regex pro Zeile"><?= isset($userConfig['filters']['header_allow']) ? htmlspecialchars(implode("\n", $userConfig['filters']['header_allow'])) : '' ?></textarea>
              </div>

              <div class="col-12 col-md-6">
                <label class="form-label d-flex align-items-center" for="f_bodyblock">
                  <code class="me-2">body_block</code>
                </label>
                <textarea class="form-control form-control-sm font-monospace textarea-auto"
                          id="f_bodyblock" rows="4" placeholder="Ein Regex pro Zeile"><?= isset($userConfig['filters']['body_block']) ? htmlspecialchars(implode("\n", $userConfig['filters']['body_block'])) : '' ?></textarea>
              </div>

              <div class="col-12 col-md-6">
                <label class="form-label d-flex align-items-center" for="f_bodyallow">
                  <code class="me-2">body_allow</code>
                </label>
                <textarea class="form-control form-control-sm font-monospace textarea-auto"
                          id="f_bodyallow" rows="4" placeholder="Ein Regex pro Zeile"><?= isset($userConfig['filters']['body_allow']) ? htmlspecialchars(implode("\n", $userConfig['filters']['body_allow'])) : '' ?></textarea>
              </div>
            </div>
          </div>

          <br>

          <div class="card-footer d-flex align-items-center justify-content-between bg-body-tertiary">
            <span id="filterStatus" class="me-3 small text-body-secondary"></span>
            <button type="submit" class="btn btn-secondary btn-sm d-inline-flex align-items-center">
              <i class="bi bi-save me-1"></i>Speichern (an alle Server)
            </button>
          </div>
        </div>
      </form>
    </div>

    <div class="tab-pane fade" id="serverTab" role="tabpanel">
      <form id="serverConfigForm" class="mb-3">
        <div class="card">
          <div class="card-header bg-light d-flex align-items-center">
            <i class="bi bi-hdd-network me-2"></i>
            <span class="fw-semibold">Server Konfiguration (Anzeige von <?= htmlspecialchars($origin) ?>)</span>
          </div>

          <div class="card-body">
            <div class="row g-3 mb-3">
              <div class="col-md-6">
                <label class="form-label" for="serverSMTP">SMTP Server</label>
                <div class="input-group">
                  <span class="input-group-text"><i class="bi bi-envelope-at"></i></span>
                  <input type="text" class="form-control" id="serverSMTP" value="<?= htmlspecialchars($serverConfig['SMTP'] ?? 'localhost') ?>" required>
                </div>
              </div>

              <div class="col-md-6">
                <label class="form-label" for="serverPort">Port</label>
                <div class="input-group">
                  <span class="input-group-text"><i class="bi bi-plug"></i></span>
                  <input type="number" class="form-control" id="serverPort" value="<?= htmlspecialchars((string)($serverConfig['port'] ?? 25)) ?>" required>
                </div>
              </div>
            </div>

            <h6 class="fw-bold mt-2 mb-2"><i class="bi bi-shield-lock me-1"></i>Transport &amp; Auth</h6>
            <div class="row mb-3">
              <div class="col-md-4">
                <div class="form-check form-switch">
                  <input class="form-check-input" type="checkbox" id="serverSSL" <?= !empty($serverConfig['ssl']) ? 'checked' : '' ?>>
                  <label class="form-check-label" for="serverSSL">SSL</label>
                </div>
              </div>
              <div class="col-md-4">
                <div class="form-check form-switch">
                  <input class="form-check-input" type="checkbox" id="serverSTARTTLS" <?= !empty($serverConfig['starttls']) ? 'checked' : '' ?>>
                  <label class="form-check-label" for="serverSTARTTLS">STARTTLS</label>
                </div>
              </div>
              <div class="col-md-4">
                <div class="form-check form-switch">
                  <input class="form-check-input" type="checkbox" id="serverSMTPAuth" <?= !empty($serverConfig['smtpauth']) ? 'checked' : '' ?>>
                  <label class="form-check-label" for="serverSMTPAuth">SMTP Auth</label>
                </div>
              </div>
            </div>

            <div class="row g-3 mb-3">
              <div class="col-md-6">
                <label class="form-label" for="serverUsername">SMTP Username</label>
                <div class="input-group">
                  <span class="input-group-text"><i class="bi bi-person"></i></span>
                  <input type="text" class="form-control" id="serverUsername" autocomplete="new-username" value="<?= htmlspecialchars($serverConfig['username'] ?? '') ?>">
                </div>
              </div>

              <div class="col-md-6">
                <label class="form-label" for="serverPassword">SMTP Passwort</label>
                <div class="input-group">
                  <span class="input-group-text"><i class="bi bi-key"></i></span>
                  <input type="password" class="form-control" id="serverPassword" autocomplete="new-password" value="">
                </div>
                <div class="form-text">Leer lassen, um das gespeicherte Passwort nicht zu aendern.</div>
              </div>
            </div>

            <div class="mb-3">
              <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="serverLogging" <?= !empty($serverConfig['logging']) ? 'checked' : '' ?>>
                <label class="form-check-label" for="serverLogging">Logging aktivieren</label>
              </div>
            </div>

            <div class="mb-3">
              <label class="form-label" for="serverIntegrationMode"><i class="bi bi-diagram-3 me-1"></i>Integration Mode</label>
              <select class="form-select" id="serverIntegrationMode">
                <?php $im = $serverConfig['integration_mode'] ?? 'bcc'; ?>
                <option value="bcc" <?= $im === 'bcc' ? 'selected' : '' ?>>BCC</option>
                <option value="direct" <?= $im === 'direct' ? 'selected' : '' ?>>Direct</option>
              </select>
            </div>

            <h6 class="fw-bold mt-4 mb-2"><i class="bi bi-check2-square me-1"></i>Autoreply Checks</h6>
            <?php $ac = $serverConfig['autoreply_checks'] ?? []; $on = fn($k) => !empty($ac[$k]) ? 'checked' : ''; ?>
            <div class="row">
              <div class="col-md-6">
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkAutoSubmitted" <?= $on('auto_submitted') ?>><label class="form-check-label" for="checkAutoSubmitted">Auto-Submitted</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkXAutoResponseSuppress" <?= $on('x_auto_response_suppress') ?>><label class="form-check-label" for="checkXAutoResponseSuppress">X-Auto-Response-Suppress</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkListHeaders" <?= $on('list_headers') ?>><label class="form-check-label" for="checkListHeaders">List Headers</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkFeedbackId" <?= $on('feedback_id') ?>><label class="form-check-label" for="checkFeedbackId">Feedback-ID</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkPrecedence" <?= $on('precedence') ?>><label class="form-check-label" for="checkPrecedence">Precedence</label></div>
              </div>

              <div class="col-md-6">
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkXAutoreply" <?= $on('x_autoreply') ?>><label class="form-check-label" for="checkXAutoreply">X-Autoreply</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkEmptyEnvelopeFrom" <?= $on('empty_envelope_from') ?>><label class="form-check-label" for="checkEmptyEnvelopeFrom">Empty Envelope From</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkSystemFrom" <?= $on('system_from') ?>><label class="form-check-label" for="checkSystemFrom">System From</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkSystemReplyTo" <?= $on('system_replyto') ?>><label class="form-check-label" for="checkSystemReplyTo">System Reply-To</label></div>
                <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="checkNoReply" <?= $on('noreply') ?>><label class="form-check-label" for="checkNoReply">No-Reply</label></div>
              </div>
            </div>
          </div>

          <div class="card-footer d-flex align-items-center">
            <button type="submit" class="btn btn-secondary btn-sm d-inline-flex align-items-center">
              <i class="bi bi-save me-1"></i>Speichern (an alle Server)
            </button>
            <span id="serverConfigStatus" class="ms-3 small"></span>
          </div>
        </div>
      </form>
    </div>
  </div>
</div>

<div class="modal fade" id="editModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <form id="entryForm">
        <div class="modal-header bg-light">
          <h6 class="modal-title" id="modalTitle">Eintrag bearbeiten</h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Schliessen"></button>
        </div>

        <div class="modal-body">
          <input type="hidden" id="entryIndex">

          <ul class="nav nav-tabs small" id="editInnerTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="rule-tab" data-bs-toggle="tab" data-bs-target="#tab-rule"
                      type="button" role="tab" aria-controls="tab-rule" aria-selected="true">
                Regel, gueltig fuer
              </button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="mail-tab" data-bs-toggle="tab" data-bs-target="#tab-mail"
                      type="button" role="tab" aria-controls="tab-mail" aria-selected="false">
                Autoresponder Mail
              </button>
            </li>
          </ul>

          <div class="tab-content pt-3">
            <div class="tab-pane fade show active" id="tab-rule" role="tabpanel" aria-labelledby="rule-tab">
              <div class="row">
                <div class="col-md-6 mb-2">
                  <label class="form-label">Typ</label>
                  <select class="form-select" id="addressType">
                    <option value="email">E-Mail</option>
                    <option value="domain">Domain</option>
                  </select>
                </div>

                <div class="col-md-6 mb-2">
                  <label class="form-label" id="addressLabel">E-Mail</label>
                  <textarea class="form-control" id="fieldAddress" rows="4" required></textarea>
                  <div class="form-text" id="addressHint">Eine Adresse pro Zeile oder mit Komma getrennt</div>
                </div>
              </div>
            </div>

            <div class="tab-pane fade" id="tab-mail" role="tabpanel" aria-labelledby="mail-tab">
              <div class="row">
                <div class="col-md-6 mb-2">
                  <label class="form-label">From</label>
                  <input type="text" class="form-control" id="fieldFrom">
                </div>
                <div class="col-md-6 mb-2">
                  <label class="form-label">Reply-To</label>
                  <input type="text" class="form-control" id="fieldReplyTo">
                </div>
              </div>

              <div class="mb-2">
                <label class="form-label">Subject</label>
                <input type="text" class="form-control" id="fieldSubject">
                <small class="text-muted d-block mt-1">
                  Platzhalter:
                  <code>{ORIGINAL_SUBJECT}</code>
                  <code>{ORIGINAL_SENDER}</code>
                  <code>{ORIGINAL_DESTINATION}</code>
                  <code>{ORIGINAL_DATE}</code>
                  <code>{ORIGINAL_BODY}</code>
                </small>
              </div>

              <div class="mb-2">
                <label class="form-label">HTML?</label>
                <select id="fieldHtml" class="form-select">
                  <option value="false">nein</option>
                  <option value="true">ja</option>
                </select>
              </div>

              <div class="mb-2" id="bodyGroup">
                <label class="form-label">Body (Text)</label>
                <textarea class="form-control" id="fieldBody" rows="4"></textarea>
              </div>

              <div class="mb-2 d-none" id="htmlEditorGroup">
                <label class="form-label">HTML-Inhalt</label>
                <div id="fieldHtmlEditor"></div>
                <textarea id="fieldHtmlBody" hidden></textarea>
              </div>

              <div class="mb-2">
                <label class="form-label">Blacklist (Kommagetrennt)</label>
                <input class="form-control" id="fieldBlacklist">
              </div>

              <div class="row">
                <div class="col-md-6 mb-2">
                  <label class="form-label">max_replies_per_sender</label>
                  <input type="number" class="form-control" id="fieldMaxReplies" min="1" value="5">
                </div>
                <div class="col-md-6 mb-2">
                  <label class="form-label">reply_period_hours</label>
                  <input type="number" class="form-control" id="fieldReplyHours" min="1" value="1">
                </div>
              </div>

              <div class="mb-2">
                <label class="form-label">Kommentar</label>
                <input type="text" class="form-control" id="fieldComment">
              </div>
            </div>
          </div>
        </div>

        <div class="modal-footer">
          <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">Abbrechen</button>
          <button type="submit" class="btn btn-secondary btn-sm"><i class="bi bi-save"></i> Speichern</button>
        </div>
      </form>
    </div>
  </div>
</div>

<script src="assets/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/jquery-3.7.1.js"></script>
<script src="assets/js/jquery.dataTables.min.js"></script>
<script src="assets/js/dataTables.bootstrap5.min.js"></script>

<script>
/* global $, bootstrap, ClassicEditor, CSRF_TOKEN */
let entries = <?= json_encode($userConfig['autoreply'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;

let modal = null;
let htmlEditor = null;

/* Aktiver Haupttab merken */
document.addEventListener('DOMContentLoaded', () => {
  const saved = sessionStorage.getItem('activeTab');
  if (saved) {
    const t = document.querySelector(`button[data-bs-target="${saved}"]`);
    if (t) new bootstrap.Tab(t).show();
  }
  document.querySelectorAll('button[data-bs-toggle="tab"]').forEach(btn => {
    btn.addEventListener('shown.bs.tab', (e) => {
      sessionStorage.setItem('activeTab', e.target.getAttribute('data-bs-target'));
    });
  });
});

/* Toast UI */
function ensureToastContainer(){
  if (!document.getElementById('toastContainer')){
    const div = document.createElement('div');
    div.id = 'toastContainer';
    div.className = 'toast-container position-fixed top-0 end-0 p-3';
    div.style.zIndex = 1080;
    document.body.appendChild(div);
  }
}
function toastIcon(type){
  return {success:'check-circle',warning:'exclamation-triangle',danger:'x-octagon',info:'info-circle'}[type] || 'info-circle';
}
function showAlert(type, message, delayMs=4000){
  ensureToastContainer();
  const t = document.createElement('div');
  t.className = 'toast align-items-center border-0 show';
  t.role='alert'; t.ariaLive='assertive'; t.ariaAtomic='true';
  t.innerHTML = `<div class="toast-body d-flex align-items-start gap-2">
      <i class="bi bi-${toastIcon(type)} me-1 text-${type}"></i>
      <div>${message}</div>
      <button type="button" class="btn-close ms-auto" data-bs-dismiss="toast"></button>
    </div>`;
  document.getElementById('toastContainer').appendChild(t);
  new bootstrap.Toast(t, {delay: delayMs, autohide: true}).show();
}

/* CKEditor */
async function ensureHtmlEditor(){
  if (htmlEditor){
    const elCheck = document.getElementById('fieldHtmlEditor');
    if (!elCheck || !htmlEditor.ui || !htmlEditor.ui.view || !htmlEditor.ui.view.element){
      try { await htmlEditor.destroy(); } catch(_) {}
      htmlEditor = null;
    } else {
      return htmlEditor;
    }
  }

  const el = document.getElementById('fieldHtmlEditor');
  if (!el || typeof ClassicEditor === 'undefined') return null;

  try{
    htmlEditor = await ClassicEditor.create(el,{
      toolbar:[
        'undo','redo','|',
        'heading','|',
        'bold','italic','underline','strikethrough','|',
        'bulletedList','numberedList','blockQuote','|',
        'link','insertTable','mediaEmbed','|',
        'codeBlock','removeFormat','alignment'
      ],
      link: { addTargetToExternalLinks:true, defaultProtocol:'https://' },
      table:{ contentToolbar:['tableColumn','tableRow','mergeTableCells'] }
    });
    return htmlEditor;
  }catch(e){
    console.error('CKEditor Init failed:', e);
    showAlert('warning','HTML-Editor konnte nicht initialisiert werden.');
    return null;
  }
}
function destroyHtmlEditor(){
  if (htmlEditor){
    htmlEditor.destroy().catch(()=>{});
    htmlEditor = null;
  }
}
async function toggleFields(){
  const isHtml = (document.getElementById('fieldHtml')?.value === 'true');
  document.getElementById('bodyGroup')?.classList.toggle('d-none', isHtml);
  document.getElementById('htmlEditorGroup')?.classList.toggle('d-none', !isHtml);
  if (isHtml) await ensureHtmlEditor(); else destroyHtmlEditor();
}

/* Multi Address Helpers */
function parseMultiAddress(raw){
  return (raw || '')
    .trim()
    .split(/[\n,;]+/)
    .map(s => s.trim())
    .filter(Boolean);
}
function addressToText(v){
  if (Array.isArray(v)) return v.join('\n');
  if (v === null || v === undefined) return '';
  return String(v);
}
function isValidEmail(s){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}
function isValidDomain(s){
  s = (s || '').trim();
  return /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(s) && !s.includes('..');
}

/* Modal */
async function openModal(idx){
  const modalEl = document.getElementById('editModal');
  modal = new bootstrap.Modal(modalEl, { backdrop:'static', keyboard:false, focus:false });

  const form = document.getElementById('entryForm');
  form.reset();

  document.getElementById('addressType').value = 'email';
  document.getElementById('fieldBlacklist').value = '';
  document.getElementById('entryIndex').value = '';

  if (idx !== undefined && entries[idx]){
    const e = entries[idx];

    if (e.email){
      document.getElementById('addressType').value = 'email';
      document.getElementById('fieldAddress').value = addressToText(e.email);
    } else {
      document.getElementById('addressType').value = 'domain';
      document.getElementById('fieldAddress').value = addressToText(e.domain || []);
    }

    document.getElementById('fieldFrom').value      = e.from || '';
    document.getElementById('fieldReplyTo').value   = e['reply-to'] || '';
    document.getElementById('fieldSubject').value   = e.subject || '';
    document.getElementById('fieldHtml').value      = e.html ? 'true' : 'false';

    await toggleFields();

    if (e.html){
      const ed = await ensureHtmlEditor();
      if (ed) ed.setData(e.body || '');
    } else {
      document.getElementById('fieldBody').value = e.body || '';
    }

    document.getElementById('fieldBlacklist').value  = Array.isArray(e.blacklist) ? e.blacklist.join(',') : '';
    document.getElementById('fieldMaxReplies').value = e.max_replies_per_sender ?? 5;
    document.getElementById('fieldReplyHours').value = e.reply_period_hours ?? 1;
    document.getElementById('fieldComment').value    = e._comment || '';
    document.getElementById('entryIndex').value      = idx;
  } else {
    document.getElementById('fieldHtml').value = 'false';
    await toggleFields();
    if (htmlEditor) htmlEditor.setData('');
  }

  const addrType = document.getElementById('addressType');
  const lbl = document.getElementById('addressLabel');
  const hint = document.getElementById('addressHint');

  if (addrType && lbl){
    const isDomain = (addrType.value === 'domain');
    lbl.textContent = isDomain ? 'Domain (z.B. beispiel.ch)' : 'E-Mail';
    if (hint){
      hint.innerHTML = isDomain ? 'Bei <b>Domain</b>: nur Domain (ohne @)' : 'Eine Adresse pro Zeile oder mit Komma getrennt';
    }
  }

  modal.show();
}

/* Init: DataTables, Tooltips, Events */
(function init(){
  const onReady = async () => {
    if ($.fn.DataTable && !$.fn.DataTable.isDataTable('#autoreplyTable')) {
      $('#autoreplyTable').DataTable({
        paging:true, pagingType:"first_last_numbers", searching:true, lengthChange:true, info:true,
        order:[[0,'asc']], pageLength:15, lengthMenu:[[10,15,25,50],[10,15,25,50]],
        autoWidth:false, responsive:true,
        columnDefs:[
          { targets:3, orderable:false, className:'text-center', width:90 },
          { targets:-1, orderable:false, className:'text-end', width:140 }
        ],
        dom:'<"row mb-2"<"col-md-6"l><"col-md-6"f>>t<"row mt-2"<"col-md-6"i><"col-md-6"p>>'
      });
    }

    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el));

    document.getElementById('autoreplyTable')?.addEventListener('dblclick', (e) => {
      const tr = e.target.closest('tr[data-idx]');
      if (!tr) return;
      const n = parseInt(tr.getAttribute('data-idx'), 10);
      if (!isNaN(n)) openModal(n);
    });

    document.getElementById('addressType')?.addEventListener('change', function(){
      const lbl = document.getElementById('addressLabel');
      const hint = document.getElementById('addressHint');
      const isDomain = (this.value === 'domain');

      if (lbl) lbl.textContent = isDomain ? 'Domain (z.B. beispiel.ch)' : 'E-Mail';
      if (hint){
        hint.innerHTML = isDomain ? 'Bei <b>Domain</b>: nur Domain (ohne @)' : 'Eine Adresse pro Zeile oder mit Komma getrennt';
      }
    });

    document.getElementById('fieldHtml')?.addEventListener('change', toggleFields);
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', onReady);
  else onReady();
})();

/* POST Wrapper */
async function postLocalApi(endpoint, body){
  const resp = await fetch(endpoint, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...body, csrf_token: CSRF_TOKEN })
  });

  const txt = await resp.text();
  let data;
  try { data = JSON.parse(txt); }
  catch (_) { data = { success:false, error: txt || 'Ungueltige Server-Antwort' }; }

  if (!resp.ok || !data.success) throw new Error(data.error || 'Server-Fehler');
  return data;
}

/* User Config aus UI bauen */
function buildUserConfigFromUI(){
  const uc = {
    autoreply: entries.slice(),
    blacklist: [],
    filters: { header_block:{}, header_allow:[], body_block:[], body_allow:[] }
  };

  uc.blacklist = (document.getElementById('blacklistArea')?.value || '')
    .split('\n').map(s => s.trim()).filter(Boolean);

  const valLines = id => (document.getElementById(id)?.value || '')
    .split('\n').map(s => s.trim()).filter(Boolean);

  uc.filters.header_block = {
    'Subject': valLines('f_headerblock_subject'),
    'List-Id': valLines('f_headerblock_listid')
  };
  uc.filters.header_allow = valLines('f_headerallow');
  uc.filters.body_block   = valLines('f_bodyblock');
  uc.filters.body_allow   = valLines('f_bodyallow');

  return uc;
}

/* Entry speichern */
document.getElementById('entryForm')?.addEventListener('submit', async function(e){
  e.preventDefault();

  const idx    = document.getElementById('entryIndex').value;
  const isHtml = (document.getElementById('fieldHtml').value === 'true');

  let bodyValue = '';
  if (isHtml){
    const ed = await ensureHtmlEditor();
    bodyValue = ed ? (ed.getData() || '').trim() : '';
    if (!bodyValue) return showAlert('danger','Bitte HTML-Inhalt erfassen.');
  } else {
    bodyValue = (document.getElementById('fieldBody')?.value || '').trim();
    if (!bodyValue) return showAlert('danger','Bitte einen Text-Body eingeben.');
  }

  const entry = {
    from:       document.getElementById('fieldFrom').value,
    'reply-to': document.getElementById('fieldReplyTo').value,
    subject:    document.getElementById('fieldSubject').value,
    html:       isHtml,
    body:       bodyValue,
    blacklist:  (document.getElementById('fieldBlacklist').value || '')
                  .split(',').map(s => s.trim()).filter(Boolean),
    max_replies_per_sender: parseInt(document.getElementById('fieldMaxReplies').value, 10) || 5,
    reply_period_hours:     parseInt(document.getElementById('fieldReplyHours').value, 10) || 1,
    _comment:   document.getElementById('fieldComment').value
  };

  const type = document.getElementById('addressType').value;
  const raw  = document.getElementById('fieldAddress').value || '';
  const list = parseMultiAddress(raw);

  if (list.length === 0){
    return showAlert('danger','Bitte mindestens eine Adresse oder Domain eingeben.');
  }

  if (type === 'email'){
    const bad = list.filter(x => !isValidEmail(x));
    if (bad.length) return showAlert('danger','Ungueltige E-Mail: ' + bad.join(', '));
    entry.email = list;
    delete entry.domain;
  } else {
    const bad = list.filter(x => !isValidDomain(x));
    if (bad.length) return showAlert('danger','Ungueltige Domain: ' + bad.join(', '));
    entry.domain = list;
    delete entry.email;
  }

  if (idx !== '') entries[parseInt(idx, 10)] = entry;
  else entries.push(entry);

  try{
    const uc = buildUserConfigFromUI();
    const btn = this.querySelector('[type="submit"]');
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-arrow-repeat spin me-1"></i>Speichern...';

    const data = await postLocalApi('?api=save_user_config', { data: uc });
    showAlert('success', data.message || 'Gespeichert.');
    setTimeout(() => location.reload(), 600);
  } catch(err){
    console.error(err);
    showAlert('danger', err.message || 'Fehler beim Speichern');
  } finally {
    const btn = this.querySelector('[type="submit"]');
    if (btn){
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-save"></i> Speichern';
    }
  }
});

/* Entry loeschen */
async function deleteEntry(idx){
  if (!confirm('Wirklich loeschen?')) return;

  entries.splice(idx, 1);

  try{
    const uc = buildUserConfigFromUI();
    const data = await postLocalApi('?api=save_user_config', { data: uc });
    showAlert('success', data.message || 'Gespeichert.');
    setTimeout(() => location.reload(), 600);
  }catch(err){
    console.error(err);
    showAlert('danger', err.message || 'Fehler beim Speichern');
  }
}

/* Filter speichern */
document.getElementById('filterForm')?.addEventListener('submit', async function(e){
  e.preventDefault();

  try{
    const uc = buildUserConfigFromUI();
    const btn = this.querySelector('[type="submit"]');
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-arrow-repeat spin me-1"></i>Speichern...';

    const data = await postLocalApi('?api=save_user_config', { data: uc });
    showAlert('success', data.message || 'Gespeichert.');
    setTimeout(() => location.reload(), 600);
  }catch(err){
    console.error(err);
    showAlert('danger', err.message || 'Fehler beim Speichern');
  }finally{
    const btn = this.querySelector('[type="submit"]');
    if (btn){
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-save me-1"></i>Speichern (an alle Server)';
    }
  }
});

/* Server Config speichern */
document.getElementById('serverConfigForm')?.addEventListener('submit', async function(e){
  e.preventDefault();

  const cfg = {
    SMTP:      document.getElementById('serverSMTP').value,
    port:      parseInt(document.getElementById('serverPort').value),
    ssl:       document.getElementById('serverSSL').checked,
    starttls:  document.getElementById('serverSTARTTLS').checked,
    smtpauth:  document.getElementById('serverSMTPAuth').checked,
    username:  document.getElementById('serverUsername').value || '',
    password:  document.getElementById('serverPassword').value || '',
    logging:   document.getElementById('serverLogging').checked,
    integration_mode: document.getElementById('serverIntegrationMode').value,
    autoreply_checks: {
      auto_submitted:           document.getElementById('checkAutoSubmitted').checked,
      x_auto_response_suppress: document.getElementById('checkXAutoResponseSuppress').checked,
      list_headers:             document.getElementById('checkListHeaders').checked,
      feedback_id:              document.getElementById('checkFeedbackId').checked,
      precedence:               document.getElementById('checkPrecedence').checked,
      x_autoreply:              document.getElementById('checkXAutoreply').checked,
      empty_envelope_from:      document.getElementById('checkEmptyEnvelopeFrom').checked,
      system_from:              document.getElementById('checkSystemFrom').checked,
      system_replyto:           document.getElementById('checkSystemReplyTo').checked,
      noreply:                  document.getElementById('checkNoReply').checked
    }
  };

  if (!cfg.password) delete cfg.password;

  try{
    const btn = this.querySelector('[type="submit"]');
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-arrow-repeat spin me-1"></i>Speichern...';

    const data = await postLocalApi('?api=save_server_config', { ...cfg });
    showAlert('success', data.message || 'Gespeichert.');
    setTimeout(() => location.reload(), 600);
  }catch(err){
    console.error(err);
    showAlert('danger', err.message || 'Fehler beim Speichern');
  }finally{
    const btn = this.querySelector('[type="submit"]');
    if (btn){
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-save me-1"></i>Speichern (an alle Server)';
    }
  }
});

/* Modal Events: Layout Refresh fuer Editor */
document.getElementById('editModal')?.addEventListener('shown.bs.modal', () => {
  const first = document.querySelector('#editInnerTabs .nav-link:first-child');
  if (first) new bootstrap.Tab(first).show();
  setTimeout(() => window.dispatchEvent(new Event('resize')), 0);
});
document.getElementById('editInnerTabs')?.addEventListener('shown.bs.tab', () => {
  setTimeout(() => window.dispatchEvent(new Event('resize')), 0);
});
</script>

</body>
</html>
