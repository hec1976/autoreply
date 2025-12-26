<?php
declare(strict_types=1);

/**
 * StatsLog Viewer - Autoresponder Log-Anzeige
 * Lädt und zeigt Log-Daten von konfigurierten Servern an
 */

// === SICHERHEIT ===
require_once __DIR__ . '/includes/security-headers.php';

// === KONFIGURATION ===
$configPath = __DIR__ . '/../config/config.php';

// Config Datei prüfen
if (!file_exists($configPath) || !is_readable($configPath)) {
    error_log('StatsLog: Config file missing: ' . $configPath);
    die('Konfigurationsfehler');
}

$config = include $configPath;

// === KONFIGURATIONSWERTE ===
$apiToken = getenv('API_TOKEN') ?: ($config['apiToken'] ?? '');
if (empty($apiToken)) {
    die('API Token fehlt');
}

$serverList = is_array($config['servers'] ?? null) ? $config['servers'] : [];
$curlVerifyPeer = (bool)($config['curl_ssl_verify_peer'] ?? false);
$curlVerifyHost = $config['curl_ssl_verify_host'] ?? false;
$maxEntries = (int)($config['statslog_max_entries'] ?? 5000);

// === SERVER-AUSWAHL ===
$defaultServerKey = !empty($serverList) ? (string)array_key_first($serverList) : '';

// Validiere Server-Parameter
$selectedServer = $_GET['server'] ?? 'ALL';
$allowedServers = array_merge(['ALL'], array_keys($serverList));

if (!in_array($selectedServer, $allowedServers, true)) {
    $selectedServer = 'ALL';
}

/**
 * Holt das Statslog vom Server.
 * Rueckgabe ist raw Text (Zeilen).
 */
function fetch_statslog($endpoint, $apiToken, $verifyPeer, $verifyHost, &$err = null)
{
    $err = null;

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $endpoint,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => ["X-API-Token: $apiToken"],
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_FAILONERROR    => true,
		CURLOPT_SSL_VERIFYPEER => $verifyPeer,
		CURLOPT_SSL_VERIFYHOST => $verifyHost,
    ]);

    $response = curl_exec($ch);
    if ($response === false) {
        $err = curl_error($ch);
    }
    curl_close($ch);

    return $response;
}

// State fuer UI
$lines    = [];
$warnings = [];
$error    = null;

// Zielserver bestimmen (ALL oder einzelner)
$serversToQuery = [];

if ($selectedServer === 'ALL') {
    foreach ($serverList as $name => $url) {
        if (!is_string($url) || $url === '') continue;
        $serversToQuery[] = ['name' => (string)$name, 'url' => $url];
    }
} else {
    // selectedServer ist bereits validiert
    $serversToQuery[] = [
        'name' => (string)$selectedServer,
        'url'  => $serverList[$selectedServer],
    ];
}

// Logs sammeln
if ($error === null) {
    $allLines = [];

    foreach ($serversToQuery as $srv) {
        $endpoint = rtrim($srv['url'], '/') . '/autoreply/statslog';

        $curlErr = null;
        $resp = fetch_statslog($endpoint, $apiToken, $curlVerifyPeer, $curlVerifyHost, $curlErr);

        if ($resp === false || trim((string)$resp) === '') {			
			if ($resp === false) {
				error_log(sprintf(
					'[STATSLOG] Failed to fetch from %s: %s',
					htmlspecialchars($srv['name'], ENT_QUOTES, 'UTF-8'),
					htmlspecialchars($curlErr, ENT_QUOTES, 'UTF-8')
				));
			}			
            $warnings[] = "⚠️ {$srv['name']}: keine Daten oder Fehler ($curlErr)";
            continue;
        }

        foreach (explode("\n", trim((string)$resp)) as $line) {
            $line = trim($line);
            if ($line === '') continue;

            // server vorne anhaengen (bleibt bewusst so)
            $allLines[] = $srv['name'] . ';' . $line;
        }
    }

    // Sortierung: Timestamp sitzt nach dem ersten ';' und ist 19 Zeichen lang (YYYY-MM-DD HH:MM:SS)
    usort($allLines, function ($a, $b) {
        $aTs = substr($a, strpos($a, ';') + 1, 19);
        $bTs = substr($b, strpos($b, ';') + 1, 19);
        return strcmp($bTs, $aTs);
    });

    $lines = array_slice($allLines, 0, $maxEntries);
}
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
</head>
<body>

<?php include __DIR__ . '/includes/navigation.php'; ?>
<?php include __DIR__ . '/includes/sidebar.php'; ?>

<div class="container mt-4" style="margin-left:270px">

  <div class="d-flex align-items-center justify-content-between mb-2">
    <h2 class="mb-4">Status Log</h2>
  </div>

  <div class="card shadow-sm rounded-3">
    <div class="card-header bg-light d-flex justify-content-between align-items-center">
      <div class="d-flex align-items-center">
        <i class="bi bi-graph-up-arrow me-2"></i>
        <span class="fw-semibold">Log</span>
      </div>
      <span class="small opacity-75">Server: <strong><?= count($serverList) ?></strong></span>
    </div>

    <div class="card-body">

      <form method="get" class="mb-3">
        <div class="row g-2 align-items-center">
          <div class="col-auto">
            <label for="server" class="col-form-label fw-bold">Server:</label>
          </div>
          <div class="col-auto">
            <select class="form-select form-select-sm" name="server" id="server" onchange="this.form.submit()">
              <option value="ALL" <?= ($selectedServer === 'ALL') ? 'selected' : '' ?>>Alle Server</option>
				<?php foreach ($serverList as $name => $url): ?>
				  <option value="<?= htmlspecialchars((string)$name) ?>" <?= ((string)$name === (string)$selectedServer) ? 'selected' : '' ?>>
					<?= htmlspecialchars((string)$name) ?>
				  </option>
				<?php endforeach; ?>
            </select>
          </div>
        </div>
      </form>

      <?php if ($error): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
      <?php endif; ?>

      <?php if (!empty($warnings)): ?>
        <div class="alert alert-warning">
          <?php foreach ($warnings as $w): ?>
            <div><?= htmlspecialchars($w) ?></div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>

      <?php if (empty($lines)): ?>
        <div class="alert alert-warning">Keine Logeintraege gefunden.</div>
      <?php else: ?>
        <div class="table-responsive rounded-2">
          <table id="logTable" class="table table-hover align-middle mb-0">
            <thead class="table-light">
              <tr>
                <th>Server</th>
                <th>Datum/Zeit</th>
                <th>Ereignis</th>
                <th>Absender</th>
                <th>Empfaenger</th>
                <th>Betreff</th>
                <th>Regel</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($lines as $line): ?>
                <?php
                  $p = explode(';', $line, 8);
                  if (count($p) < 7) continue;
                ?>
                <tr>
                  <td><span class="badge text-bg-secondary"><?= htmlspecialchars($p[0]) ?></span></td>
                  <td><?= htmlspecialchars($p[1]) ?></td>
                  <td><?= htmlspecialchars($p[2]) ?></td>
                  <td><?= htmlspecialchars($p[3]) ?></td>
                  <td><?= htmlspecialchars($p[4]) ?></td>
                  <td><?= htmlspecialchars($p[5]) ?></td>
                  <td><?= htmlspecialchars($p[6]) ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>

    </div>
  </div>
</div>

<script src="assets/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/jquery-3.7.1.js"></script>
<script src="assets/js/jquery.dataTables.min.js"></script>
<script src="assets/js/dataTables.bootstrap5.min.js"></script>

<script>
document.addEventListener('DOMContentLoaded', function () {
  if (window.jQuery && jQuery.fn && jQuery.fn.DataTable) {
    jQuery('#logTable').DataTable({
      pagingType: "first_last_numbers",
      pageLength: 25,
      lengthMenu: [25, 50, 100],
      order: [[1, "desc"]]
    });
  }
});
</script>

</body>
</html>
