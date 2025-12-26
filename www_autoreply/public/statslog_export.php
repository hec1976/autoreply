<?php 
declare(strict_types=1); 

if (session_status() === PHP_SESSION_NONE) {
    session_start();
    session_regenerate_id(true);
}
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$apiToken = $config['apiToken']; 
$serverList = $config['servers']; 

// Gewählten Server prüfen 
$selectedServer = $_GET['server'] ?? reset($serverList); 
if (!in_array($selectedServer, $serverList, true)) { 
    http_response_code(400); 
    echo "Ungültiger Server."; 
    exit; 
} 

$endpoint = rtrim($selectedServer, '/') . '/autoreply/statslog'; 

// HTTP GET mit API-Token + SSL-Allow-Self-Signed 
$opts = [ 
    'http' => [ 
        'method'  => 'GET', 
        'header'  => "X-API-Token: $apiToken\r\n", 
        'timeout' => 10, 
    ], 
    'ssl' => [ 
        'verify_peer'      => false, 
        'verify_peer_name' => false, 
        'allow_self_signed'=> true, 
    ] 
]; 

$context = stream_context_create($opts); 
$result = @file_get_contents($endpoint, false, $context); 
if ($result === false) { 
    http_response_code(500); 
    echo "Fehler beim Abrufen von: $endpoint"; 
    exit; 
} 

// CSV ausgeben 
header('Content-Type: text/csv; charset=utf-8'); 
header('Content-Disposition: attachment; filename="autoreply_stats.csv"'); 

$output = fopen('php://output', 'w'); 
fputcsv($output, ['Datum/Zeit', 'Ereignis', 'Absender', 'Empfänger', 'Betreff', 'Regel'], ';'); 

$lines = explode("\n", trim($result)); 
foreach ($lines as $line) { 
    $fields = explode(';', $line); 
    if (count($fields) >= 6) { 
        fputcsv($output, array_map('trim', $fields), ';'); 
    } 
} 
fclose($output); 
exit; 

