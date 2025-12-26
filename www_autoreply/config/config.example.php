<?php
return [
    'apiToken' => 'geheimer-token',
    'servers' => [
        'postfix-1' => 'https://x.x.x.x:5010',
		'postfix-2' => 'httpx://x.x.x.x:5010',
    ],
	
	// cURL TLS Checks 
	'curl_ssl_verify_peer' => false,
	'curl_ssl_verify_host' => false,
	
	// statslog
    'statslog_max_entries' => 5000,

    // Web Security Schalter
    'https_enforce' => false,   
    'hsts_enable' => false,     
    'cookie_secure' => false,   
    'cookie_samesite' => 'Lax' 
];
