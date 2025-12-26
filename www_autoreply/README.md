# Autoresponder – Administrationskonsole

Dieses Repository enthaelt die Web-Administrationskonsole fuer den Autoresponder-Dienst.
Der Fokus liegt auf einer sauberen, ruhigen Admin-UI, klarer Struktur und einfacher Wartung.

Die Oberflaeche ist bewusst technisch gehalten (kein Marketing-UI) und eignet sich fuer den produktiven Betrieb.

---

## Funktionen (Ueberblick)

- Verwaltung von Autoreply-Eintraegen
- Blacklist & Filter
- Server-Konfiguration
- Deploy & Backup
- Statistik / Logs
- Zentrale Navigation mit Sidebar
- Einheitliches Layout ohne Inline-Styles

---

## Technologie-Stack

- PHP (serverseitig)
- HTML5 / CSS3
- Bootstrap (Layout & Komponenten)
- Bootstrap Icons
- jQuery / DataTables (Tabellen)
- CKEditor 5 (Classic Editor)
- Kein Frontend-Framework, kein Build-Step

---

## Verzeichnisstruktur (relevant)

```
project-root/
├── config/
│   ├── config.php
│   └── config.example.php
├── public/
│   ├── index.php
│   ├── deploy_and_backup.php
│   ├── statslog.php
│   ├── includes/
│   │   ├── navigation.php
│   │   └── sidebar.php
│   └── assets/
│       ├── css/
│       │   └── styles.css
│       ├── js/
│       └── img/
└── README.md
```

---

## Layout-Konzept

### Navbar
- Fixiert am oberen Rand (80px Hoehe)
- Logo links, Titel rechts davon
- Dezenter Farbverlauf als Akzent

### Sidebar
- Fixiert links (250px)
- 1-Level-Navigation
- Icons + Text
- Aktiver Punkt mit Farbmarker
- Keine Inline-Styles

### Content
- In `.main-content` gekapselt
- Sidebar-Offset rein ueber CSS
- Bootstrap `.container` fuer saubere Breiten


---

## Backend-Abhaengigkeit

Die Web-Konsole ist ein reiner Client fuer einen oder mehrere Autoreply-Agenten.

Voraussetzungen:
- Erreichbarer Autoreply-Agent (HTTP oder HTTPS)
- Gueltiger API-Token
- Kompatible API-Version

Ohne erreichbares Backend ist die Konsole nicht funktionsfaehig.

---

## Wichtige CSS-Regeln

- **Keine Inline-Styles** (z.B. kein `margin-left` im HTML)
- Offsets nur ueber `.main-content`
- Sidebar-Breite zentral in `styles.css`
- Navbar-Hoehe zentral in `styles.css`

Beispiel:
```css
.main-content {
    margin-left: 250px;
    padding: 20px;
}
```

---

## Installation

1. Repository auschecken oder kopieren
2. Webroot auf `public/` setzen
3. Sicherstellen, dass folgende Files eingebunden sind:
   - `assets/css/styles.css`
   - `includes/navigation.php`
   - `includes/sidebar.php`
4. PHP >= 8 empfohlen

Kein Build, keine Abhaengigkeiten.

---

## Konfiguration

Die Administrationskonsole verwendet eine PHP Konfigurationsdatei zur Definition von API Token, Backend Servern und optionalen Security Schaltern.

### Datei: `config/config.php`

Beispiel:

```php
<?php
return [
    'apiToken' => 'geheimer-token',
    'servers' => [
        'postfix-1' => 'http://192.168.20.220:5010',
        'postfix-2' => 'http://192.168.20.221:5010',
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
```

### Bedeutung der Parameter

- `apiToken`  
  Geheimer Token fuer die Authentisierung gegen den Autoreply Agent. Dieser Wert darf nicht versioniert werden.

- `servers`  
  Liste der Backend Server. Key ist der Anzeigename in der UI, Value ist die Base URL inkl. Schema und Port.

- `curl_ssl_verify_peer`  
  Steuert `CURLOPT_SSL_VERIFYPEER`. Wenn `false`, wird das Zertifikat nicht geprueft. Nur fuer Test oder Lab empfohlen.

- `curl_ssl_verify_host`  
  Steuert `CURLOPT_SSL_VERIFYHOST`. Wenn `false`, wird der Hostname im Zertifikat nicht geprueft. Nur fuer Test oder Lab empfohlen.

- `statslog_max_entries`  
  Maximale Anzahl Eintraege, die in der Statslog Ansicht geladen werden.

- `https_enforce`  
  Wenn `true`, wird HTTP auf HTTPS umgeleitet. Nur aktivieren, wenn die Seite effektiv via HTTPS betrieben wird.

- `hsts_enable`  
  Wenn `true`, wird ein HSTS Header gesetzt. Nur aktivieren, wenn HTTPS sauber eingerichtet ist, sonst kann es zu Zugriffsproblemen kommen.

- `cookie_secure`  
  Wenn `true`, werden Cookies nur ueber HTTPS gesendet. Bei reinem HTTP Betrieb muss dieser Wert `false` bleiben.

- `cookie_samesite`  
  SameSite Attribut fuer Session Cookies. Empfohlen ist `Lax`. `Strict` kann je nach Workflow zu Nebenwirkungen fuehren.

### Hinweise fuer Produktivbetrieb

- Empfehlung: Backend Server via `https://` anbinden und TLS Checks aktiv lassen:
  - `curl_ssl_verify_peer = true`
  - `curl_ssl_verify_host = true`

- Wenn TLS Checks deaktiviert sind, ist ein Man in the Middle Angriff prinzipiell moeglich, da der API Token ueber die Verbindung mitlaeuft.

- `https_enforce` und `hsts_enable` nur aktivieren, wenn der Webserver wirklich TLS terminiert und die Konsole ausschliesslich via HTTPS erreichbar ist.

### Git Ignore

Empfohlener Eintrag in `.gitignore`:

```
config/config.php
```

Die Datei `config/config.example.php` dient als Vorlage und wird versioniert.


---

## Anpassungen

### Sidebar erweitern
Eintraege werden zentral in `includes/sidebar.php` gepflegt.

### Farben / CI
Zentrale Variablen in `styles.css`:
```css
:root {
  --ch-blue-1: #0b3c6f;
  --ch-green-1: #3cb371;
}
```

### Titel aendern
Navbar-Titel in `includes/navigation.php`:
```html
<div class="navbar-title">Administrationskonsole</div>
```

---

## Best Practices

### Grundgeruest fuer neue Seiten

Neue Seiten immer gleich aufbauen:

- `declare(strict_types=1);`
- Session + CSRF Token initialisieren
- CSS und JS zentral laden
- Navigation und Sidebar als Includes
- Content immer in `.main-content` kapseln (kein Inline `margin-left`)

```php
<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$csrf = $_SESSION['csrf_token'];
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

<div class="main-content">
  <div class="container mt-4">
    <div class="d-flex align-items-center justify-content-between mb-2">
      <h2 class="mb-4">Beschreibung</h2>
    </div>

    <!-- Inhalt -->
    <!-- Bei Formularen: <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf); ?>"> -->

  </div>
</div>

<script src="assets/js/bootstrap.bundle.min.js"></script>
<script src="assets/js/jquery-3.7.1.js"></script>
<script src="assets/js/jquery.dataTables.min.js"></script>
<script src="assets/js/dataTables.bootstrap5.min.js"></script>

</body>
</html>
```


- Keine Layout-Logik in PHP oder HTML
- Alles Layout gehoert ins CSS


---

## Sicherheitskonzept

Diese Administrationskonsole ist nicht oeffentlich zugaenglich gedacht.

### Zugriff
- Betrieb ausschliesslich in internen Netzen oder via VPN
- Kein Public Exposure vorgesehen
- Absicherung ueber Webserver (IP-Restriktion / Auth)

### Authentisierung
- Die Konsole authentisiert sich gegen den Autoreply-Agent via API-Token
- Das Token wird ausschliesslich serverseitig verwendet
- Kein Token im Frontend sichtbar

### CSRF-Schutz
- Alle Formulare verwenden einen serverseitigen CSRF-Token
- Token wird in der PHP-Session gehalten

### HTTPS
- Betrieb ausschliesslich via HTTPS empfohlen
- HSTS auf Webserver-Ebene empfohlen

---
## Betriebsempfehlung

Empfohlene Umgebung:
- Dedizierter Admin-Host oder internes Management-Netz
- Separater vHost fuer die Konsole
- Zugriff nur fuer Administratoren

Nicht empfohlen:
- Betrieb auf Shared Hosting
- Oeffentlicher Internetzugang
- Kombination mit oeffentlichen Web-Anwendungen


---
## Lizenz

Dieses Projekt steht unter der MIT License.

---
## Lizenzen & Drittsoftware

Diese Administrationskonsole verwendet folgende Open-Source-Komponenten:

- **Bootstrap**  
  Lizenz: MIT License  
  https://getbootstrap.com

- **Bootstrap Icons**  
  Lizenz: MIT License  
  https://icons.getbootstrap.com

- **jQuery**  
  Lizenz: MIT License  
  https://jquery.com

- **DataTables**  
  Lizenz: MIT License  
  https://datatables.net

- **CKEditor 5 (Classic Editor)**  
  Lizenz: GPL v2+ (Dual License)  
  https://ckeditor.com/ckeditor-5/

Alle genannten Bibliotheken werden gemaess ihren jeweiligen Open-Source-Lizenzen verwendet.
Die jeweiligen Lizenztexte sind in den Originalprojekten einsehbar.

---


## Status

Produktionsreif.  
Layout konsolidiert.  
Keine bekannten UI-Probleme.

---

## Autor

heclab / Autoresponder Projekt
