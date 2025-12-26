# Autoreply Services Agent

## Zweck

Der Autoreply Services Agent ist ein systemd Service, der eine **interne HTTP API**
bereitstellt. Über diese API werden Autoreply Konfigurationen gelesen, validiert,
geschrieben, versioniert und bei Bedarf zurückgerollt.

Der Service ist **nicht öffentlich** gedacht und wird ausschliesslich aus internen
Netzen oder über Reverse Proxies angesprochen.

---

## API Grundlagen

- Protokoll: HTTP oder HTTPS
- Datenformat: JSON
- Charset: UTF-8
- Authentifizierung: IP Allowlist (optional API Token)
- Schreiboperationen sind **nicht idempotent**
- Jede schreibende Operation erzeugt automatisch ein Backup

---

## Allgemeine Antwortstruktur

Erfolgreiche Antwort:
```json
{
  "status": "ok",
  "data": {}
}
```

Fehlerhafte Antwort:
```json
{
  "status": "error",
  "error": "Beschreibung des Fehlers"
}
```

HTTP Status Codes:
- 200 OK
- 400 Bad Request
- 403 Forbidden
- 404 Not Found
- 500 Internal Server Error

---

## API Endpoints

### GET /health

Health Endpoint für Monitoring und systemd Watchdogs.

Antwort:
```json
{
  "status": "ok"
}
```

---

### GET /info

Liefert Basisinformationen über den laufenden Service.

Antwort:
```json
{
  "service": "autoreply-agent",
  "version": "1.x",
  "env": "prod",
  "pid": 1234
}
```

---

### GET /config/server

Liefert die aktuell aktive **Server Konfiguration**.

Antwort:
```json
{
  "status": "ok",
  "data": {
    "listen": "0.0.0.0:5010",
    "ssl_enable": 0,
    "logfile": "/var/log/autoreply/agent.log"
  }
}
```

---

### POST /config/server

Schreibt eine neue Server Konfiguration.

Ablauf:
1. JSON Schema Validierung
2. Backup der aktuellen Config
3. Atomic Write der neuen Config
4. Reload der Konfiguration im laufenden Prozess

Request Body:
```json
{
  "listen": "127.0.0.1:5010",
  "ssl_enable": 1
}
```

Antwort:
```json
{
  "status": "ok",
  "backup": "server_20251226_101533.json"
}
```

---

### GET /config/user

Liefert die aktuellen **User Autoreply Regeln**.

Antwort:
```json
{
  "status": "ok",
  "data": {
    "rules": []
  }
}
```

---

### POST /config/user

Aktualisiert die User Regeln.

Besonderheiten:
- Strukturprüfung der Regeln
- Prüfung auf doppelte Einträge
- Backup vor dem Schreiben

Request Body:
```json
{
  "rules": [
    {
      "email": "info@example.ch",
      "subject": "Abwesenheit",
      "body": "Vielen Dank für Ihre Nachricht"
    }
  ]
}
```

Antwort:
```json
{
  "status": "ok",
  "backup": "user_20251226_101544.json"
}
```

---

### GET /backups

Listet verfügbare Backups auf.

Antwort:
```json
{
  "status": "ok",
  "data": [
    "server_20251225_224706.json",
    "user_20251226_095942.json"
  ]
}
```

---

### POST /config/rollback

Rollback auf eine vorherige Version.

Request Body:
```json
{
  "file": "user_20251226_095942.json"
}
```

Ablauf:
1. Prüfung ob Backup existiert
2. Wiederherstellen der Datei
3. Reload der Konfiguration

Antwort:
```json
{
  "status": "ok",
  "restored": "user_20251226_095942.json"
}
```

---

### POST /reload

Erzwingt ein erneutes Einlesen der Konfiguration ohne Änderungen.

Antwort:
```json
{
  "status": "ok"
}
```

---

## Zugriffskontrolle

- Zugriff nur aus `allowed_ips`
- Reverse Proxy Support über `trusted_proxies`
- Client IP Ermittlung über `client_ip_header`
- Requests ausserhalb der Allowlist werden mit **403** abgelehnt

---

## Typische Fehler

- 400: Ungültiges JSON oder fehlende Felder
- 403: IP nicht erlaubt
- 404: Endpoint existiert nicht
- 500: Schreib- oder Reload Fehler

---

## Sicherheitshinweise

- API niemals direkt ins Internet exponieren
- HTTPS aktivieren bei Remote Zugriff
- Firewall zusätzlich zur IP Allowlist einsetzen
- Backups regelmässig prüfen

---

## Lizenz

MIT License. Siehe LICENSE.
