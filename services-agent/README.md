# Autoreply Services Agent

Der **Autoreply Services Agent** ist ein produktionsreifer Backend Service zur zentralen Steuerung und Verwaltung von Autoreply Regeln.
Er ist als **systemd Service** ausgelegt und stellt eine lokale HTTP API bereit, ueber welche Konfigurationen gelesen, geschrieben,
validiert und versioniert werden koennen.

Der Agent ist bewusst **kein Mailfilter selbst**, sondern die Steuerebene fuer Autoreply Logik, Konfiguration und Betrieb.
Er ist dafuer gedacht, von GUIs, Admin Tools oder Automationsskripten angesprochen zu werden.

---

## Architektur Ueberblick

- Programmiersprache: Perl
- Laufzeit: systemd Service
- Konfiguration: JSON + ENV
- Schnittstelle: HTTP API (lokal oder intern)
- Persistenz: JSON Files mit automatischen Backups
- Ziel: stabiler, auditierbarer und nachvollziehbarer Betrieb

Der Service laeuft typischerweise auf demselben Host wie der Autoreply Mailfilter oder in einem internen Management Netz.

---

## Features

- systemd Daemon Betrieb
- HTTP API fuer Konfig Verwaltung
- Trennung von Server Config und User Rules
- Automatische JSON Backups vor jeder Aenderung
- Atomic Writes und File Locking
- ENV basierte Laufzeit Parameter
- Optionaler SSL Betrieb
- IP Allowlist und Trusted Proxy Support
- Saubere Rollback Moeglichkeit

---

## Repository Struktur

```text
services-agent/
├─ autoreply-agent.pl            # Hauptservice
├─ config.json                   # Zentrale Server Konfiguration
├─ install_service.sh            # Installationsskript
├─ svc-apply-once.sh             # Einmaliges Anwenden neuer Configs
├─ service/
│  └─ autoreply-agent.service    # systemd Unit
├─ example/
│  └─ autoreply-agent.env.example
└─ backups/
   └─ *.json                     # Automatische Backups
```

---

## Voraussetzungen

- Linux mit systemd
- Perl >= 5.26
- Schreibrechte auf das Installationsverzeichnis
- Eigener Service User empfohlen (z. B. `autoreply`)

---

## Installation

### 1. Repository bereitstellen

```bash
git clone <repo-url>
cd services-agent
```

### 2. Installation ausfuehren

```bash
sudo ./install_service.sh
```

Das Install Script erledigt:
- Anlegen von User und Gruppe (optional)
- Kopieren der Dateien nach /opt oder Zielpfad
- Setzen von Owner und File Permissions
- Installation der systemd Unit
- Aktivieren und Starten des Services

---

## Konfiguration

### config.json (Server Konfiguration)

Die `config.json` steuert das komplette Verhalten des Services.

Typische Struktur:

```json
{
  "listen": "0.0.0.0:5010",
  "allowed_ips": ["127.0.0.1/32", "192.168.0.0/24"],
  "trusted_proxies": ["127.0.0.1"],
  "client_ip_header": "X-Forwarded-For",

  "ssl_enable": 0,
  "ssl_cert_file": "/opt/autoreply/ssl/server.crt",
  "ssl_key_file": "/opt/autoreply/ssl/server.key",

  "logfile": "/var/log/autoreply/agent.log",

  "configDir": "/opt/autoreply/conf",
  "jsonDir": "/opt/autoreply/json",
  "backupDir": "/opt/autoreply/backups",

  "maxBackups": 30,
  "fileMode_service": "0660"
}
```

### Wichtige Felder erklaert

- `listen`  
  IP und Port, auf dem der Service lauscht

- `allowed_ips`  
  CIDR Liste erlaubter Client Netze

- `trusted_proxies`  
  IPs von Reverse Proxies

- `client_ip_header`  
  Header fuer Original Client IP

- `ssl_enable`  
  0 oder 1, aktiviert HTTPS

- `configDir` / `jsonDir`  
  Pfade zu Konfigurationsdateien

- `backupDir`  
  Ziel fuer automatische Backups

---

## ENV Datei

Die ENV Datei wird durch systemd geladen und enthaelt Laufzeit Flags.

Beispiel:

```env
AUTOREPLY_ENV=prod
AUTOREPLY_DEBUG=0
```

Sie liegt bewusst ausserhalb des Repos und enthaelt keine Logik.

---

## HTTP API

Der Service stellt eine einfache REST aehnliche API bereit.
Alle Endpoints liefern JSON.

### Authentifizierung

- IP basierte Zugriffskontrolle
- Optional API Token (falls aktiviert)
- Kein Public Internet Zugriff vorgesehen

---

### Endpoints Ueberblick

#### GET /health

Health Check fuer Monitoring.

Antwort:
```json
{ "status": "ok" }
```

---

#### GET /config/server

Liefert die aktuelle Server Konfiguration.

---

#### POST /config/server

Aktualisiert die Server Konfiguration.

- Validierung vor dem Schreiben
- Backup der alten Version
- Atomic Write

---

#### GET /config/user

Liefert die User Autoreply Regeln.

---

#### POST /config/user

Schreibt neue User Regeln.

- Schema Check
- Backup
- Sofort wirksam

---

#### POST /config/rollback

Rollback auf eine vorherige Version anhand Backup Dateiname.

---

## Backup Konzept

- Vor jeder Aenderung wird ein Backup erstellt
- Dateinamen enthalten Typ und Timestamp
- Maximale Anzahl ueber `maxBackups` begrenzt
- Alte Backups werden automatisch geloescht

---

## Service Betrieb

### Status und Steuerung

```bash
systemctl status autoreply-agent
systemctl restart autoreply-agent
journalctl -u autoreply-agent
```

---

## Sicherheit

- Service laeuft mit eigenem User
- Keine Root Rechte im Runtime Betrieb
- Zugriff nur ueber interne Netze
- SSL optional aktivierbar
- Klare Trennung von Code und Daten

---

## Typische Einsatzszenarien

- Web GUI zur Autoreply Verwaltung
- CI/CD Rollout von Konfigurationen
- Automatisierte Provisionierung
- Audit faehige Aenderungshistorie

---

## Lizenz

MIT License. Siehe Datei LICENSE.
