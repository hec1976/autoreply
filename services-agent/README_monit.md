
# Monit Konfiguration für autoreply-agent

Diese Anleitung beschreibt die Monit-Überwachung für den `autoreply-agent`-Service.

---

## Konfiguration

### 1. Monit-Konfiguration
Erstelle die Datei `/etc/monit/conf.d/autoreply-agent.conf` mit folgendem Inhalt:

```monit
check process autoreply-agent with pidfile /run/autoreply-agent/autoreply-agent.pid
  group services
  start program = "/bin/systemctl start autoreply-agent.service"
  stop program = "/bin/systemctl stop autoreply-agent.service"
  if does not exist then restart
  if 5 restarts within 5 cycles then timeout
  depends on autoreply_permissions
  depends on autoreply_directories

# Berechtigungsprüfung für /opt/autoreply/script/json
check file autoreply_permissions with path /opt/autoreply/script/json
  group services
  if uid != "autoreply" then alert
  if gid != "autoreply" then alert
  if not readable then alert
  if not writable then alert

# Verzeichnisprüfung (tmpfs-Einbindung)
check directory autoreply_directories with path /opt/autoreply/script/json
  group services
  if does not exist then alert
  if not readable then alert
  if not writable then alert

# Log-Überwachung auf Fehler
check file autoreply_log with path /var/log/mmbb/autoreply-agent.log
  group services
  if match "Permission denied" then alert
  if match "Upload fehlgeschlagen" then alert
  if match "Backup fehlgeschlagen" then alert
```

---

## Einrichtung

### 1. Konfiguration speichern
```bash
sudo nano /etc/monit/conf.d/autoreply-agent.conf
```

### 2. Monit neu laden
```bash
sudo monit reload
```

### 3. Syntax prüfen
```bash
sudo monit -t
```

### 4. Status prüfen
```bash
sudo monit status
```

---

## Alerting

### E-Mail-Alerts
Füge in `/etc/monit/monitrc` hinzu:
```monit
set alert admin@example.com
set mailserver localhost
```

---

## Überwachte Komponenten

| Komponente               | Check                                                                 |
|--------------------------|-----------------------------------------------------------------------|
| Service-Prozess          | Läuft der Prozess?                                                    |
| Berechtigungen           | Gehört `/opt/autoreply/script/json` dem Benutzer `autoreply`?         |
| Verzeichnisse            | Ist `/opt/autoreply/script/json` les- und schreibbar?                 |
| Logs                     | Enthalten die Logs Fehler (`Permission denied`, `Upload fehlgeschlagen`)? |

---

## Fehlerbehebung

| Problem                          | Lösung                                                                 |
|----------------------------------|------------------------------------------------------------------------|
| Monit startet den Service nicht | Prüfe `pidfile` in der Konfiguration (`/run/autoreply-agent/autoreply-agent.pid`).     |
| Berechtigungsfehler              | Manuell korrigieren: `sudo chown autoreply:autoreply /opt/autoreply/script/json` |
| Log-Datei nicht gefunden        | Prüfe Pfad in `autoreply_log` (`/var/log/mmbb/autoreply-agent.log`).    |

---
