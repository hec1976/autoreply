# Autoreply Mailfilter fuer Postfix

Dieses Projekt ist ein Autoreply Mailfilter fuer Postfix. Das Script liest eine Mail von STDIN, prueft Blacklist und Filterregeln und sendet bei Bedarf eine automatische Antwort. Zusaetzlich wird ein Limit pro Absender und Empfaenger gefuehrt, damit sich keine Reply Schleifen oder Spam Wellen aufschaukeln.

Die Konfiguration ist bewusst extern gehalten, damit das Script nicht mit festen Pfaden leben muss und in unterschiedlichen Umgebungen gleich funktioniert. Standard ist eine lokale config.conf im gleichen Ordner wie das Script. Von dort aus werden die JSON Pfade und Log Pfade gesetzt.

## Features

- Einfache Integration als Postfix Pipe Filter (Mail kommt via STDIN)
- Regeln nach exakter Empfaenger Adresse oder Domain Matching
- Schutz gegen Autoreply Loops durch Header Checks (Auto Submitted, List Headers usw.)
- Blacklist auf Regel Ebene und global
- Header und Body Filter (block und allow)
- Reply Limit pro Absender pro Zeitfenster, gespeichert in JSON mit File Lock
- Statistik Log mit monatlicher Rotation
- Minimaler Install Helper fuer Owner und Permissions

## Repo Struktur (empfohlen)

```text
.
├─ autoreply.py
├─ config.conf
├─ conf/
│  └─ autoreply_server.json
├─ json/
│  └─ autoreply_user.json
├─ log/
│  ├─ autoreply_script.log
│  ├─ autoreply_stats.log
│  └─ autoreply_limit.json
└─ install_script.sh
```

Hinweis: In deiner aktuellen config.conf sind die relativen Pfade so definiert, dass server_config unter conf/ und user_config unter json/ liegen.

## Voraussetzungen

- Python 3.6+
- Zugriff auf /usr/sbin/sendmail (Re Injection im klassischen Mode)
- SMTP Zugang oder lokaler SMTP (je nach Server Settings)

## Konfiguration

### 1) config.conf

Das Script sucht eine config.conf im gleichen Ordner wie autoreply.py.
Absolute Pfade bleiben absolut, relative Pfade werden relativ zum Script Ordner aufgeloest.

Beispiel:

```ini
[paths]
server_config = conf/autoreply_server.json
user_config   = json/autoreply_user.json

log_path      = /opt/autoreply/log/autoreply_script.log
stats_path    = /opt/autoreply/log/autoreply_stats.log
limit_path    = /opt/autoreply/log/autoreply_limit.json

[runtime]
logging_enabled_override =
limit_prune_sec_override =
limit_lock_path =
```

### 2) Server Settings: conf/autoreply_server.json

Hier legst du SMTP, Integration Mode und die Autoreply Checks fest.

Wichtige Keys:
- logging: true|false
- integration_mode: bcc oder klassisch
- SMTP, port, ssl, starttls, smtpauth, username, password
- autoreply_checks: einzelne Checks aktivieren oder deaktivieren

### 3) User Settings: json/autoreply_user.json

Hier kommen deine Autoreply Regeln, Blacklists und Filter rein.

Regel Typen:
- email: Liste oder String. Matcht exakte Empfaenger Adresse.
- domain: Liste oder String. Matcht Empfaenger Domain.

Wichtige Felder pro Regel:
- from, reply-to, subject, body, html
- max_replies_per_sender
- reply_period_hours
- blacklist (optional)

Platzhalter im body und subject:
- {ORIGINAL_DESTINATION}
- {ORIGINAL_SUBJECT}
- {ORIGINAL_SENDER}
- {ORIGINAL_DATE}
- {ORIGINAL_BODY}

## Betrieb und Aufruf

Typischer Aufruf (Postfix Pipe), das Script bekommt:
- argv[1] = Envelope Sender
- argv[2..] = Empfaenger
- Mail kommt via STDIN

Manuell testen:

```bash
cat testmail.eml | python3 autoreply.py sender@example.tld info@example.ch
```

## Integration mit Postfix (Beispiel)

main.cf (Auszug):

```conf
# Beispiel Transport
autoreply_filter unix  -  n  n  -  -  pipe
  flags=Rq user=autoreply argv=/usr/bin/python3 /opt/mmbb_script/autoreply/autoreply.py ${sender} ${recipient}
```

Je nach Setup kann man auch mehrere Empfaenger uebergeben. Das Script erkennt im bcc Mode den tatsaechlichen Empfaenger aus Delivered To oder X Original To oder To.

## Integration Mode

- bcc
  Default in deiner server config. Das Script versucht den echten Empfaenger aus Headers zu ziehen und reagiert nur auf diesen.

- klassisch
  Wenn integration_mode nicht "bcc" ist, werden die Empfaenger aus argv genutzt und die Original Mail wird wieder per sendmail reinjected.

## Logs und Statistik

- Script Log: log_path  
  Normale Logs nur wenn logging aktiv ist. Errors werden immer geloggt, damit Monitoring sauber geht.

- Statistik Log: stats_path  
  Format: timestamp;event;sender;recipient;subject;template  
  Die Datei wird monatlich rotiert.

- Limits: limit_path  
  JSON Status fuer Reply Limits. Wird mit File Lock geschrieben.

## Permissions Setup

Im Repo ist ein Bash Script enthalten, das Owner und Rechte auf Verzeichnisse und Files setzt. Das Script erwartet root, weil chown verwendet wird.

Beispiel:

```bash
sudo ./install_script.sh --user autoreply --group autoreply --base-dir /opt/mmbb_script/autoreply
```

Was es setzt:
- json/ und conf/ auf 0770
- autoreply.py auf 0760 (0660 plus u+x)
- config.conf und JSON Files auf 0660

## Security Hinweise aus der Praxis

- SMTP Zugangsdaten gehoeren nicht ins Repo. Lege produktive Dateien ausserhalb ab oder nutze Deployment Mechanismen.
- Autoreply Loop Schutz ist aktiviert, aber nur so gut wie die Headers der eingehenden Mails. Die Checks sind im server config steuerbar.
- Blacklist und Filter helfen gegen Reply Abuse, aber du solltest das auch auf MTA Ebene mit Rate Limits und Spam Schutz kombinieren.

## Lizenz

MIT License. Siehe Datei LICENSE im Repo.
