# Postfix Autoreply-Mailfilter (Python)

Dieses Skript ist ein professioneller Mail-Filter für Postfix. Es liest E-Mails über STDIN, prüft sie gegen komplexe Filterregeln sowie Blacklists und versendet bei Bedarf eine automatische Antwort.

## Hauptfunktionen

- **Loop-Prävention:** Erkennt automatisch generierte Mails (Auto-Submitted, List-Id, etc.) und verhindert Ping-Pong-Effekte.
- **Flexibler Modus:** Unterstützt den klassischen Transport-Modus (Re-Injection) und den BCC-Modus.
- **Sicherheits-Features:** Begrenzung des Original-Textes (Body Truncation) auf 2000 Zeichen, um Serverlast zu minimieren.
- **Monitoring:** Detaillierte Statistiken im CSV-Format mit automatischer monatlicher Rotation.
- **Dateisicherheit:** Atomares Schreiben von JSON-Dateien und prozessübergreifendes Locking (`flock`).

---

## Changelog


### [v2.6.0] - 2026-02-18
**SMTP-Failover über alle A/AAAA-Records**
- **IP-Failover:** Der SMTP-FQDN wird vollständig aufgelöst (A und AAAA), alle IPs werden nacheinander probiert – kein Single-Point-of-Failure.
- **Keine externe Abhängigkeit:** Kein `dig` nötig, Auflösung über Python `socket.getaddrinfo`.
- **Neuer Config-Parameter:** `timeout_sec` (Default `8`) in `autoreply_server.json`.

### [v2.5.0] 
**Stabilität und Robustheit**
- **stdin-Handling:** Explizites Schließen von stdin bei zu grossen Nachrichten, damit Postfix sauber EOF erkennt.
- **Typ-Annotationen:** `Pattern[str]` statt bare `Pattern` für Python 3.6 Kompatibilität.
- **Mindestargument-Dokumentation:** Klarere Aufruf-Dokumentation im Help-Text.

### [v2.4.0] 
**Sicherheit und Korrektheit**
- **HTML-Injection Fix:** Alle Placeholder-Werte aus der Original-Mail (`{ORIGINAL_SUBJECT}`, `{ORIGINAL_SENDER}`, `{ORIGINAL_DATE}`, `{ORIGINAL_BODY}`) werden bei `html=True` vollständig HTML-escaped.
- **Self-Send Fix:** Prüfung ob Sender gleich Empfänger ist erfolgt jetzt vor dem Limit-Check, damit kein Limit-Slot verschwendet wird.
- **Attachment-Größenlimit:** Maximalgröße für Anhänge über `max_attachment_bytes` konfigurierbar (Default 10 MB), mit doppelter Prüfung via `stat` und `read`.
- **Logging konsistent:** `log_blocked_autoreply` nutzt jetzt `get_decoded_header` statt rohem `message.get()`.
- **Dokumentation:** `_build_rule_index` dokumentiert First-wins-Verhalten und Dual-Key-Regeln.

### [v2.3.0] 
**Performance und Sicherheit**
- **Regel-Index:** `_build_rule_index` ersetzt lineare Regelsuche durch Dict-Lookup – O(1) statt O(n×m).
- **Mehrfach-Empfänger:** `autoreply()` verarbeitet jetzt jeden Empfänger einzeln korrekt.
- **HTML-Escape:** `_html_escape()` eingeführt für `{ORIGINAL_BODY}` bei HTML-Mails.
- **Attachment-Validierung:** `_load_attachment_from_cfg` mit Path-Traversal-Schutz (`allowed_attachment_dir`).
- **Attachment-Refactoring:** Datei wird vor `generate_email` geladen und als Tuple übergeben, kein direkter Dateipfad mehr in `generate_email`.
- **MSG_TOO_LARGE:** Konfigurierbare Aktion (`discard` oder `tempfail` via EX_TEMPFAIL=75) bei zu großen Nachrichten.

### [v2.2.0]
**Bugfixes und Threadsicherheit**
- **Stats-Lock:** `_stats_flock` eingeführt – `log_stat` und `_rotate_stats_monthly` laufen jetzt unter exklusivem Lock, Race Condition bei parallelen Prozessen behoben.
- **Funktion umbenannt:** `check_autoreply` → `is_autoreply_suppressed` für klare Semantik.
- **reinject_email:** Leerer Sender wird korrekt behandelt – kein `-f ""` mehr an sendmail.
- **normalize_email:** Robusterer Strip mit Regex statt `.strip("<>")`.
- **encode_address:** Gibt leeren String zurück wenn kein gültiger E-Mail-Teil vorhanden.
- **Speicherlimit:** `max_message_bytes` (Default 25 MB) verhindert OOM bei großen Mails.
- **`_compute_limit_prune_sec`:** Ungültige `reply_period_hours`-Werte werden geloggt statt still ignoriert.

### [v2.1.0] 
**Erstes refaktoriertes Release**
- **Atomares Limit-Handling:** `is_limit_reached` und `register_autoreply` zu `check_and_register_limit` zusammengeführt – Race Condition zwischen Check und Registrierung behoben.
- **Regex-Cache:** `REGEX_DEFAULT_IGNORECASE` wird korrekt im Cache-Key und beim Compile berücksichtigt.
- **Re-Injection:** Empfänger werden als separate Argumente übergeben, nicht als kommaseparierter String.

### [v1.2.0] 
**Optimierung der Sicherheit und Statistik-Kompatibilität**
- **Sicherheits-Fix (Message-ID):** Robustere Behandlung von E-Mails ohne `Message-ID`.
- **Bounce-Schutz:** Zuverlässige `envelope_from`-Prüfung gegen leere Absender.
- **Body Truncation:** 2000-Zeichen-Begrenzung für `{ORIGINAL_BODY}`.
- **Performance:** Optimierung des Regex-Caches.

### [v1.1.0]
**Umstellung auf CSV-Logging und Berechtigungs-Management**
- **CSV-Statistiken:** Umstellung auf Python `csv`-Modul, Trennzeichen `;`.
- **Berechtigungs-Fix:** `os.chmod(..., 0o660)` für Statistik-Datei.
- **Rotations-Sicherheit:** Korrekte Gruppenberechtigungen nach monatlicher Rotation.

### [v1.0.0]
**Initiales Release**
- Grundlegende Filterlogik (Header/Body-Block & Allow).
- Blacklist-Unterstützung (E-Mail und Domain-Ebene).
- Rate-Limiting (`max_replies_per_sender`).
- Unterstützung für HTML und Plaintext-Antworten.
- Platzhalter-System für Antwort-Vorlagen.

---

## Installation & Konfiguration

### Pfade

| Zweck | Pfad |
|-------|------|
| Server-Config | `/opt/mmbb_script/autoreply/config/autoreply_server.json` |
| User-Config | `/opt/mmbb_script/autoreply/json/autoreply_user.json` |
| Statistiken | `/opt/mmbb_script/autoreply/log/autoreply_stats.log` |
| Limits | `/opt/mmbb_script/autoreply/log/autoreply_limit.json` |
| Log | `/var/log/mmbb/autoreply.log` |

### Berechtigungen

Das Skript setzt die Berechtigungen für die Statistik-Datei automatisch auf `660` (`rw-rw----`). Stellen Sie sicher, dass der Postfix-Benutzer und die Administratoren-Gruppe in derselben Linux-Gruppe sind.

### Integration in Postfix (master.cf)

```conf
autoreply unix  -       n       n       -       -       pipe
  flags=R user=autoreply argv=/usr/bin/python3 /opt/mmbb_script/autoreply/autoreply.py ${sender} ${recipient}
```

### Konfigurationsoptionen (autoreply_server.json)

| Parameter | Default | Beschreibung |
|-----------|---------|--------------|
| `logging` | `false` | Debug-Logging aktivieren |
| `integration_mode` | `"bcc"` | `"bcc"` oder `"classic"` |
| `max_message_bytes` | `26214400` | Max. Mail-Größe (25 MB) |
| `too_large_action` | `"discard"` | `"discard"` oder `"tempfail"` |
| `max_attachment_bytes` | `10485760` | Max. Anhang-Größe (10 MB) |
| `allowed_attachment_dir` | `""` | Pflichtpfad für Anhänge (leer = deaktiviert) |
| `timeout_sec` | `10` | SMTP-Timeout in Sekunden |
| `regex_default_ignorecase` | `false` | Regex case-insensitive by default |

---

