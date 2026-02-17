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

### [v1.2.0] - 2026-02-17 
**Optimierung der Sicherheit und Statistik-Kompatibilität**
- **Sicherheits-Fix (Message-ID):** Robustere Behandlung von E-Mails ohne `Message-ID` zur Vermeidung von Skript-Abstürzen.
- **Bounce-Schutz:** Korrektur der `envelope_from`-Prüfung. Das Skript nutzt nun zuverlässig den von Postfix übergebenen Envelope-Sender, um Antworten an leere Absender (Bounces) zu verhindern.
- **Body Truncation:** Wiedereinführung der 2000-Zeichen-Begrenzung für `{ORIGINAL_BODY}`, um die Größe der Antwort-Mails zu kontrollieren.
- **Performance:** Optimierung des Regex-Caches für schnellere Header-Prüfungen.

### [v1.1.0] 
**Umstellung auf CSV-Logging und Berechtigungs-Management**
- **CSV-Statistiken:** Umstellung des Statistik-Loggings auf das Python `csv`-Modul für Excel-kompatible Auswertungen (Trennzeichen `;`).
- **Berechtigungs-Fix:** Implementierung von `os.chmod(..., 0o660)` für die Statistik-Datei.
- **Rotations-Sicherheit:** Sicherstellung, dass auch nach der monatlichen Rotation der Statistiken die neue Datei sofort wieder die korrekten Gruppen-Berechtigungen erhält.

### [v1.0.0] - Basisversion
**Initiales Release**
- Grundlegende Filterlogik (Header/Body-Block & Allow).
- Blacklist-Unterstützung (E-Mail und Domain-Ebene).
- Rate-Limiting (max_replies_per_sender).
- Unterstützung für HTML und Plaintext-Antworten.
- Platzhalter-System für Antwort-Vorlagen.

---

## Installation & Konfiguration

### Pfade
- **Server-Config:** `/opt/mmbb_script/autoreply/config/autoreply_server.json`
- **User-Config:** `/opt/mmbb_script/autoreply/json/autoreply_user.json`
- **Statistiken:** `/opt/mmbb_script/autoreply/log/autoreply_stats.log`

### Berechtigungen
Das Skript setzt die Berechtigungen für die Statistik-Datei automatisch auf `660` (`rw-rw----`). Stellen Sie sicher, dass der Postfix-Benutzer und die Administratoren-Gruppe in derselben Linux-Gruppe sind.

### Integration in Postfix (master.cf)
```conf
autoreply unix  -       n       n       -       -       pipe
  flags=R user=autoreply argv=/usr/bin/python3 /opt/mmbb_script/autoreply/autoreply.py ${sender} ${recipient}
```

---

*Erstellt am 17. Februar 2026*
