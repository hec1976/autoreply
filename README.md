# Autoreply Plattform

Dieses Repository enthaelt die **Autoreply Plattform** fuer Postfix-basierte Mailinfrastrukturen.
Die Plattform stellt eine robuste, modular aufgebaute Loesung fuer automatische Antworten bereit und trennt dabei klar zwischen:

- Mailverarbeitung (Runtime)
- Konfigurations- und Steuerlogik (Service / API)
- Administration und Automatisierung

Die Installation erfolgt **zentral ueber ein install.sh Script**, welches alle benoetigten Komponenten einrichtet.
Web- oder GUI-Komponenten sind **nicht Bestandteil** dieses Repositories.

---

## Was dieses Projekt ist

- Produktiv faehige Autoreply Loesung
- Fuer interne Mailplattformen gedacht
- Kein SaaS, kein Public Service
- Fokus auf Stabilitaet, Nachvollziehbarkeit und Betriebssicherheit

---

## Gesamtarchitektur

Die Plattform besteht aus folgenden Bausteinen:

### 1. Autoreply Mailfilter

- Wird direkt in Postfix als Pipe Filter eingebunden
- Verarbeitet eingehende Mails
- Prueft Regeln, Limits und Loop-Schutz
- Versendet automatische Antworten
- Enthält **keine Verwaltungslogik**

### 2. Autoreply Services Agent

- systemd Service (Daemon)
- Stellt eine **interne HTTP API** bereit
- Verwaltet Konfigurationen und Regeln
- Erstellt automatische Backups
- Ermoeglicht Rollbacks
- Dient als zentrale Steuerinstanz

### 3. Konfigurationsdaten

- JSON Dateien fuer Server- und User-Regeln
- ENV Dateien fuer Laufzeitparameter
- Keine Konfiguration im Code
- Alle Aenderungen sind versionierbar

---

## Installation (zentral ueber install.sh)

Die komplette Plattform wird ueber **ein zentrales Installationsskript** installiert.

```bash
sudo ./install.sh
```

### Was install.sh erledigt

Das Script fuehrt **alle notwendigen Schritte automatisch aus**, ausser der Web-Ebene:

- Anlegen von Service-Usern und Gruppen
- Installation des Autoreply Mailfilters
- Installation des Services Agent
- Setzen aller Verzeichnis- und Dateiberechtigungen
- Deployment von systemd Service Units
- Aktivieren und Starten der Services
- Initiales Anlegen von Konfigurations- und Backup-Verzeichnissen

Nicht installiert wird:
- WWW oder GUI Komponenten
- Reverse Proxies
- Externe Monitoring Systeme

---

## Voraussetzungen

- Linux System mit systemd
- Postfix ist installiert und laeuft
- Perl und Python sind verfuegbar
- Root Zugriff fuer die Installation
- Kein aktiver Autoreply Filter in Postfix

---

## Nach der Installation

Nach erfolgreicher Installation stehen folgende Komponenten bereit:

- Autoreply Mailfilter ist in Postfix integriert
- Services Agent laeuft als systemd Service
- HTTP API ist lokal oder intern erreichbar
- Konfigurationsdateien liegen in definierten Pfaden
- Backups werden automatisch erstellt

Pruefen:

```bash
systemctl status autoreply-agent
```

---

## Betriebskonzept

- Mailfilter laeuft ausschliesslich ueber Postfix
- Konfigurationsaenderungen erfolgen nur ueber den Services Agent
- Keine manuellen JSON Edits im Produktivbetrieb
- Rollbacks sind jederzeit moeglich
- Fehler in Agent oder API stoppen den Mailfluss nicht

---

## Dokumentation

- autoreply/README.md – Mailfilter und Postfix Integration
- services-agent/README.md – Service Betrieb
- services-agent/README_API.md – HTTP API Endpoints

---

## Sicherheitshinweise

- Die API ist nicht fuer den Internetzugriff gedacht
- Zugriff erfolgt ueber IP Allowlisten
- Eigene Service-User fuer alle Komponenten
- Schreibrechte nur wo technisch notwendig
- Backups regelmaessig pruefen

---

## Lizenz

MIT License – siehe `LICENSE`
