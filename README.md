# Autoreply Plattform

```
 █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗██████╗ ██╗     ██╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║     ╚██╗ ██╔╝
███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██████╔╝██║      ╚████╔╝ 
██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██╔═══╝ ██║       ╚██╔╝  
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗██║     ███████╗   ██║   
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝   ╚═╝
```
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![Version](https://img.shields.io/badge/version-1.2.0-blue)
![License](https://img.shields.io/badge/license-MIT-purple)
[![PHP](https://img.shields.io/badge/php-8.1%2B-blue)]()
![Python](https://img.shields.io/badge/python-3.6%2B-yellow)
[![Perl](https://img.shields.io/badge/perl-5.30%2B-yellow)]()
![Security](https://img.shields.io/badge/CodeQL-Security%20Scan-blueviolet)


> **Projekt:** autoreply    
> **Beschreibung:** Enterprise Autoreply Management und Compliance Plattform für Postfix-Umgebungen (GUI → API → Mailfilter)  
> **Sprache:** Perl 5.30+ (Mailfilter), Python 3.6+ (Services Agent), PHP 8.1+ (Web-Konsole), Bash (Installation)  
> **Zweck:** Betriebssichere und zentralisierte Verwaltung von Autoreply-Regeln für Postfix-Cluster
----

Zentrale Auto-Response Verwaltung für Postfix-Cluster

Die **Autoreply Plattform** ist eine vollumfängliche, produktionsreife Lösung zur zentralen Verwaltung automatischer E-Mail-Antworten in Postfix-basierten Mailinfrastrukturen.

Sie kombiniert eine robuste Mailfilter-Runtime mit einer zentralen Service- und API-Ebene sowie einer optionalen webbasierten Administrationsoberfläche. Der Fokus liegt auf stabilen Betriebsabläufen, klarer Trennung der Komponenten und nachvollziehbaren Änderungen.

---

## Zweck und Ziel

Die Plattform wurde entwickelt, um Autoreply-Regeln in Umgebungen mit mehreren Postfix-Servern kontrolliert, einheitlich und revisionssicher zu betreiben.

Typische Herausforderungen, die gelöst werden:

- Manuelle Pflege von Autoreplies auf einzelnen Servern
- Fehlende oder inkonsistente Backups
- Keine saubere Änderungshistorie
- Aufwendige Rollbacks
- Hohe Abhängigkeit der Fachabteilungen von der IT

Die Autoreply Plattform ersetzt diesen Ansatz durch eine zentrale Steuerung, ohne den Mailfluss unnötig zu verkomplizieren oder von Verwaltungsdiensten abhängig zu machen.

---

## Grundprinzip

- Mailverarbeitung erfolgt lokal auf jedem Postfix-Server
- Administration und Konfigurationspflege erfolgen zentral
- Jede Änderung wird validiert, versioniert und gesichert
- GUI und API sind nicht kritisch für den Mailfluss
- Rollbacks sind jederzeit möglich

---

## Hauptfunktionen

- Zentrale Verwaltung mehrerer Postfix-Server
- Einheitliche Autoreply-Regeln für E-Mail-Adressen und Domains
- Automatische Backups bei jeder Änderung
- Versionierung mit Diff- und Restore-Funktion
- Kontrolliertes Deployment auf einzelne oder alle Server
- Trennung von Runtime und Verwaltungslogik
- Audit- und Compliance-tauglicher Betrieb

---

## Zielumgebungen

Geeignet für:

- Unternehmen mit mehreren Postfix-Instanzen
- Organisationen mit 100 bis 2000 Fachanwendungen
- IT-Betrieb mit Änderungs- und Nachweispflichten
- Umgebungen mit klarer Trennung von Betrieb und Inhalt

Typische Einsatzbereiche:

- HR Bewerbungsbestätigungen
- Finanzabteilungen für Rechnungseingänge
- Support- und Ticket-Systeme
- Allgemeine Service- und Info-Adressen

---

## Repository Inhalte

Dieses Repository enthält die technische Kernplattform.

Enthalten sind:

- Autoreply Mailfilter (Postfix Pipe)
- Autoreply Services Agent (systemd Service mit HTTP API)
- Zentrale Konfigurations-, Backup- und Restore-Mechanismen
- Installations- und Betriebslogik
- Technische Dokumentation

Die Web-Konsole ist logisch Teil der Plattform, wird jedoch separat installiert und betrieben.

---

## Gesamtarchitektur

Die Plattform ist strikt modular aufgebaut.

### Komponenten

**Postfix**  
Übergibt eingehende E-Mails an den Autoreply Mailfilter.

**Autoreply Mailfilter**  
Verarbeitet E-Mails, prüft Regeln, Limits und Loop-Schutz und versendet Antworten.  
Keine Verwaltungslogik, keine API.

**Services Agent (HTTP API)**  
Zentrale Steuerinstanz für Konfigurationen.  
Validierung, Versionierung, Backup und Rollback.

**Autoresponder Console (WWW)**  
Optionale webbasierte Administrationsoberfläche.  
Greift ausschliesslich über die API zu und verarbeitet keine E-Mails.

### Datenfluss

GUI → Services Agent → JSON-Konfigurationen → Mailfilter → Postfix

Der Mailfluss bleibt auch bei Ausfall von GUI oder API vollständig funktionsfähig.

---

## Installation

Die technische Plattform wird vollständig über ein zentrales Installationsskript eingerichtet.

~~~bash
sudo ./install.sh
~~~

### Was install.sh installiert

- Anlegen von Service-Usern und Gruppen
- Deployment des Autoreply Mailfilters
- Installation des Services Agent
- Setzen aller benötigten Verzeichnis- und Dateiberechtigungen
- Installation und Aktivierung der systemd Services
- Initiales Anlegen von Konfigurations- und Backup-Verzeichnissen

### Was install.sh bewusst nicht installiert

- Web-Konsole
- Reverse Proxies
- TLS-Termination
- Externe Monitoring- oder Logging-Systeme

---

## Voraussetzungen

- Linux mit systemd
- Postfix installiert und aktiv
- Perl und Python verfügbar
- Root-Zugriff für Installation
- Interner Betrieb vorgesehen

---

## Web-Konsole (optional)

Die Autoresponder Console dient der komfortablen Administration und Visualisierung.  
Sie ist kein Bestandteil von install.sh, ergänzt die Plattform aber funktional.

### Funktionen

- Verwaltung von Autoreply-Einträgen (E-Mail und Domain)
- HTML- und Text-Templates mit Platzhaltern
- Live-Quelle und Origin-Vergleich
- Backup-, Diff- und Restore-Funktionen
- Verteilung auf mehrere Mailserver

Screenshots können unter `docs/screenshots/` abgelegt werden.

---

## Betriebskonzept

- Mailverarbeitung ist vollständig entkoppelt von API und GUI
- Konfigurationsänderungen erfolgen ausschliesslich über den Services Agent
- Keine manuellen JSON-Änderungen im Produktivbetrieb
- Jede Änderung erzeugt automatisch ein Backup
- Rollbacks sind jederzeit möglich

---

## Sicherheit

- Interner Betrieb ohne Public Exposure
- API-Zugriff über IP-Allowlisten
- Optionale TLS-Absicherung
- Dedizierte Service-User ohne Root-Betrieb
- Keine Secrets im Code oder Repository
- Nachvollziehbare Änderungen durch Backups und Diffs

---

## Dokumentation

- README.md Gesamtübersicht und Installation
- autoreply/README.md Mailfilter
- services-agent/README.md Service-Betrieb
- services-agent/README_API.md HTTP API

---

## Lizenz

Dieses Projekt steht unter der **MIT Lizenz**.

Siehe `LICENSE`.
