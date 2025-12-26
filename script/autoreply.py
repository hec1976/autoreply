#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Autoreply-Mailfilter für Postfix

Liest Mails von STDIN, prüft Filter- und Blacklist-Regeln und sendet ggf. eine
automatische Antwort gemäß Nutzer- und Server-Konfiguration.

Konfigurationsdateien (Standardpfade):
- /opt/mmbb_script/autoreply/config/autoreply_server.json
- /opt/mmbb_script/autoreply/json/autoreply_user.json

Voraussetzungen:
- Python 3.6+
- Zugriff auf /usr/sbin/sendmail (für Re-Injection)
- SMTP-Zugang (für Autoreply)

Aufruf (typisch via MTA/Filter):
  python3 autoreply.py <envelope-sender> <rcpt1> [rcpt2 ...]
"""

import mimetypes
import smtplib
import ssl
import sys
import json
import os
import os.path
import re
import traceback
import configparser
import fcntl

from contextlib import contextmanager
from email.message import Message, EmailMessage
from email import message_from_bytes
from email.utils import make_msgid, formataddr, parseaddr, getaddresses
from email.header import Header, decode_header
from subprocess import Popen, PIPE
from datetime import datetime
from typing import Dict, Any, List, Optional, Pattern

# -----------------------------------------------------------------------------
# Lokale Konfiguration via config.conf neben dem Script
#
# Zweck
#   Dieses Script soll keine Pfade hart verdrahten. Stattdessen werden die
#   wichtigsten Pfade aus einer INI Datei (config.conf) geladen, die im gleichen
#   Ordner liegt wie autoreply.py.
#
# Suchpfad
#   <script_dir>/config.conf
#
# Aufloesung von Pfaden
#   Absolute Pfade bleiben unveraendert:
#     /opt/mmbb_script/autoreply/config/autoreply_server.json
#
#   Relative Pfade werden relativ zum Script Ordner aufgeloest:
#     config/autoreply_server.json
#     -> <script_dir>/config/autoreply_server.json
#
# Sections und Keys in config.conf
#   [paths]
#     server_config
#     user_config
#     log_path
#     stats_path
#     limit_path
#
#   [runtime] optional
#     logging_enabled_override        true|false oder leer
#     limit_prune_sec_override        int Sekunden oder leer
#     limit_lock_path                 optionaler Pfad oder leer
#
# Defaults
#   Wenn config.conf fehlt oder ein Key nicht gesetzt ist, werden Defaults
#   verwendet. Damit bleibt das Script weiterhin lauffaehig, auch wenn die
#   config.conf noch nicht ausgerollt ist.
#
# Hinweis Betrieb
#   logging_enabled und LIMIT_PRUNE_SEC sind Laufzeitwerte. Sie werden spaeter in
#   main() gesetzt, nachdem server_settings und user_settings geladen sind.
# -----------------------------------------------------------------------------

def _script_dir() -> str:
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return os.getcwd()

def _abspath_from_script_dir(p: str) -> str:
    if not p:
        return p
    p = str(p).strip()
    if os.path.isabs(p):
        return p
    return os.path.normpath(os.path.join(_script_dir(), p))

def _parse_bool(v: str):
    if v is None:
        return None
    s = str(v).strip().lower()
    if s == "":
        return None
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return None

def _parse_int(v: str):
    if v is None:
        return None
    s = str(v).strip()
    if s == "":
        return None
    try:
        return int(s)
    except Exception:
        return None

def load_local_conf() -> dict:
    defaults_paths = {
        "server_config": "config/autoreply_server.json",
        "user_config":   "json/autoreply_user.json",
        "log_path":      "log/mmbb/autoreply_script.log",
        "stats_path":    "log/autoreply_stats.log",
        "limit_path":    "log/autoreply_limit.json",
    }
    defaults_runtime = {
        "logging_enabled_override": "",
        "limit_prune_sec_override": "",
        "limit_lock_path": "",
    }

    conf_path = os.path.join(_script_dir(), "config.conf")
    cfg = configparser.ConfigParser()
    cfg.read_dict({"paths": defaults_paths, "runtime": defaults_runtime})

    if os.path.isfile(conf_path):
        cfg.read(conf_path, encoding="utf-8")

    p = dict(cfg["paths"])
    r = dict(cfg["runtime"]) if "runtime" in cfg else {}

    out = {
        "SERVER_CONFIG_PATH": _abspath_from_script_dir(p.get("server_config", defaults_paths["server_config"])),
        "USER_CONFIG_PATH":   _abspath_from_script_dir(p.get("user_config", defaults_paths["user_config"])),
        "LOG_PATH":           _abspath_from_script_dir(p.get("log_path", defaults_paths["log_path"])),
        "STATS_PATH":         _abspath_from_script_dir(p.get("stats_path", defaults_paths["stats_path"])),
        "LIMIT_PATH":         _abspath_from_script_dir(p.get("limit_path", defaults_paths["limit_path"])),

        "LOGGING_ENABLED_OVERRIDE": _parse_bool(r.get("logging_enabled_override", "")),
        "LIMIT_PRUNE_SEC_OVERRIDE": _parse_int(r.get("limit_prune_sec_override", "")),
        "LIMIT_LOCK_PATH_OVERRIDE": _abspath_from_script_dir(r.get("limit_lock_path", "").strip())
                                   if str(r.get("limit_lock_path", "")).strip() else None,
    }
    return out

# -----------------------------------------------------------------------------
# Pfade & globale Flags
# -----------------------------------------------------------------------------
_conf = load_local_conf()

SERVER_CONFIG_PATH = _conf["SERVER_CONFIG_PATH"]
USER_CONFIG_PATH   = _conf["USER_CONFIG_PATH"]
LOG_PATH           = _conf["LOG_PATH"]
STATS_PATH         = _conf["STATS_PATH"]
LIMIT_PATH         = _conf["LIMIT_PATH"]

LIMIT_LOCK_PATH = (_conf.get("LIMIT_LOCK_PATH_OVERRIDE") or (LIMIT_PATH + ".lock"))

# runtime defaults, werden in main() gesetzt
LIMIT_PRUNE_SEC = 0
logging_enabled = False

# -----------------------------------------------------------------------------
# Regex-Cache
# -----------------------------------------------------------------------------
_REGEX_CACHE: Dict[str, Pattern] = {}
def _compile(pat: str) -> Pattern:
    return _REGEX_CACHE.setdefault(pat, re.compile(pat))

def _match_any(patterns, text: str) -> bool:
    if not text:
        return False
    if isinstance(patterns, str):
        patterns = [patterns]
    try:
        return any(_compile(p).search(text) for p in patterns)
    except re.error as e:
        log_error(f"REGEX_FAIL patterns={patterns} err={e}")
        return False

# -----------------------------------------------------------------------------
# Datei/Log-Helfer
# -----------------------------------------------------------------------------
def _ensure_dir_for(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, mode=0o750, exist_ok=True)

def _atomic_write(path: str, data: str) -> None:
    _ensure_dir_for(path)
    tmp = path + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)

def log(message: str) -> None:
    if logging_enabled:
        try:
            _ensure_dir_for(LOG_PATH)
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(LOG_PATH, 'a+', encoding='utf-8') as f:
                f.write(f"{ts}: {message}\n")
        except Exception as e:
            print(f"Log-Fehler: {e}", file=sys.stderr)

def log_error(message: str) -> None:
    """
    Fehler immer loggen (auch wenn logging_enabled = False),
    damit Monit nur Fehler ueberwachen kann.
    """
    try:
        _ensure_dir_for(LOG_PATH)
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_PATH, 'a+', encoding='utf-8') as f:
            f.write(f"{ts}: ERROR {message}\n")
    except Exception as e:
        print(f"Log-Fehler: {e}", file=sys.stderr)

    try:
        print(f"ERROR {message}", file=sys.stderr)
    except Exception:
        pass

def _rotate_stats_monthly(stats_path: str) -> None:
    """
    Aktiver Name bleibt gleich (autoreply_stats.log).
    Beim Monatswechsel wird die bestehende Datei umbenannt nach:
      autoreply_stats_YYYY-MM.log
    Danach entsteht automatisch wieder eine neue autoreply_stats.log.
    """
    try:
        if not os.path.isfile(stats_path):
            return

        st = os.stat(stats_path)
        last_month = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m')
        now_month = datetime.now().strftime('%Y-%m')

        if last_month == now_month:
            return

        base_dir = os.path.dirname(stats_path)
        base_name = os.path.basename(stats_path)
        stem = base_name[:-4] if base_name.lower().endswith('.log') else base_name

        rotated = os.path.join(base_dir, f"{stem}_{last_month}.log")

        if os.path.exists(rotated):
            i = 1
            while True:
                cand = os.path.join(base_dir, f"{stem}_{last_month}_{i}.log")
                if not os.path.exists(cand):
                    rotated = cand
                    break
                i += 1

        os.rename(stats_path, rotated)
    except Exception as e:
        try:
            print(f"Statistik-Rotation fehlgeschlagen: {e}", file=sys.stderr)
        except Exception:
            pass

def log_stat(event: str, sender: str, recipient: str, subject: str, template: str) -> None:
    try:
        _ensure_dir_for(STATS_PATH)
        _rotate_stats_monthly(STATS_PATH)

        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(STATS_PATH, 'a+', encoding='utf-8') as f:
            f.write(f"{ts};{event};{sender};{recipient};{subject};{template}\n")
    except Exception as e:
        print(f"Statistik-Log-Fehler: {e}", file=sys.stderr)

def log_blocked_autoreply(message: Message, reason: str) -> None:
    log_stat(
        'autoreply_blocked',
        message.get('From', ''),
        message.get('To', ''),
        get_decoded_header(message, 'Subject'),
        reason
    )

# -----------------------------------------------------------------------------
# Limits Lock (prozessweit)
# -----------------------------------------------------------------------------
@contextmanager
def _limits_flock():
    _ensure_dir_for(LIMIT_LOCK_PATH)
    fh = open(LIMIT_LOCK_PATH, "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()

def _compute_limit_prune_sec(user_settings: dict) -> int:
    """
    Aufraeumfenster basiert auf groesstem reply_period_hours aus allen Regeln.
    Entfernt nur Eintraege, die fuer kein konfiguriertes Fenster mehr relevant sind.
    """
    mx = 24
    try:
        rules = user_settings.get("autoreply") or []
        for r in rules:
            try:
                h = int(r.get("reply_period_hours", 24))
                if h > mx:
                    mx = h
            except Exception:
                pass
    except Exception:
        pass
    return int(mx) * 3600

def _prune_limits(limits: dict, max_age_sec: int) -> dict:
    if not isinstance(limits, dict) or max_age_sec <= 0:
        return limits if isinstance(limits, dict) else {}

    now = datetime.now()
    out: dict = {}

    for rcpt, senders in limits.items():
        if not isinstance(senders, dict):
            continue

        new_senders: dict = {}
        for snd, ts_list in senders.items():
            if not isinstance(ts_list, list):
                continue

            kept: List[str] = []
            for t in ts_list:
                try:
                    dt = datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
                    if (now - dt).total_seconds() < max_age_sec:
                        kept.append(t)
                except Exception:
                    pass

            if kept:
                new_senders[snd] = kept[-50:]

        if new_senders:
            out[rcpt] = new_senders

    return out

# -----------------------------------------------------------------------------
# JSON & Limits
# -----------------------------------------------------------------------------
def load_json(path: str, missing_message: str) -> dict:
    if not os.path.isfile(path):
        print(missing_message)
        sys.exit(1)
    try:
        with open(path, 'r', encoding='utf-8') as json_file:
            return json.load(json_file)
    except Exception as e:
        print(f"Fehler beim Lesen von {path}: {e}")
        sys.exit(1)

def load_limits() -> dict:
    if not os.path.isfile(LIMIT_PATH):
        return {}
    try:
        with open(LIMIT_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_limits(limits: dict) -> None:
    try:
        _atomic_write(LIMIT_PATH, json.dumps(limits, ensure_ascii=False, indent=2))
    except Exception as e:
        log_error(f"LIMIT_SAVE_FAIL err={e}")

# -----------------------------------------------------------------------------
# Limits pro Absender/Empfänger
# -----------------------------------------------------------------------------
def is_limit_reached(recipient: str, sender: str, max_replies: int, period_hours: int) -> bool:
    now = datetime.now()
    period_sec = int(period_hours) * 3600

    with _limits_flock():
        limits = load_limits()

        if LIMIT_PRUNE_SEC > 0:
            pruned = _prune_limits(limits, LIMIT_PRUNE_SEC)
            if pruned != limits:
                limits = pruned
                save_limits(limits)

        user_limits = limits.get(recipient, {})
        timestamps = user_limits.get(sender, [])

        recent_times: List[str] = []
        for t in timestamps:
            try:
                dt = datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
                if (now - dt).total_seconds() < period_sec:
                    recent_times.append(t)
            except Exception:
                pass

        return len(recent_times) >= int(max_replies)

def register_autoreply(recipient: str, sender: str) -> None:
    now_str = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    with _limits_flock():
        limits = load_limits()

        if LIMIT_PRUNE_SEC > 0:
            limits = _prune_limits(limits, LIMIT_PRUNE_SEC)

        user_limits = limits.setdefault(recipient, {})
        timestamps = user_limits.setdefault(sender, [])
        timestamps.append(now_str)

        user_limits[sender] = timestamps[-50:]
        limits[recipient] = user_limits
        save_limits(limits)

# -----------------------------------------------------------------------------
# Mail & Header Utilities
# -----------------------------------------------------------------------------
def replace_placeholders(text: str, context: dict) -> str:
    if not isinstance(text, str):
        return ""
    for key, value in context.items():
        text = text.replace(key, value or '')
    return text

def decode_header_to_unicode(header_value: Optional[str]) -> str:
    if not header_value:
        return ''
    decoded_fragments = decode_header(header_value)
    out = []
    for fragment, encoding in decoded_fragments:
        if isinstance(fragment, bytes):
            try:
                out.append(fragment.decode(encoding or 'utf-8', errors='replace'))
            except Exception:
                out.append(fragment.decode('utf-8', errors='replace'))
        else:
            out.append(fragment)
    return ''.join(out)

def get_decoded_header(msg: Message, name: str, fallback: str = '') -> str:
    return decode_header_to_unicode(msg.get(name, fallback))

def encode_address(addr: str) -> str:
    name, email = parseaddr(addr)
    if name:
        return formataddr((str(Header(name, 'utf-8')), email))
    return email

def _extract_body_text(msg: Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
        for part in msg.walk():
            if part.get_content_type() == "text/html" and "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
        return ""
    payload = msg.get_payload(decode=True) or b""
    return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")

# -----------------------------------------------------------------------------
# Plaintext Cleanup (Outlook Winkelklammer Links)
# -----------------------------------------------------------------------------
_RE_ANGLE_URL = re.compile(r'(?P<label>[^\n<>]{2,}?)<(?P<url>https?://[^>\s]+)>')
_RE_MAILTO = re.compile(r'(?i)<mailto:([^>\s]+)>')
_RE_BARE_ANGLE_URL = re.compile(r'<(https?://[^>\s]+)>')

def _cleanup_plaintext(s: str) -> str:
    """
    Bereinigt Outlook/Exchange Klartext Links.
    Beispiele:
      Text<https://example>  -> Text (https://example)
      <https://example>      -> (https://example)
      mail@x<mailto:mail@x>  -> mail@x
    """
    if not s:
        return ""

    def _repl(m):
        label = (m.group('label') or '').rstrip()
        url = m.group('url')
        if label.endswith(url):
            return label
        return f"{label} ({url})"

    s = _RE_ANGLE_URL.sub(_repl, s)
    s = _RE_BARE_ANGLE_URL.sub(lambda m: f"({m.group(1)})", s)
    s = _RE_MAILTO.sub("", s)

    return s.strip()

# -----------------------------------------------------------------------------
# Filterlogik (unterstützt header_allow als Liste ODER Dict)
# -----------------------------------------------------------------------------
def blocked_by_filters(msg: Message, user_cfg: dict) -> bool:
    cfg = user_cfg.get("filters", {}) or {}

    for hdr, patterns in cfg.get("header_block", {}).items():
        if _match_any(patterns, get_decoded_header(msg, hdr)):
            return True

    allow_list = cfg.get("header_allow", [])
    if isinstance(allow_list, list) and allow_list:
        all_headers = " ".join([f"{k}: {decode_header_to_unicode(v)}" for k, v in msg.items()])
        if not _match_any(allow_list, all_headers):
            return True
    else:
        allow_dict = cfg.get("header_allow", {})
        if isinstance(allow_dict, dict) and allow_dict:
            if not any(
                patterns and _match_any(patterns, get_decoded_header(msg, h))
                for h, patterns in allow_dict.items()
            ):
                return True

    body = _extract_body_text(msg)
    if _match_any(cfg.get("body_block", []), body):
        return True
    body_allow = cfg.get("body_allow", [])
    if body_allow and not _match_any(body_allow, body):
        return True

    return False

# -----------------------------------------------------------------------------
# Body Auflösung: INLINE ONLY
# -----------------------------------------------------------------------------
def resolve_body_content(recipient_config: dict) -> str:
    body = recipient_config.get('body', '')
    return body if isinstance(body, str) else ''

# -----------------------------------------------------------------------------
# Blacklist & Header Checks
# -----------------------------------------------------------------------------
def is_blacklisted(sender: str, entry_blacklist=None, user_blacklist=None) -> bool:
    s = (sender or '').lower()
    sender_domain = s.split('@')[-1] if '@' in s else s
    for blist in (entry_blacklist, user_blacklist):
        if not blist:
            continue
        for entry in blist:
            e = (entry or '').lower()
            if '@' in e and s == e:
                return True
            if sender_domain == e:
                return True
    return False

def check_noreply(header: str) -> bool:
    name = str(header).split('@')[0].lower().replace('-', '').replace('_', '').replace('.', '')
    return 'noreply' in name or 'donotreply' in name or 'dontreply' in name

def check_autoreply(message: Message, original_id: Optional[str], server_settings: dict) -> bool:
    checks = server_settings.get("autoreply_checks", {}) or {}
    log(f"Prüfe auf Autoreply-Header für ID {original_id}")

    try:
        if checks.get("auto_submitted", True):
            val = (message.get('Auto-Submitted') or '').lower()
            if val and val not in ('no',):
                log("Auto-Submitted gesetzt, keine Autoreply")
                log_blocked_autoreply(message, 'auto_submitted')
                return True

        if checks.get("x_auto_response_suppress", True):
            xars = (message.get('X-Auto-Response-Suppress') or '')
            xars_list = [v.strip() for v in xars.split(',') if v.strip()]
            if any(v in ('DR', 'AutoReply', 'All', 'OOF') for v in xars_list):
                log("X-Auto-Response-Suppress (DR/AutoReply/All/OOF), keine Autoreply")
                log_blocked_autoreply(message, 'x_auto_response_suppress')
                return True

        if checks.get("list_headers", True):
            if message.get('List-Id') or message.get('List-Unsubscribe'):
                log("List-Id/List-Unsubscribe vorhanden, keine Autoreply")
                log_blocked_autoreply(message, 'list_headers')
                return True

        if checks.get("feedback_id", True):
            if message.get('Feedback-ID'):
                log("Feedback-ID vorhanden, keine Autoreply")
                log_blocked_autoreply(message, 'feedback_id')
                return True

        if checks.get("precedence", True):
            if str(message.get('Precedence', '')).lower() in ('bulk', 'auto_reply', 'list'):
                log("Precedence bulk/auto_reply/list, keine Autoreply")
                log_blocked_autoreply(message, 'precedence')
                return True

        if checks.get("x_autoreply", True):
            if message.get('X-Autoreply') or message.get('X-Autorespond'):
                log("X-Autoreply/X-Autorespond vorhanden, keine Autoreply")
                log_blocked_autoreply(message, 'x_autoreply')
                return True

        if checks.get("empty_envelope_from", True):
            if hasattr(message, 'envelope_from') and (not message.envelope_from or message.envelope_from.strip() == ''):
                log("Envelope-From leer (Bounce/NDR), keine Autoreply")
                log_blocked_autoreply(message, 'empty_envelope_from')
                return True

        if checks.get("system_from", True):
            if any(x in str(message.get('From', '')).lower() for x in ['mailer-daemon', 'postmaster', 'daemon', 'bounce']):
                log("Absender enthält Systemaccount, keine Autoreply")
                log_blocked_autoreply(message, 'system_from')
                return True

        if checks.get("system_replyto", True):
            if any(x in str(message.get('Reply-To', '')).lower() for x in ['mailer-daemon', 'postmaster', 'daemon', 'bounce']):
                log("Reply-To enthält Systemaccount, keine Autoreply")
                log_blocked_autoreply(message, 'system_replyto')
                return True

        if checks.get("noreply", True):
            if check_noreply(message.get('From', '')):
                log(f"Absender ist NoReply-Adresse: {message.get('From')}, keine Autoreply")
                log_blocked_autoreply(message, 'noreply')
                return True

    except Exception as e:
        log_error(f"CHECK_FAIL id={original_id} err={e}")
        return True

    log(f"Keine Autoreply-Header gefunden für ID {original_id}, Autoreply möglich")
    return False

# -----------------------------------------------------------------------------
# Empfänger Ermittlung / Re Injection
# -----------------------------------------------------------------------------
def _first_email_from_header(raw: str) -> Optional[str]:
    if not raw:
        return None
    addrs = [addr for _, addr in getaddresses([raw]) if addr]
    return addrs[0] if addrs else None

def get_recipient_address(message: Message, recipients: List[str]) -> Optional[str]:
    for header in ('Delivered-To', 'X-Original-To', 'To'):
        val = message.get(header)
        email = _first_email_from_header(val) if val else None
        if email:
            return email
    return recipients[0] if recipients else None

def reinject_email(message_bytes: bytes, sender: str, recipients: List[str], original_id: Optional[str]) -> None:
    recipients_joined = ','.join(recipients)
    log(f'Re-injecting Original-Mail (ID: {original_id}) an: {recipients_joined}')
    try:
        process = Popen(
            ['/usr/sbin/sendmail', '-f', sender, '-G', '-oi', recipients_joined],
            stdin=PIPE
        )
        process.communicate(message_bytes)
    except Exception as e:
        log_error(f"REINJECT_FAIL id={original_id} err={e}")

# -----------------------------------------------------------------------------
# Mail erzeugen und versenden
# -----------------------------------------------------------------------------
def _html_to_text(html: str) -> str:
    if not html:
        return ''
    txt = re.sub(r'(?is)<(script|style).*?</\1>', '', html)
    txt = re.sub(r'(?is)<br\s*/?>', '\n', txt)
    txt = re.sub(r'(?is)</p\s*>', '\n\n', txt)
    txt = re.sub(r'(?is)<.*?>', '', txt)
    return re.sub(r'\n{3,}', '\n\n', txt).strip()

def generate_email(sender: str, recipient, original_id: Optional[str], replyto: str,
                   subject: str, body: str, html: bool,
                   attachment_path: Optional[str] = None, test: bool = False) -> EmailMessage:
    message = EmailMessage()

    def _clean(h: str) -> str:
        return (h or '').replace('\r', '').replace('\n', '')

    message['From'] = encode_address(_clean(sender)) if sender else ''
    if isinstance(recipient, list):
        message['To'] = ", ".join([encode_address(_clean(r)) for r in recipient])
    else:
        message['To'] = encode_address(_clean(recipient)) if recipient else ''
    message['Subject'] = str(Header(_clean(subject), 'utf-8'))
    message['Message-ID'] = make_msgid()
    message['Reply-To'] = encode_address(_clean(replyto)) if replyto else ''

    if not test:
        if original_id:
            message['In-Reply-To'] = _clean(original_id)
        message['Auto-Submitted'] = 'auto-replied'
        message['X-Autoreply'] = 'yes'
        message['X-Auto-Response-Suppress'] = 'All'
        message['Precedence'] = 'auto_reply'

    if html:
        text_part = _html_to_text(body)
        message.set_content(text_part or '')
        message.add_alternative(body or '', subtype='html')
    else:
        message.set_content(body or '')

    if attachment_path:
        attachment_filename = os.path.basename(attachment_path)
        mime_type, _ = mimetypes.guess_type(attachment_path)
        maintype, mime_subtype = (mime_type.split('/', 1) if mime_type else ('application', 'octet-stream'))
        try:
            with open(attachment_path, 'rb') as ap:
                message.add_attachment(
                    ap.read(),
                    maintype=maintype,
                    subtype=mime_subtype,
                    filename=attachment_filename
                )
        except Exception as e:
            log_error(f"ATTACH_FAIL file={attachment_path} err={e}")
    return message

def send_email(message: EmailMessage, server_settings: dict) -> None:
    try:
        smtp_host = server_settings.get('SMTP', 'localhost')
        smtp_port = int(server_settings.get('port', 25))
        use_ssl   = bool(server_settings.get('ssl'))
        use_tls   = bool(server_settings.get('starttls'))
        use_auth  = bool(server_settings.get('smtpauth'))
        username  = server_settings.get('username', '')
        password  = server_settings.get('password', '')

        context = ssl.create_default_context()

        if use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10, context=context) as srv:
                if use_auth:
                    srv.login(username, password)
                srv.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as srv:
                if use_tls:
                    srv.starttls(context=context)
                if use_auth:
                    srv.login(username, password)
                srv.send_message(message)
    except Exception as e:
        log_error(f"SMTP_FAIL to={message.get('To','')} subj={message.get('Subject','')} err={e}")

# -----------------------------------------------------------------------------
# Autoreply senden
# -----------------------------------------------------------------------------
def send_autoreply_email(sender: str, recipient_email: str, recipient_config: dict,
                         original_msg: Message, original_id: Optional[str],
                         server_settings: dict, user_settings: dict) -> None:
    log('Autoreply ausgelöst')
    log(f'Absender: {sender}')
    log(f'Message-Id: {original_id}')
    log(f'Regel-Empfänger: {recipient_email}')

    if blocked_by_filters(original_msg, user_settings):
        subject_log = get_decoded_header(original_msg, 'Subject')
        log(f"Header/Body-Filter ausgelöst, keine Autoreply an {sender}.")
        log_stat('filter_skip', sender, recipient_email, subject_log, '-')
        return

    entry_blacklist = recipient_config.get('blacklist', [])
    user_blacklist  = user_settings.get('blacklist', [])
    if is_blacklisted(sender, entry_blacklist, user_blacklist):
        log(f'Sender {sender} ist geblacklistet, keine Autoreply.')
        return

    max_replies  = int(recipient_config.get('max_replies_per_sender', 3))
    period_hours = int(recipient_config.get('reply_period_hours', 24))
    if is_limit_reached(recipient_email, sender, max_replies, period_hours):
        subject_log = get_decoded_header(original_msg, 'Subject')
        log(f"Autoreply-Limit erreicht für {recipient_email} an {sender}: max {max_replies} pro {period_hours}h.")
        log_stat('autoreply_limit', sender, recipient_email, subject_log, '-')
        return

    if recipient_email == sender:
        return

    try:
        html = bool(recipient_config.get('html', False))
        body_raw = resolve_body_content(recipient_config)

        reply_to = recipient_config.get('reply-to', sender)
        from_field = recipient_config.get('from', '')
        subject_template = recipient_config.get('subject', '')

        orig_body = _extract_body_text(original_msg)
        orig_body = _cleanup_plaintext(orig_body)

        placeholders = {
            '{ORIGINAL_DESTINATION}': recipient_email,
            '{ORIGINAL_SUBJECT}': get_decoded_header(original_msg, 'Subject'),
            '{ORIGINAL_SENDER}': get_decoded_header(original_msg, 'From', sender),
            '{ORIGINAL_DATE}': get_decoded_header(original_msg, 'Date', ''),
            '{ORIGINAL_BODY}': orig_body,
        }

        subject = replace_placeholders(subject_template, placeholders)
        body    = replace_placeholders(body_raw, placeholders)

        message = generate_email(
            from_field,
            sender,
            original_id,
            reply_to,
            subject,
            body,
            html
        )
        send_email(message, server_settings)
        register_autoreply(recipient_email, sender)

        log_stat(
            'sent_autoreply',
            sender,
            recipient_email,
            subject,
            recipient_config.get('email', recipient_config.get('domain', ''))
        )
    except Exception as e:
        log_error(f"AUTOREPLY_SEND_FAIL id={original_id} rcpt={recipient_email} sender={sender} err={e}")

# -----------------------------------------------------------------------------
# Regel Matching
# -----------------------------------------------------------------------------
def autoreply(sender: str, recipients: List[str], original_msg: Message,
              original_id: Optional[str], server_settings: dict, user_settings: dict) -> None:
    rules = user_settings.get('autoreply') or []

    for recipient in rules:
        if 'email' in recipient:
            emails = recipient['email']
            if not isinstance(emails, list):
                emails = [emails]
            for email in emails:
                for rcpt in recipients:
                    if email == rcpt:
                        send_autoreply_email(sender, email, recipient, original_msg, original_id, server_settings, user_settings)
                        return

    for recipient in rules:
        if 'domain' in recipient:
            domains = recipient['domain']
            if not isinstance(domains, list):
                domains = [domains]
            for domain in domains:
                for rcpt in recipients:
                    try:
                        recipient_domain = rcpt.split('@')[1].lower()
                        if recipient_domain == domain.lower():
                            send_autoreply_email(sender, rcpt, recipient, original_msg, original_id, server_settings, user_settings)
                            return
                    except IndexError:
                        log(f'Ungültige E-Mail-Adresse: {rcpt}')

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ('help', '--help', '-h'):
        print(
            "Verwendung (über Filter/pipe typischerweise mit Envelope-Sender + Empfänger):\n"
            "  python3 autoreply.py <sender> <rcpt1> [rcpt2 ...]\n\n"
            "Konfiguration:\n"
            f"  Server: {SERVER_CONFIG_PATH}\n"
            f"  User  : {USER_CONFIG_PATH}\n"
        )
        sys.exit(0)

    server_settings = load_json(
        SERVER_CONFIG_PATH,
        "Fehler: autoreply_server.json fehlt!\nBitte anlegen."
    )
    user_settings = load_json(
        USER_CONFIG_PATH,
        "Fehler: autoreply_user.json fehlt!\nBitte anlegen."
    )

    global logging_enabled
    if _conf.get("LOGGING_ENABLED_OVERRIDE") is None:
        logging_enabled = bool(server_settings.get("logging", False))
    else:
        logging_enabled = bool(_conf.get("LOGGING_ENABLED_OVERRIDE"))
    
    global LIMIT_PRUNE_SEC
    if _conf.get("LIMIT_PRUNE_SEC_OVERRIDE") is None:
        LIMIT_PRUNE_SEC = _compute_limit_prune_sec(user_settings)
    else:
        LIMIT_PRUNE_SEC = int(_conf.get("LIMIT_PRUNE_SEC_OVERRIDE"))

    integration_mode = server_settings.get("integration_mode", "bcc")

    sender = sys.argv[1]
    recipient_list = sys.argv[2:]
    mail_bytes = sys.stdin.buffer.read()
    original_msg = message_from_bytes(mail_bytes)

    try:
        original_id = (original_msg['Message-ID']).replace('\r', '').replace('\n', '').replace(' ', '')
    except Exception:
        original_id = None

    if integration_mode != "bcc":
        recipients = recipient_list
        reinject_email(mail_bytes, sender, recipients, original_id or 'ohne-Message-ID')
        log("Integration Mode: klassisch, Mail wurde reinjected.")
    else:
        actual_recipient = get_recipient_address(original_msg, recipient_list)
        if actual_recipient:
            recipients = [actual_recipient]
            log(f"Integration Mode: BCC, tatsächlicher Empfänger aus Header: {actual_recipient}")
        else:
            recipients = recipient_list
            log(f"Integration Mode: BCC, kein Empfänger im Header gefunden, nutze Empfängerliste: {recipient_list}")

    if not check_autoreply(original_msg, original_id or 'ohne-Message-ID', server_settings):
        autoreply(sender, recipients, original_msg, original_id, server_settings, user_settings)

if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        sys.exit(0)
    except BaseException as exc:
        log_error(f"UNCAUGHT {exc.__class__.__name__} {traceback.format_exc()}")
        raise