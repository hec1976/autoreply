#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Autoreply-Mailfilter fuer Postfix (Version 2.6)

Liest Mails von STDIN, prueft Filter- und Blacklist-Regeln und sendet bei Bedarf
eine automatische Antwort gemaess Nutzer- und Server-Konfiguration.

Konfigurationsdateien (Standardpfade):
- /opt/mmbb_script/autoreply/config/autoreply_server.json
- /opt/mmbb_script/autoreply/json/autoreply_user.json

Voraussetzungen:
- Python 3.6+
- Zugriff auf /usr/sbin/sendmail (fuer Re-Injection)
- SMTP-Zugang (fuer Autoreply)

Aufruf:
  python3 autoreply.py <envelope-sender> <rcpt1> [rcpt2 ...]
"""

import csv
import fcntl
import json
import mimetypes
import os
import re
import smtplib
import socket
import ssl
import sys
import traceback

from contextlib import contextmanager
from datetime import datetime
from email import message_from_bytes
from email.header import Header, decode_header
from email.message import Message, EmailMessage
from email.utils import formataddr, getaddresses, make_msgid, parseaddr
from subprocess import Popen, PIPE, run
from typing import Dict, List, Optional, Pattern, Any, Tuple


VERSION = "2.6"

SERVER_CONFIG_PATH = '/opt/mmbb_script/autoreply/config/autoreply_server.json'
USER_CONFIG_PATH = '/opt/mmbb_script/autoreply/json/autoreply_user.json'

LOG_PATH = '/var/log/mmbb/autoreply.log'
STATS_PATH = '/opt/mmbb_script/autoreply/log/autoreply_stats.log'
STATS_LOCK_PATH = STATS_PATH + ".lock"

LIMIT_PATH = '/opt/mmbb_script/autoreply/log/autoreply_limit.json'
LIMIT_LOCK_PATH = LIMIT_PATH + ".lock"

LIMIT_PRUNE_SEC = 0
logging_enabled = False

REGEX_DEFAULT_IGNORECASE = False

# Python 3.6 kompatibel
_REGEX_CACHE: Dict[str, Pattern[str]] = {}


def _compile(pat: str) -> Pattern[str]:
    key = f"{'i' if REGEX_DEFAULT_IGNORECASE else 'n'}::{pat}"
    if key in _REGEX_CACHE:
        return _REGEX_CACHE[key]
    flags = re.IGNORECASE if REGEX_DEFAULT_IGNORECASE else 0
    _REGEX_CACHE[key] = re.compile(pat, flags)
    return _REGEX_CACHE[key]


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
    if not logging_enabled:
        return
    try:
        _ensure_dir_for(LOG_PATH)
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(f"{ts}: {message}\n")
    except Exception as e:
        print(f"Log-Fehler: {e}", file=sys.stderr)


def log_error(message: str) -> None:
    try:
        _ensure_dir_for(LOG_PATH)
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(f"{ts}: ERROR {message}\n")
    except Exception as e:
        print(f"Log-Fehler: {e}", file=sys.stderr)

    try:
        print(f"ERROR {message}", file=sys.stderr)
    except Exception:
        pass


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


@contextmanager
def _stats_flock():
    _ensure_dir_for(STATS_LOCK_PATH)
    fh = open(STATS_LOCK_PATH, "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def _compute_limit_prune_sec(user_settings: dict) -> int:
    mx = 24
    rules = user_settings.get("autoreply") or []
    for r in rules:
        v = r.get("reply_period_hours", 24)
        try:
            h = int(v)
            if h > mx:
                mx = h
        except Exception as e:
            log_error(f"CFG_WARN reply_period_hours invalid value={v} err={e}")
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


def load_json(path: str, missing_message: str) -> dict:
    if not os.path.isfile(path):
        print(missing_message)
        sys.exit(1)
    try:
        with open(path, 'r', encoding='utf-8') as json_file:
            data = json.load(json_file)
        return data if isinstance(data, dict) else {}
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
    except Exception as e:
        log_error(f"LIMIT_LOAD_FAIL err={e}")
        try:
            bad = LIMIT_PATH + ".bad"
            os.replace(LIMIT_PATH, bad)
            log_error(f"LIMIT_FILE_MOVED to={bad}")
        except Exception:
            pass
        return {}


def save_limits(limits: dict) -> None:
    try:
        _atomic_write(LIMIT_PATH, json.dumps(limits, ensure_ascii=False, indent=2))
    except Exception as e:
        log_error(f"LIMIT_SAVE_FAIL err={e}")


def normalize_email(raw: str) -> str:
    if not raw:
        return ""
    raw = str(raw).strip()

    if raw == "<>":
        return ""

    _, addr = parseaddr(raw)
    addr = (addr or "").strip().lower()
    addr = re.sub(r'^[<\s]+|[>\s]+$', '', addr)
    if addr == "<>":
        return ""
    return addr


def normalize_email_list(items: List[str]) -> List[str]:
    out: List[str] = []
    for it in items or []:
        addr = normalize_email(it)
        if addr:
            out.append(addr)

    seen = set()
    uniq: List[str] = []
    for a in out:
        if a not in seen:
            uniq.append(a)
            seen.add(a)
    return uniq


def _match_any(patterns: Any, text: str) -> bool:
    if not text:
        return False
    if isinstance(patterns, str):
        patterns = [patterns]
    try:
        return any(_compile(p).search(text) for p in patterns if isinstance(p, str) and p != "")
    except re.error as e:
        log_error(f"REGEX_FAIL patterns={patterns} err={e}")
        return False


def check_and_register_limit(
    recipient: str,
    sender: str,
    max_replies: int,
    period_hours: int,
    prune_sec: Optional[int] = None
) -> bool:
    """
    prune_sec Verhalten:
    - Wenn prune_sec gesetzt ist (>0), wird genau dieser Wert genutzt.
    - Wenn prune_sec None oder <=0 ist:
        - Falls LIMIT_PRUNE_SEC durch main() initialisiert wurde, wird der genutzt
        - Sonst (z.B. direkter Funktionsaufruf im Test) faellt es auf max(period_sec, 24h) zurueck
    """
    recipient = normalize_email(recipient)
    sender = normalize_email(sender)

    if not recipient or not sender:
        return False

    now = datetime.now()
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S")
    period_sec = int(period_hours) * 3600

    with _limits_flock():
        limits = load_limits()

        eff_prune = prune_sec
        if not eff_prune or int(eff_prune) <= 0:
            eff_prune = LIMIT_PRUNE_SEC if LIMIT_PRUNE_SEC > 0 else max(period_sec, 24 * 3600)

        pruned = _prune_limits(limits, int(eff_prune))
        if pruned != limits:
            limits = pruned

        user_limits = limits.setdefault(recipient, {})
        timestamps = user_limits.setdefault(sender, [])

        recent: List[str] = []
        for t in timestamps:
            try:
                dt = datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
                if (now - dt).total_seconds() < period_sec:
                    recent.append(t)
            except Exception:
                pass

        if len(recent) >= int(max_replies):
            user_limits[sender] = recent[-50:]
            limits[recipient] = user_limits
            save_limits(limits)
            return True

        recent.append(now_str)
        user_limits[sender] = recent[-50:]
        limits[recipient] = user_limits
        save_limits(limits)
        return False


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
    email = (email or "").strip()
    if not email:
        return ""
    if name:
        return formataddr((str(Header(name, 'utf-8')), email))
    return email


def _extract_body_text(msg: Message) -> str:
    if msg.is_multipart():
        plain = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    plain = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace")
                    if plain.strip():
                        return plain
                except Exception:
                    pass

        for part in msg.walk():
            if part.get_content_type() == "text/html" and "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    html = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace")
                    if html:
                        return html
                except Exception:
                    pass

        return plain or ""

    payload = msg.get_payload(decode=True) or b""
    return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")


_RE_ANGLE_URL = re.compile(r'(?P<label>[^\n<>]{2,200})<(?P<url>https?://[^>\s]+)>')
_RE_MAILTO = re.compile(r'(?i)<mailto:([^>\s]+)>')
_RE_BARE_ANGLE_URL = re.compile(r'<(https?://[^>\s]+)>')


def _cleanup_plaintext(s: str) -> str:
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


def _html_escape(s: str) -> str:
    if s is None:
        return ""
    s = str(s)
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", "&#39;")
    return s


def blocked_by_filters(msg: Message, user_cfg: dict) -> bool:
    cfg = user_cfg.get("filters", {}) or {}

    for hdr, patterns in (cfg.get("header_block", {}) or {}).items():
        if _match_any(patterns, get_decoded_header(msg, hdr)):
            log(f"Filter header_block match header={hdr}")
            return True

    allow_list = cfg.get("header_allow", [])
    if isinstance(allow_list, list) and allow_list:
        parts = []
        for k, v in msg.items():
            parts.append(f"{k}: {decode_header_to_unicode(v)}")
        all_headers = " ".join(parts)[:20000]
        if not _match_any(allow_list, all_headers):
            log("Filter header_allow list kein Match")
            return True
    else:
        allow_dict = cfg.get("header_allow", {})
        if isinstance(allow_dict, dict) and allow_dict:
            ok = False
            for h, patterns in allow_dict.items():
                if patterns and _match_any(patterns, get_decoded_header(msg, h)):
                    ok = True
                    break
            if not ok:
                log("Filter header_allow dict kein Match")
                return True

    body = _extract_body_text(msg)
    if _match_any(cfg.get("body_block", []), body):
        log("Filter body_block match")
        return True

    body_allow = cfg.get("body_allow", [])
    if body_allow and not _match_any(body_allow, body):
        log("Filter body_allow kein Match")
        return True

    return False


def resolve_body_content(recipient_config: dict) -> str:
    body = recipient_config.get('body', '')
    return body if isinstance(body, str) else ''


def is_blacklisted(sender: str, entry_blacklist=None, user_blacklist=None) -> bool:
    s = normalize_email(sender)
    sender_domain = s.split('@', 1)[-1] if '@' in s else s

    for blist in (entry_blacklist, user_blacklist):
        if not blist:
            continue
        for entry in blist:
            e = normalize_email(entry) if entry and '@' in str(entry) else (str(entry or '').lower().strip())
            if '@' in e and s == e:
                return True
            if sender_domain and sender_domain == e:
                return True

    return False


def check_noreply(header: str) -> bool:
    addr = normalize_email(header)
    localpart = addr.split('@', 1)[0] if '@' in addr else addr
    name = (localpart or '').lower().replace('-', '').replace('_', '').replace('.', '')
    return 'noreply' in name or 'donotreply' in name or 'dontreply' in name


def _rotate_stats_monthly(stats_path: str) -> None:
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
        log_error(f"STATS_ROTATE_FAIL err={e}")


def log_stat(event: str, sender: str, recipient: str, subject: str, template: str) -> None:
    try:
        with _stats_flock():
            _ensure_dir_for(STATS_PATH)
            _rotate_stats_monthly(STATS_PATH)

            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Hinweis: subject/template koennen User-Content enthalten (Placeholder aus Original-Mail),
            # csv.writer quotet sauber, trotzdem ist das bewusst so.
            row = [ts, event, sender or "", recipient or "", subject or "", template or ""]
            with open(STATS_PATH, 'a', encoding='utf-8', newline='') as f:
                w = csv.writer(f, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                w.writerow(row)
    except Exception as e:
        print(f"Statistik-Log-Fehler: {e}", file=sys.stderr)


def log_blocked_autoreply(message: Message, reason: str) -> None:
    log_stat(
        'autoreply_blocked',
        get_decoded_header(message, 'From'),
        get_decoded_header(message, 'To'),
        get_decoded_header(message, 'Subject'),
        reason
    )


def is_autoreply_suppressed(message: Message, original_id: Optional[str], server_settings: dict, envelope_from_raw: str) -> bool:
    checks = server_settings.get("autoreply_checks", {}) or {}
    env_norm = normalize_email(envelope_from_raw or "")
    log(f"Pruefe Autoreply Suppress id={original_id} envelope_from_raw='{envelope_from_raw}' envelope_from='{env_norm}'")

    try:
        if checks.get("auto_submitted", True):
            val = (message.get('Auto-Submitted') or '').lower()
            if val and val not in ('no',):
                log_blocked_autoreply(message, 'auto_submitted')
                return True

        if checks.get("x_auto_response_suppress", True):
            xars = (message.get('X-Auto-Response-Suppress') or '')
            xars_list = [v.strip() for v in xars.split(',') if v.strip()]
            if any(v in ('DR', 'AutoReply', 'All', 'OOF') for v in xars_list):
                log_blocked_autoreply(message, 'x_auto_response_suppress')
                return True

        if checks.get("list_headers", True):
            if message.get('List-Id') or message.get('List-Unsubscribe'):
                log_blocked_autoreply(message, 'list_headers')
                return True

        if checks.get("feedback_id", True):
            if message.get('Feedback-ID'):
                log_blocked_autoreply(message, 'feedback_id')
                return True

        if checks.get("precedence", True):
            if str(message.get('Precedence', '')).lower() in ('bulk', 'auto_reply', 'list'):
                log_blocked_autoreply(message, 'precedence')
                return True

        if checks.get("x_autoreply", True):
            if message.get('X-Autoreply') or message.get('X-Autorespond'):
                log_blocked_autoreply(message, 'x_autoreply')
                return True

        if checks.get("empty_envelope_from", True):
            if not (envelope_from_raw or "").strip() or (envelope_from_raw or "").strip() == "<>" or env_norm == "":
                log_blocked_autoreply(message, 'empty_envelope_from')
                return True

        if checks.get("system_from", True):
            if any(x in str(message.get('From', '')).lower() for x in ['mailer-daemon', 'postmaster', 'daemon', 'bounce']):
                log_blocked_autoreply(message, 'system_from')
                return True

        if checks.get("system_replyto", True):
            if any(x in str(message.get('Reply-To', '')).lower() for x in ['mailer-daemon', 'postmaster', 'daemon', 'bounce']):
                log_blocked_autoreply(message, 'system_replyto')
                return True

        if checks.get("noreply", True):
            if check_noreply(message.get('From', '')):
                log_blocked_autoreply(message, 'noreply')
                return True

    except Exception as e:
        log_error(f"CHECK_FAIL id={original_id} err={e}")
        return True

    return False


def _first_email_from_header(raw: str) -> Optional[str]:
    if not raw:
        return None
    addrs = [addr for _, addr in getaddresses([raw]) if addr]
    if not addrs:
        return None
    return normalize_email(addrs[0])


def get_recipient_address(message: Message, recipients: List[str]) -> Optional[str]:
    for header in ('Delivered-To', 'X-Original-To', 'To'):
        val = message.get(header)
        email = _first_email_from_header(val) if val else None
        if email:
            return email
    if recipients:
        return normalize_email(recipients[0])
    return None


def reinject_email(message_bytes: bytes, sender: str, recipients: List[str], original_id: Optional[str]) -> None:
    rcpts = [normalize_email(r) for r in recipients if normalize_email(r)]
    if not rcpts:
        log_error(f"REINJECT_FAIL id={original_id} err=no_recipients")
        return

    sender_n = normalize_email(sender or "")
    if sender_n:
        cmd = ['/usr/sbin/sendmail', '-f', sender_n, '-oi', '--'] + rcpts
        log(f"Re-inject id={original_id} sender='{sender_n}' to={','.join(rcpts)}")
    else:
        cmd = ['/usr/sbin/sendmail', '-oi', '--'] + rcpts
        log(f"Re-inject id={original_id} sender=default to={','.join(rcpts)}")

    try:
        p = Popen(cmd, stdin=PIPE)
        p.communicate(message_bytes)
        if p.returncode != 0:
            log_error(f"REINJECT_FAIL rc={p.returncode} id={original_id} to={','.join(rcpts)}")
    except Exception as e:
        log_error(f"REINJECT_FAIL id={original_id} err={e}")


def _html_to_text(html: str) -> str:
    if not html:
        return ''
    txt = re.sub(r'(?is)<(script|style).*?</\1\s*>', '', html)
    txt = re.sub(r'(?is)<br\s*/?>', '\n', txt)
    txt = re.sub(r'(?is)<p\b[^>]*>', '\n\n', txt)
    txt = re.sub(r'(?is)</p\s*>', '', txt)
    txt = re.sub(r'(?is)<.*?>', '', txt)
    return re.sub(r'\n{3,}', '\n\n', txt).strip()


def _load_attachment_from_cfg(server_settings: dict, recipient_config: dict) -> Optional[Tuple[str, str, str, bytes]]:
    allowed_dir = str(server_settings.get("allowed_attachment_dir", "") or "").strip()
    cfg_att = recipient_config.get("attachment_path")
    if not allowed_dir or not cfg_att:
        return None

    max_att = int(server_settings.get("max_attachment_bytes", 10 * 1024 * 1024))

    try:
        allowed_dir_r = os.path.realpath(allowed_dir)
        p_r = os.path.realpath(str(cfg_att))

        if not p_r.startswith(allowed_dir_r + os.sep):
            log_error(f"ATTACH_BLOCKED path={cfg_att} reason=outside_allowed_dir")
            return None

        try:
            st = os.stat(p_r)
            if st.st_size > max_att:
                log_error(f"ATTACH_BLOCKED path={cfg_att} reason=too_large size={st.st_size} max={max_att}")
                return None
        except Exception as e:
            log_error(f"ATTACH_STAT_FAIL path={cfg_att} err={e}")
            return None

        filename = os.path.basename(p_r)
        mime_type, _ = mimetypes.guess_type(p_r)
        maintype, subtype = (mime_type.split('/', 1) if mime_type else ('application', 'octet-stream'))

        with open(p_r, 'rb') as f:
            data = f.read(max_att + 1)
            if len(data) > max_att:
                log_error(f"ATTACH_BLOCKED path={cfg_att} reason=too_large_read max={max_att}")
                return None

        return (filename, maintype, subtype, data)
    except Exception as e:
        log_error(f"ATTACH_FAIL path={cfg_att} err={e}")
        return None


def generate_email(
    sender: str,
    recipient,
    original_id: Optional[str],
    replyto: str,
    subject: str,
    body: str,
    html: bool,
    attachment: Optional[Tuple[str, str, str, bytes]] = None,
    test: bool = False
) -> EmailMessage:
    message = EmailMessage()

    def _clean(h: str) -> str:
        h = (h or '')
        h = re.sub(r'[\r\n\t]+', ' ', h)
        return h.strip()

    sender_clean = _clean(sender)
    replyto_clean = _clean(replyto)
    subject_clean = _clean(subject)

    message['From'] = encode_address(sender_clean) if sender_clean else ''
    if isinstance(recipient, list):
        message['To'] = ", ".join([encode_address(_clean(r)) for r in recipient if _clean(r)])
    else:
        message['To'] = encode_address(_clean(recipient)) if recipient else ''

    message['Subject'] = str(Header(subject_clean, 'utf-8'))
    message['Message-ID'] = make_msgid()
    if replyto_clean:
        message['Reply-To'] = encode_address(replyto_clean)

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

    if attachment:
        filename, maintype, subtype, data = attachment
        try:
            message.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
        except Exception as e:
            log_error(f"ATTACH_ADD_FAIL file={filename} err={e}")

    return message


# =========================
# SMTP v2.6: MX first (optional), sonst A/AAAA Failover ueber alle IPs
# timeout_sec und mx_first sind optional in config, Default wird genutzt
# =========================

def _resolve_mx_hosts_via_dig(name: str) -> List[str]:
    """
    MX via dig abfragen und nach Preference sortieren (kleinste Zahl zuerst).
    Falls dig fehlt oder keine MX vorhanden sind, kommt [] zurueck.
    """
    try:
        p = run(["dig", "+short", "MX", name], stdout=PIPE, stderr=PIPE, text=True, timeout=3)
        if p.returncode != 0:
            return []
        entries: List[Tuple[int, str]] = []
        for line in (p.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                pref = int(parts[0])
            except Exception:
                continue
            host = parts[1].rstrip(".").strip()
            if host:
                entries.append((pref, host))
        entries.sort(key=lambda x: x[0])
        return [h for _, h in entries]
    except Exception:
        return []


def _resolve_all_ips(host: str, port: int) -> List[str]:
    ips: List[str] = []
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def _is_literal_ip(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except Exception:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except Exception:
        return False


def _smtp_try_host_list(
    message: EmailMessage,
    host_label: str,
    hosts: List[str],
    port: int,
    use_ssl: bool,
    use_tls: bool,
    use_auth: bool,
    username: str,
    password: str,
    timeout: int
) -> bool:
    context = ssl.create_default_context()
    last_err: Optional[Exception] = None

    for host in hosts:
        host = str(host or "").strip()
        if not host:
            continue

        try:
            if _is_literal_ip(host):
                ips = [host]
            else:
                ips = _resolve_all_ips(host, port)

            if not ips:
                log_error(f"SMTP_DNS_NO_IPS label={host_label} host={host}")
                continue

            for ip in ips:
                try:
                    log(f"SMTP_TRY label={host_label} host={host} ip={ip}:{port} ssl={use_ssl} starttls={use_tls} auth={use_auth}")

                    if use_ssl:
                        with smtplib.SMTP_SSL(ip, port, timeout=timeout, context=context) as srv:
                            try:
                                srv.ehlo()
                            except Exception:
                                pass
                            if use_auth:
                                srv.login(username, password)
                            srv.send_message(message)
                            log(f"SMTP_OK label={host_label} ip={ip}:{port}")
                            return True
                    else:
                        with smtplib.SMTP(ip, port, timeout=timeout) as srv:
                            try:
                                srv.ehlo()
                            except Exception:
                                pass
                            if use_tls:
                                srv.starttls(context=context)
                                try:
                                    srv.ehlo()
                                except Exception:
                                    pass
                            if use_auth:
                                srv.login(username, password)
                            srv.send_message(message)
                            log(f"SMTP_OK label={host_label} ip={ip}:{port}")
                            return True

                except Exception as e:
                    last_err = e
                    log_error(f"SMTP_TRY_FAIL label={host_label} host={host} ip={ip}:{port} err={e}")
                    continue

        except Exception as e:
            last_err = e
            log_error(f"SMTP_HOST_FAIL label={host_label} host={host} err={e}")
            continue

    if last_err:
        log_error(f"SMTP_FAIL label={host_label} err={last_err}")
    return False


def send_email(message: EmailMessage, server_settings: dict) -> None:
    """
    v2.6 Verhalten:
    - SMTP ist ein einzelner Haupt-FQDN (wie bisher)
    - optional: mx_first (Default True)
    - optional: timeout_sec (Default 8)
    - Wenn mx_first true: zuerst MX(smtp_host) probieren
    - Danach immer Fallback auf A/AAAA des Haupt-FQDN, mit Failover ueber alle IPs
    """
    try:
        smtp_host = str(server_settings.get('SMTP', 'localhost') or '').strip()
        smtp_port = int(server_settings.get('port', 25))
        use_ssl = bool(server_settings.get('ssl'))
        use_tls = bool(server_settings.get('starttls'))
        use_auth = bool(server_settings.get('smtpauth'))
        username = server_settings.get('username', '')
        password = server_settings.get('password', '')

        timeout = int(server_settings.get('timeout_sec', 8))
        mx_first = bool(server_settings.get('mx_first', True))

        if not smtp_host:
            log_error("SMTP_FAIL reason=empty_smtp_host")
            return

        if use_ssl and use_tls:
            log_error("CONFIG_WARN ssl=true und starttls=true gleichzeitig, nehme SSL")
            use_tls = False

        if mx_first:
            mx_hosts = _resolve_mx_hosts_via_dig(smtp_host)
            if mx_hosts:
                ok = _smtp_try_host_list(
                    message,
                    f"mx_first:{smtp_host}",
                    mx_hosts,
                    smtp_port,
                    use_ssl,
                    use_tls,
                    use_auth,
                    username,
                    password,
                    timeout
                )
                if ok:
                    return
            else:
                log(f"SMTP_MX_NONE host={smtp_host} fallback=A")

        ok = _smtp_try_host_list(
            message,
            f"a_fallback:{smtp_host}",
            [smtp_host],
            smtp_port,
            use_ssl,
            use_tls,
            use_auth,
            username,
            password,
            timeout
        )
        if ok:
            return

        log_error(f"SMTP_FAIL_ALL host={smtp_host} to={message.get('To','')} subj={message.get('Subject','')}")

    except Exception as e:
        log_error(f"SMTP_FAIL to={message.get('To','')} subj={message.get('Subject','')} err={e}")


def _build_rule_index(user_settings: dict) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """
    - First-wins: wenn mehrere Regeln dieselbe email/domain definieren, gewinnt die erste im JSON.
    - Regeln koennen sowohl 'email' als auch 'domain' enthalten, dann werden beide Maps befuellt.
      In autoreply() hat email Vorrang (zuerst email_map, dann domain_map).
    """
    email_map: Dict[str, dict] = {}
    domain_map: Dict[str, dict] = {}

    rules = user_settings.get('autoreply') or []
    for rule in rules:
        if 'email' in rule:
            emails = rule.get('email')
            if not isinstance(emails, list):
                emails = [emails]
            for e in emails or []:
                en = normalize_email(str(e or ""))
                if en and en not in email_map:
                    email_map[en] = rule

        if 'domain' in rule:
            domains = rule.get('domain')
            if not isinstance(domains, list):
                domains = [domains]
            for d in domains or []:
                dn = str(d or "").strip().lower()
                if dn and dn not in domain_map:
                    domain_map[dn] = rule

    return email_map, domain_map


def send_autoreply_email(
    sender: str,
    recipient_email: str,
    recipient_config: dict,
    original_msg: Message,
    original_id: Optional[str],
    server_settings: dict,
    user_settings: dict
) -> None:
    sender = normalize_email(sender)
    recipient_email = normalize_email(recipient_email)

    if recipient_email and sender and recipient_email == sender:
        log("Skip: Sender gleich Empfaenger")
        return

    log(f"Autoreply ausgeloest version={VERSION} sender={sender} rcpt={recipient_email} msgid={original_id}")

    if blocked_by_filters(original_msg, user_settings):
        subject_log = get_decoded_header(original_msg, 'Subject')
        log(f"Header/Body-Filter ausgeloest, keine Autoreply an {sender}")
        log_stat('filter_skip', sender, recipient_email, subject_log, '')
        return

    entry_blacklist = recipient_config.get('blacklist', [])
    user_blacklist = user_settings.get('blacklist', [])
    if is_blacklisted(sender, entry_blacklist, user_blacklist):
        log(f"Sender {sender} ist geblacklistet, keine Autoreply")
        log_stat('blacklist_skip', sender, recipient_email, get_decoded_header(original_msg, 'Subject'), '')
        return

    max_replies = int(recipient_config.get('max_replies_per_sender', 3))
    period_hours = int(recipient_config.get('reply_period_hours', 24))

    if check_and_register_limit(recipient_email, sender, max_replies, period_hours, prune_sec=None):
        subject_log = get_decoded_header(original_msg, 'Subject')
        log(f"Autoreply-Limit erreicht rcpt={recipient_email} sender={sender} max={max_replies} period_h={period_hours}")
        log_stat('autoreply_limit', sender, recipient_email, subject_log, '')
        return

    try:
        html = bool(recipient_config.get('html', False))
        body_raw = resolve_body_content(recipient_config)

        reply_to = recipient_config.get('reply-to', sender)
        from_field = recipient_config.get('from', '')
        subject_template = recipient_config.get('subject', '')

        orig_body_plain = _cleanup_plaintext(_extract_body_text(original_msg))
        if len(orig_body_plain) > 2000:
            orig_body_plain = orig_body_plain[:2000] + "\n\n[... gekuerzt ...]"

        if html:
            placeholders = {
                '{ORIGINAL_DESTINATION}': _html_escape(recipient_email),
                '{ORIGINAL_SUBJECT}': _html_escape(get_decoded_header(original_msg, 'Subject')),
                '{ORIGINAL_SENDER}': _html_escape(get_decoded_header(original_msg, 'From', sender)),
                '{ORIGINAL_DATE}': _html_escape(get_decoded_header(original_msg, 'Date', '')),
                '{ORIGINAL_BODY}': _html_escape(orig_body_plain),
            }
        else:
            placeholders = {
                '{ORIGINAL_DESTINATION}': recipient_email,
                '{ORIGINAL_SUBJECT}': get_decoded_header(original_msg, 'Subject'),
                '{ORIGINAL_SENDER}': get_decoded_header(original_msg, 'From', sender),
                '{ORIGINAL_DATE}': get_decoded_header(original_msg, 'Date', ''),
                '{ORIGINAL_BODY}': orig_body_plain,
            }

        subject = replace_placeholders(subject_template, placeholders)
        body = replace_placeholders(body_raw, placeholders)

        attachment = _load_attachment_from_cfg(server_settings, recipient_config)

        message = generate_email(
            from_field,
            sender,
            original_id,
            reply_to,
            subject,
            body,
            html,
            attachment=attachment
        )
        send_email(message, server_settings)

        log_stat(
            'sent_autoreply',
            sender,
            recipient_email,
            subject,
            str(recipient_config.get('email', recipient_config.get('domain', '')))
        )

    except Exception as e:
        log_error(f"AUTOREPLY_SEND_FAIL id={original_id} rcpt={recipient_email} sender={sender} err={e}")


def autoreply(
    sender: str,
    recipients: List[str],
    original_msg: Message,
    original_id: Optional[str],
    server_settings: dict,
    user_settings: dict
) -> None:
    sender_n = normalize_email(sender)
    rcpts_n = normalize_email_list(recipients)

    email_map, domain_map = _build_rule_index(user_settings)

    for rcpt in rcpts_n:
        rule = email_map.get(rcpt)
        if rule:
            send_autoreply_email(sender_n, rcpt, rule, original_msg, original_id, server_settings, user_settings)
            continue

        if '@' in rcpt:
            dom = rcpt.split('@', 1)[1].lower()
            rule = domain_map.get(dom)
            if rule:
                send_autoreply_email(sender_n, rcpt, rule, original_msg, original_id, server_settings, user_settings)


def _safe_message_id(msg: Message) -> Optional[str]:
    try:
        v = msg.get('Message-ID')
        if not v:
            return None
        v = str(v).replace('\r', '').replace('\n', '').replace(' ', '')
        return v or None
    except Exception:
        return None


def _close_stdin_safely() -> None:
    try:
        sys.stdin.buffer.close()
    except Exception:
        try:
            sys.stdin.close()
        except Exception:
            pass


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ('help', '--help', '-h'):
        print(
            "Verwendung:\n"
            "  python3 autoreply.py <envelope-sender> <rcpt1> [rcpt2 ...]\n\n"
            "Konfiguration:\n"
            f"  Server: {SERVER_CONFIG_PATH}\n"
            f"  User  : {USER_CONFIG_PATH}\n"
            f"  Version: {VERSION}\n"
        )
        sys.exit(0)

    server_settings = load_json(
        SERVER_CONFIG_PATH,
        "Fehler: autoreply_server.json fehlt, bitte anlegen."
    )
    user_settings = load_json(
        USER_CONFIG_PATH,
        "Fehler: autoreply_user.json fehlt, bitte anlegen."
    )

    global logging_enabled
    logging_enabled = bool(server_settings.get('logging', False))

    global REGEX_DEFAULT_IGNORECASE
    REGEX_DEFAULT_IGNORECASE = bool(server_settings.get('regex_default_ignorecase', False))

    global LIMIT_PRUNE_SEC
    LIMIT_PRUNE_SEC = _compute_limit_prune_sec(user_settings)

    integration_mode = server_settings.get("integration_mode", "bcc")

    sender_raw = sys.argv[1]
    sender = normalize_email(sender_raw)

    recipient_list_raw: List[str] = sys.argv[2:]
    recipient_list = normalize_email_list(recipient_list_raw)

    max_bytes = int(server_settings.get("max_message_bytes", 25 * 1024 * 1024))
    data = sys.stdin.buffer.read(max_bytes + 1)

    if len(data) > max_bytes:
        log_error(f"MSG_TOO_LARGE bytes>{max_bytes} mode={integration_mode} action=discard_no_reinject")
        _close_stdin_safely()

        action = str(server_settings.get("too_large_action", "discard") or "").strip().lower()
        if action == "tempfail":
            sys.exit(75)
        sys.exit(0)

    original_msg = message_from_bytes(data)
    original_id = _safe_message_id(original_msg)

    if integration_mode != "bcc":
        reinject_email(data, sender_raw, recipient_list_raw, original_id or 'ohne-Message-ID')
        log("Integration Mode klassisch, Mail wurde reinjected")
        return

    actual_recipient = get_recipient_address(original_msg, recipient_list_raw)
    actual_recipient = normalize_email(actual_recipient or "")
    if actual_recipient:
        recipients = [actual_recipient]
        log(f"Integration Mode BCC, Empfaenger aus Header: {actual_recipient}")
    else:
        recipients = recipient_list
        log(f"Integration Mode BCC, kein Empfaenger im Header, nutze argv: {recipient_list_raw}")

    if not is_autoreply_suppressed(original_msg, original_id or 'ohne-Message-ID', server_settings, sender_raw):
        autoreply(sender, recipients, original_msg, original_id, server_settings, user_settings)


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:
        log_error(f"UNCAUGHT {exc.__class__.__name__} {traceback.format_exc()}")
        raise
