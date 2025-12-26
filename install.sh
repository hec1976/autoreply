#!/usr/bin/env bash
# install_all.sh
# One-Stop Installer fuer autoreply

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install_all.sh [OPTIONS]

Options:
  --user USER                 Default: autoreply
  --group GROUP               Default: autoreply
  --base-prefix PATH          Default: /opt/autoreply
  --service-name NAME         Default: autoreply-agent
  --enable-service            systemctl enable --now <service-name>
  --no-create-user            User/Group nicht anlegen, nur pruefen
  --no-sync                   Kein rsync vom Repo nach /opt (nur Rechte setzen)
  --dry-run                   Nur anzeigen, nichts ausfuehren
  -h, --help                  Hilfe
USAGE
}

die(){ echo "ERROR: $*" >&2; exit 1; }
info(){ echo "[i] $*"; }
ok(){ echo "[OK] $*"; }
warn(){ echo "[!] $*" >&2; }

DRY_RUN=0
NO_SYNC=0
ENABLE_SERVICE=0
NO_CREATE_USER=0

USER_="autoreply"
GROUP_="autoreply"
BASE_PREFIX="/opt/autoreply"
SERVICE_NAME="autoreply-agent"

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
  else
    eval "$@"
  fi
}

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Bitte als root ausfuehren."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_="${2-}"; shift 2 ;;
    --group) GROUP_="${2-}"; shift 2 ;;
    --base-prefix) BASE_PREFIX="${2-}"; shift 2 ;;
    --service-name) SERVICE_NAME="${2-}"; shift 2 ;;
    --enable-service) ENABLE_SERVICE=1; shift ;;
    --no-create-user) NO_CREATE_USER=1; shift ;;
    --no-sync) NO_SYNC=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unbekanntes Argument: $1" ;;
  esac
done

need_root

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SERVICES_AGENT_REPO="${REPO_DIR}/services-agent"
SCRIPT_REPO="${REPO_DIR}/script"
SSL_REPO="${REPO_DIR}/ssl"
ENV_REPO="${REPO_DIR}/env"

SERVICES_AGENT_DST="${BASE_PREFIX}/services-agent"
SCRIPT_DST="${BASE_PREFIX}/script"
SSL_DST="${BASE_PREFIX}/ssl"
ENV_DST="${BASE_PREFIX}/env"

AGENT_PL="${SERVICES_AGENT_DST}/autoreply-agent.pl"
CONFIG_JSON="${SERVICES_AGENT_DST}/config.json"

# Unit: Quelle bevorzugt aus DEST (weil symlink), fallback auf REPO
UNIT_SRC_DST="${SERVICES_AGENT_DST}/service/${SERVICE_NAME}.service"
UNIT_SRC_REPO="${SERVICES_AGENT_REPO}/service/${SERVICE_NAME}.service"
UNIT_DST="/etc/systemd/system/${SERVICE_NAME}.service"

ENV_EXAMPLE_DST="${SERVICES_AGENT_DST}/example/${SERVICE_NAME}.env.example"
ENV_EXAMPLE_REPO="${SERVICES_AGENT_REPO}/example/${SERVICE_NAME}.env.example"
ENV_DST_FILE="${ENV_DST}/${SERVICE_NAME}.env"

PY_SCRIPT_DST=""
PY1="${SCRIPT_DST}/autoreply,py"
PY2="${SCRIPT_DST}/autoreply.py"

info "Repo:            $REPO_DIR"
info "User:Group:      ${USER_}:${GROUP_}"
info "Base Prefix:     $BASE_PREFIX"
info "Service Name:    $SERVICE_NAME"

# 1) User/Group zuerst
if [[ "$NO_CREATE_USER" -eq 0 ]]; then
  getent group "$GROUP_" >/dev/null 2>&1 || run "groupadd -r '$GROUP_'"
  if ! getent passwd "$USER_" >/dev/null 2>&1; then
    run "useradd -r -g '$GROUP_' -d '$BASE_PREFIX' -s /bin/false '$USER_'"
  fi
else
  getent group "$GROUP_" >/dev/null 2>&1 || die "Gruppe fehlt: $GROUP_"
  getent passwd "$USER_" >/dev/null 2>&1 || die "User fehlt: $USER_"
fi
ok "User/Group ok: ${USER_}:${GROUP_}"

OWNER_APP="${USER_}:${GROUP_}"
OWNER_CODE="root:${GROUP_}"

# 2) Pflichtverzeichnisse sicherstellen (Basis)
run "install -d -m 0755 '$BASE_PREFIX'"
run "install -d -m 0755 '$SERVICES_AGENT_DST'"
run "install -d -m 0755 '$SCRIPT_DST'"
run "install -d -m 0750 '$SSL_DST'"
run "install -d -m 0750 '$ENV_DST'"

# Script-Subdirs immer erstellen damit Rechte sicher greifen
run "install -d -m 0770 -o '$USER_' -g '$GROUP_' '$SCRIPT_DST/conf'"
run "install -d -m 0770 -o '$USER_' -g '$GROUP_' '$SCRIPT_DST/json'"

# 0) Optional sync (jetzt nach User/Group)
if [[ "$NO_SYNC" -eq 0 ]]; then
  info "Synchronisiere Repo nach $BASE_PREFIX (private.key wird nicht ueberschrieben)"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] rsync -a --delete --exclude '.git' --exclude 'ssl/private.key' '$REPO_DIR/' '$BASE_PREFIX/'"
  else
    command -v rsync >/dev/null 2>&1 || die "rsync fehlt. Installiere rsync oder nutze --no-sync."
    rsync -a --delete --exclude '.git' --exclude 'ssl/private.key' "$REPO_DIR/" "$BASE_PREFIX/"
  fi
else
  info "Sync uebersprungen (--no-sync)."
fi

# 3) Runtime dirs fuer service-agent
for d in "$SERVICES_AGENT_DST/backups" "$SERVICES_AGENT_DST/tmp"; do
  run "install -d -m 0770 '$d'"
  run "chown '$OWNER_APP' '$d'"
done
ok "Runtime dirs gesetzt (backups/tmp)"


# 3b) Log dir sicherstellen (Agent log/stats)
LOG_DST="${BASE_PREFIX}/log"
run "install -d -m 0770 -o '$USER_' -g '$GROUP_' '$LOG_DST'"
ok "Log dir gesetzt: $LOG_DST"


# 3c) Standard Logfiles / Limit-File anlegen (optional, aber praktisch)
for lf in \
  "$LOG_DST/autoreply_agent.log" \
  "$LOG_DST/autoreply_stats.log" \
  "$LOG_DST/autoreply_script.log" \
  "$LOG_DST/autoreply_limit.json"
do
  run "touch '$lf'"
  run "chown '$OWNER_APP' '$lf'"
  run "chmod 0660 '$lf'"
done
ok "Logfiles/Limit-File gesetzt"


# 4) Code haerten (perl)
[[ -f "$AGENT_PL" ]] || die "Fehlt: $AGENT_PL"
run "chown '$OWNER_CODE' '$AGENT_PL'"
run "chmod 0750 '$AGENT_PL'"
ok "Code gehaertet: $AGENT_PL"

# 5) Configs haerten (services-agent)
if [[ -f "$CONFIG_JSON" ]]; then
  run "chown '$OWNER_APP' '$CONFIG_JSON'"
  run "chmod 0640 '$CONFIG_JSON'"
else
  warn "Fehlt: $CONFIG_JSON"
fi

for f in "$SERVICES_AGENT_DST"/*.json "$SERVICES_AGENT_DST"/*.ini "$SERVICES_AGENT_DST"/*.conf; do
  [[ -f "$f" ]] || continue
  run "chown '$OWNER_APP' '$f'"
  run "chmod 0640 '$f'"
done

# 6) Script-Teil perms (files)
for f in "$SCRIPT_DST/config.conf" "$SCRIPT_DST/json/autoreply_server.json" "$SCRIPT_DST/conf/autoreply_user.json"; do
  if [[ -f "$f" ]]; then
    run "chown '$OWNER_APP' '$f'"
    run "chmod 0660 '$f'"
  else
    warn "Fehlt: $f"
  fi
done

# python file (komma oder normal)
if [[ -f "$PY1" ]]; then
  PY_SCRIPT_DST="$PY1"
elif [[ -f "$PY2" ]]; then
  PY_SCRIPT_DST="$PY2"
fi

if [[ -n "$PY_SCRIPT_DST" ]]; then
  run "chown '$OWNER_APP' '$PY_SCRIPT_DST'"
  run "chmod 0660 '$PY_SCRIPT_DST'"
  run "chmod u+x '$PY_SCRIPT_DST'"   # => 0760
  ok "Python script perms: $PY_SCRIPT_DST"
else
  warn "Kein Python Script gefunden (autoreply,py oder autoreply.py)"
fi

# 7) SSL haerten (root:<group>, 0640)
for f in "$SSL_DST/certifikate.cert" "$SSL_DST/private.key"; do
  if [[ -f "$f" ]]; then
    run "chown '$OWNER_CODE' '$f'"
    run "chmod 0640 '$f'"
    ok "SSL File perms: $f"
  else
    warn "Fehlt: $f"
  fi
done
run "chmod 0750 '$SSL_DST'"
run "chown '$OWNER_CODE' '$SSL_DST'"

# 8) ENV Datei (nur Vorlage kopieren wenn fehlt)
run "install -d -m 0750 '$ENV_DST'"
run "chown root:root '$ENV_DST'"

if [[ -f "$ENV_DST_FILE" ]]; then
  run "chown root:root '$ENV_DST_FILE'"
  run "chmod 0600 '$ENV_DST_FILE'"
  ok "ENV vorhanden gehaertet: $ENV_DST_FILE"
else
  # Vorlage bevorzugt aus DEST, fallback Repo
  if [[ -f "$ENV_EXAMPLE_DST" ]]; then
    run "cp '$ENV_EXAMPLE_DST' '$ENV_DST_FILE'"
  elif [[ -f "$ENV_EXAMPLE_REPO" ]]; then
    run "cp '$ENV_EXAMPLE_REPO' '$ENV_DST_FILE'"
  else
    warn "Keine ENV Vorlage gefunden: $ENV_EXAMPLE_DST / $ENV_EXAMPLE_REPO"
  fi

  if [[ -f "$ENV_DST_FILE" ]]; then
    run "chown root:root '$ENV_DST_FILE'"
    run "chmod 0600 '$ENV_DST_FILE'"
    ok "ENV erstellt aus Vorlage: $ENV_DST_FILE"
  fi
fi

# 9) systemd unit link
UNIT_SRC=""
if [[ -f "$UNIT_SRC_DST" ]]; then
  UNIT_SRC="$UNIT_SRC_DST"
elif [[ -f "$UNIT_SRC_REPO" ]]; then
  UNIT_SRC="$UNIT_SRC_REPO"
fi
[[ -n "$UNIT_SRC" ]] || die "Fehlt systemd unit: $UNIT_SRC_DST (fallback $UNIT_SRC_REPO)"

run "ln -sfn '$UNIT_SRC' '$UNIT_DST'"
ok "Systemd symlink: $UNIT_DST"

run "systemctl daemon-reload"

# optional unit verify
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$UNIT_DST" || warn "systemd-analyze verify meldet Probleme fuer $UNIT_DST"
fi

# 10) optional enable
if [[ "$ENABLE_SERVICE" -eq 1 ]]; then
  run "systemctl enable --now '$SERVICE_NAME'"
  ok "Service enabled: $SERVICE_NAME"
else
  info "Service nicht aktiviert. Manuell:"
  echo "  systemctl enable --now $SERVICE_NAME"
fi

info "Fertig."
