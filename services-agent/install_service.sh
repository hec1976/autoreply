#!/usr/bin/env bash
#
# install_service.sh
# Universal-Installer fuer gehärtete Dienste (systemd)
# Default: autoreply:autoreply
#
# Funktionen:
# - optional User/Group anlegen oder nur pruefen
# - Code (pl) haerten: root:<group>, 0750
# - Configs (json/ini/conf) haerten: <user>:<group>, 0640
# - Verzeichnisse aus config.json anlegen (tmp/backup/config/json + logdir)
# - SSL Files aus config.json haerten: root:<group>, 0640
# - ENV Datei aus example erstellen, 0600
# - systemd Unit symlinken und daemon-reload

set -Eeuo pipefail

usage() {
  cat <<USAGE
Usage: $(basename "$0") [OPTIONS]

Options:
  --name NAME              Basisname des Services (z.B. autoreply-agent)

  --user USER              Service-User (Default: autoreply)
  --group GROUP            Service-Group (Default: autoreply)
  --no-create-user         User/Group nicht anlegen, nur pruefen

  --owner-code USER:GRP    Besitzer fuer Programmcode (Default: root:<group>)
  --owner-app  USER:GRP    Besitzer fuer App-Daten/Configs (Default: <user>:<group>)

  --app-dir PATH           Pfad zum App-Verzeichnis (Default: aktuelles Verzeichnis)
  --env-dir PATH           Pfad fuer .env Dateien (Default: ../env)
  --etc-dir PATH           Systemd Verzeichnis (Default: /etc/systemd/system)

  -h, --help               Hilfe
USAGE
}

ok()   { printf "  [OK] %s\n" "$*"; }
info() { printf "  [i ] %s\n" "$*"; }
warn() { printf "  [!] %s\n" "$*"; }
die()  { printf "  [x ] %s\n" "$*" >&2; exit 1; }

need_root() { [[ ${EUID:-0} -eq 0 ]] || die "Dieses Skript muss als root ausgefuehrt werden."; }

NAME=""
APP_DIR="$(pwd -P)"
ETC_DIR="/etc/systemd/system"
ENV_DIR=""

USER_="autoreply"
GROUP_="autoreply"
CREATE_USER=1

OWNER_CODE=""
OWNER_APP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)       NAME="${2-}"; shift 2 ;;
    --user)       USER_="${2-}"; shift 2 ;;
    --group)      GROUP_="${2-}"; shift 2 ;;
    --no-create-user) CREATE_USER=0; shift ;;
    --owner-code) OWNER_CODE="${2-}"; shift 2 ;;
    --owner-app)  OWNER_APP="${2-}"; shift 2 ;;
    --app-dir)    APP_DIR="${2-}"; shift 2 ;;
    --env-dir)    ENV_DIR="${2-}"; shift 2 ;;
    --etc-dir)    ETC_DIR="${2-}"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) die "Unbekanntes Argument: $1" ;;
  esac
done

need_root

# Defaults aus user/group ableiten, wenn owner nicht explizit gesetzt
[[ -n "$OWNER_CODE" ]] || OWNER_CODE="root:${GROUP_}"
[[ -n "$OWNER_APP"  ]] || OWNER_APP="${USER_}:${GROUP_}"

# User/Group sicherstellen oder pruefen
if [[ $CREATE_USER -eq 1 ]]; then
  getent group "$GROUP_" >/dev/null 2>&1 || groupadd -r "$GROUP_"
  if ! getent passwd "$USER_" >/dev/null 2>&1; then
    useradd -r -g "$GROUP_" -d /opt/autoreply -s /bin/false "$USER_"
  fi
else
  getent group "$GROUP_" >/dev/null 2>&1 || die "Gruppe fehlt: $GROUP_"
  getent passwd "$USER_" >/dev/null 2>&1 || die "User fehlt: $USER_"
fi

check_owner() {
  local u="${1%%:*}"
  local g="${1#*:}"
  getent passwd "$u" >/dev/null || die "User $u existiert nicht."
  getent group  "$g" >/dev/null || die "Gruppe $g existiert nicht."
}
check_owner "$OWNER_CODE"
check_owner "$OWNER_APP"

SRC_DIR="${APP_DIR}/service"
[[ -d "$SRC_DIR" ]] || die "Verzeichnis ${SRC_DIR} nicht gefunden (erwarte ./service unter APP_DIR)"

# Name ableiten, wenn nicht gesetzt
if [[ -z "$NAME" ]]; then
  shopt -s nullglob
  services=("$SRC_DIR"/*.service)
  if (( ${#services[@]} == 1 )); then
    NAME="$(basename "${services[0]}" .service)"
  else
    die "Mehrere oder keine .service Dateien gefunden. Bitte --name angeben."
  fi
fi

info "Starte Installation fuer: $NAME"
info "APP_DIR: $APP_DIR"
info "OWNER_CODE: $OWNER_CODE"
info "OWNER_APP:  $OWNER_APP"

# 1) Programmcode haerten
info "Haerte Programmcode ..."
shopt -s nullglob
for f in "$APP_DIR"/*.pl; do
  [[ -f "$f" ]] || continue
  chown "$OWNER_CODE" "$f"
  chmod 0750 "$f"
  ok "Code: $(basename "$f") (0750, $OWNER_CODE)"
done

# 2) Konfiguration haerten
info "Haerte Konfigurationen ..."
for f in "$APP_DIR"/*.json "$APP_DIR"/*.ini "$APP_DIR"/*.conf; do
  [[ -f "$f" ]] || continue
  chown "$OWNER_APP" "$f"
  chmod 0640 "$f"
  ok "Config: $(basename "$f") (0640, $OWNER_APP)"
done

# 3) App Infrastruktur aus config.json
CONFIG_FILE="${APP_DIR}/config.json"
if [[ -f "$CONFIG_FILE" ]]; then
  info "Lese Verzeichnisse/Files aus config.json ..."

  # simple JSON string extractor (funktioniert fuer flache "key":"value" Eintraege)
  json_get() {
    local key="$1"
    sed -n -E "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*/\1/p" "$CONFIG_FILE" | head -n1
  }

  KEYS=("configDir" "jsonDir" "backupDir" "tmpDir")
  for key in "${KEYS[@]}"; do
    path="$(json_get "$key")"
    [[ -n "$path" ]] || continue
    [[ "$path" == /* ]] || path="${APP_DIR}/$path"

    install -d -m 0770 "$path"
    chown "$OWNER_APP" "$path"
    ok "Verzeichnis: $key -> $path (0770, $OWNER_APP)"
  done

  # log dir aus logfile/statslog
  for key in "logfile" "statslog"; do
    path="$(json_get "$key")"
    [[ -n "$path" ]] || continue
    logdir="$(dirname "$path")"
    [[ "$logdir" == /* ]] || logdir="${APP_DIR}/$logdir"

    install -d -m 0775 "$logdir"
    chown "$OWNER_APP" "$logdir"
    ok "Log-Dir: $key -> $logdir (0775, $OWNER_APP)"
  done

  # SSL (root:<group>, 0640)
  for key in "ssl_cert_file" "ssl_key_file"; do
    path="$(json_get "$key")"
    [[ -n "$path" ]] || continue
    [[ "$path" == /* ]] || path="${APP_DIR}/$path"

    ssldir="$(dirname "$path")"
    install -d -m 0750 "$ssldir"
    chown "root:${GROUP_}" "$ssldir"
    ok "SSL-Dir: $key -> $ssldir (0750, root:${GROUP_})"

    if [[ -f "$path" ]]; then
      chown "root:${GROUP_}" "$path"
      chmod 0640 "$path"
      ok "SSL-File: $key -> $path (0640, root:${GROUP_})"
    else
      warn "SSL-File fehlt: $key -> $path"
    fi
  done
else
  warn "Keine config.json gefunden, ueberspringe config-basierte Verzeichnisse."
fi

# 4) ENV
[[ -n "$ENV_DIR" ]] || ENV_DIR="${APP_DIR}/../env"
install -d -m 0750 "$ENV_DIR"
chown root:root "$ENV_DIR"

ENV_SRC="${APP_DIR}/example/${NAME}.env.example"
ENV_DEST="${ENV_DIR}/${NAME}.env"

if [[ -f "$ENV_SRC" && ! -f "$ENV_DEST" ]]; then
  cp "$ENV_SRC" "$ENV_DEST"
  chown root:root "$ENV_DEST"
  chmod 0600 "$ENV_DEST"
  ok "ENV: Vorlage erstellt -> $ENV_DEST (0600)"
elif [[ -f "$ENV_DEST" ]]; then
  chown root:root "$ENV_DEST"
  chmod 0600 "$ENV_DEST"
  ok "ENV: Bestehende Datei gehaertet -> $ENV_DEST (0600)"
else
  warn "ENV Vorlage nicht gefunden: $ENV_SRC"
fi

# 5) systemd Link setzen
SERVICE_PATH="${ETC_DIR}/${NAME}.service"
ln -sfn "${SRC_DIR}/${NAME}.service" "$SERVICE_PATH"
ok "Systemd: Symlink erstellt -> $SERVICE_PATH"

systemctl daemon-reload
info "Installation abgeschlossen."
echo "Status: systemctl status $NAME"
echo "Start:  systemctl enable --now $NAME"
