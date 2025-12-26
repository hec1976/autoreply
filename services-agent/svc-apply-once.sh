#!/usr/bin/env bash
# svc-apply-once.sh — Units aus ./service (und ./timer) linken, reload, starten/restarten, Status ausgeben
set -Eeuo pipefail

# --- Defaults / Optionen ---
SCOPE="system"          # "system" oder "user"
DO_ENABLE=0
ACTION="restart"        # "restart" | "start" | "none"
DRYRUN=0

usage() {
  cat <<'USG'
Usage: svc-apply-once.sh [--enable] [--start|--restart|--no-apply] [--user|--system] [--dry-run]

  --enable       : Units nach dem Linken mit systemctl enable aktivieren (falls [Install] vorhanden)
  --start        : Units starten (ohne Restart)
  --restart      : Units neu starten (Default)
  --no-apply     : Weder starten noch neustarten (nur Link + reload)
  --user         : Im Benutzer-Scope installieren (systemd --user)
  --system       : Systemweit (Default)
  --dry-run      : Nur anzeigen, was passieren würde

Beachtet *.service in ./service und *.timer in ./timer (wenn vorhanden).
USG
}

log()  { printf "%s %s\n" "$1" "$2"; }
ok()   { log "[OK]" "$*"; }
info() { log "[ i]" "$*"; }
warn() { log "[! ]" "$*"; }
err()  { log "[ x]" "$*" >&2; exit 1; }

# --- Argumente ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enable) DO_ENABLE=1 ;;
    --start) ACTION="start" ;;
    --restart) ACTION="restart" ;;
    --no-apply) ACTION="none" ;;
    --user) SCOPE="user" ;;
    --system) SCOPE="system" ;;
    --dry-run) DRYRUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unbekannte Option: $1";;
  esac
  shift
done

# --- Umgebung / Pfade ---
APP_DIR="$(pwd -P)"
DIR_SVC="${APP_DIR}/service"
DIR_TMR="${APP_DIR}/timer"

[[ "$SCOPE" == "system" ]] && [[ $EUID -eq 0 ]] || { [[ "$SCOPE" == "user" ]] || err "Root nötig (oder --user wählen)"; }
command -v systemctl >/dev/null || err "systemctl fehlt"
command -v systemd-analyze >/dev/null || warn "systemd-analyze fehlt (Skip Verify)"

# --- Units einsammeln ---
mapfile -t UNITS < <(
  shopt -s nullglob
  for f in "$DIR_SVC"/*.service "$DIR_TMR"/*.timer; do
    [[ -e "$f" ]] && printf "%s\n" "$f"
  done
)

[[ ${#UNITS[@]} -gt 0 ]] || err "Keine Units gefunden (erwarte $DIR_SVC/*.service und/oder $DIR_TMR/*.timer)"

# --- Hilfsfunktionen ---
sc() {
  # systemctl Wrapper je nach Scope
  if [[ "$SCOPE" == "user" ]]; then
    systemctl --user "$@"
  else
    systemctl "$@"
  fi
}

verify_unit() {
  local path="$1"
  if command -v systemd-analyze >/dev/null; then
    if ! systemd-analyze verify "$path" 2>&1 | sed '/^/ s//    /'; then
      warn "Verify meldet Probleme für: $path"
    fi
  fi
}

link_unit() {
  local path="$1"
  if (( DRYRUN )); then
    info "(dry-run) link $path"
  else
    sc link "$path" >/dev/null && ok "gelinkt: $(basename "$path")"
  fi
}

enable_if_possible() {
  local unit="$1"
  (( DO_ENABLE )) || return 0
  if (( DRYRUN )); then
    info "(dry-run) enable $unit"
    return 0
  fi
  if sc show -p InstallWantedBy "$unit" | grep -q '='; then
    sc enable "$unit" >/dev/null && ok "enabled: $unit" || warn "enable fehlgeschlagen: $unit"
  else
    info "kein [Install] in $unit (enable übersprungen)"
  fi
}

apply_action() {
  local unit="$1"
  case "$ACTION" in
    none) return 0 ;;
    start)
      (( DRYRUN )) && { info "(dry-run) start $unit"; return 0; }
      sc start "$unit" && ok "gestartet: $unit" || warn "start fehlgeschlagen: $unit"
      ;;
    restart)
      (( DRYRUN )) && { info "(dry-run) restart $unit"; return 0; }
      sc restart "$unit" && ok "restart: $unit" || warn "restart fehlgeschlagen: $unit"
      ;;
  esac
}

show_status() {
  local unit="$1"
  sc show -p FragmentPath,LoadState,ActiveState,SubState "$unit" 2>/dev/null | sed 's/^/  /'
}

# --- Plan ---
echo "----- PLAN -----"
echo "Scope   : $SCOPE"
echo "AppDir  : $APP_DIR"
echo "Service : $DIR_SVC (*.service)"
echo "Timer   : $DIR_TMR (*.timer)"
echo "Units   : ${#UNITS[@]}"
echo "Enable  : $DO_ENABLE"
echo "Action  : $ACTION"
echo "DryRun  : $DRYRUN"
echo "--------------"

# --- Verify ---
echo "----- VERIFY -----"
for p in "${UNITS[@]}"; do verify_unit "$p"; done

# --- Link ---
echo "----- LINK -----"
for p in "${UNITS[@]}"; do link_unit "$p"; done

# --- Reload ---
echo "----- RELOAD -----"
if (( DRYRUN )); then
  info "(dry-run) daemon-reload"
else
  sc daemon-reload && ok "daemon-reload" || warn "daemon-reload meldete Fehler"
fi

# --- Enable / Apply ---
echo "----- APPLY -----"
for p in "${UNITS[@]}"; do
  u="$(basename "$p")"
  enable_if_possible "$u"
  apply_action "$u"
done

# --- Summary ---
echo "----- SUMMARY -----"
for p in "${UNITS[@]}"; do
  u="$(basename "$p")"
  en="$(sc is-enabled "$u" 2>/dev/null || echo unknown)"
  ac="$(sc is-active  "$u" 2>/dev/null || echo unknown)"
  printf "%-40s enabled=%-10s active=%s\n" "$u" "$en" "$ac"
done
echo "------------------"

ok "done"
