#!/usr/bin/env bash
# scipt.sh
# Setzt Owner/Mode fuer Script-Teil (config/json/conf + autoreply python script)
# Default: autoreply:autoreply

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scipt.sh [OPTIONS]

Options:
  --user USER        Owner User (Default: autoreply)
  --group GROUP      Owner Group (Default: autoreply)
  --base-dir PATH    Basisordner (Default: Ordner von scipt.sh)
  -h, --help         Hilfe
USAGE
}

die(){ echo "ERROR: $*" >&2; exit 1; }
warn(){ echo "WARN: $*" >&2; }
ok(){ echo "OK: $*"; }

USER_="autoreply"
GROUP_="autoreply"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) USER_="${2-}"; shift 2 ;;
    --group) GROUP_="${2-}"; shift 2 ;;
    --base-dir) BASE_DIR="${2-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unbekanntes Argument: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "Bitte als root ausfuehren (wegen chown)."

OWNER="${USER_}:${GROUP_}"

# python script: 
PY_SCRIPT=""
if [[ -f "$BASE_DIR/autoreply.py" ]]; then
  PY_SCRIPT="$BASE_DIR/autoreply.py"
else
  warn " autoreply.py nicht gefunden unter: $BASE_DIR"
fi

# Verzeichnisse
for d in "$BASE_DIR/json" "$BASE_DIR/conf"; do
  if [[ -d "$d" ]]; then
    chown "$OWNER" "$d"
    chmod 0770 "$d"
    ok "DIR: $d owner=$OWNER mode=0770"
  fi
done

# python script: 0660 + u+x => 0760 (wie gewuenscht: +x und sonst restriktiv)
if [[ -n "$PY_SCRIPT" && -f "$PY_SCRIPT" ]]; then
  chown "$OWNER" "$PY_SCRIPT"
  chmod 0660 "$PY_SCRIPT"
  chmod u+x "$PY_SCRIPT"
  ok "FILE: $PY_SCRIPT owner=$OWNER mode=$(stat -c '%a' "$PY_SCRIPT")"
fi

FILES=(
  "$BASE_DIR/config.conf"
  "$BASE_DIR/json/autoreply_server.json"
  "$BASE_DIR/conf/autoreply_user.json"
)

for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    warn "fehlt: $f"
    continue
  fi
  chown "$OWNER" "$f"
  chmod 0660 "$f"
  ok "FILE: $f owner=$OWNER mode=$(stat -c '%a' "$f")"
done
