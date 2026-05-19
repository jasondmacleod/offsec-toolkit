#!/usr/bin/env bash
# ==============================================================================
# vquery — Vault Query Engine launcher
# ==============================================================================
# PURPOSE   Local, read-only, OffSec-rules-compliant retrieval over the Obsidian
#           vault. No AI at runtime — pure FTS5 + pre-authored shortcuts.
#
# USAGE     ./run.sh start             launch on http://127.0.0.1:5051
#           ./run.sh stop              stop a running instance
#           ./run.sh status            show pid + index stats
#           ./run.sh rebuild           re-index the vault, reload shortcuts
#           ./run.sh import-shortcuts  reload data/shortcuts/*.json only
#
# OUTPUT    data/vquery.sqlite (derived index, gitignored), .run/ (pid+log)
#
# DESIGN    Drop-and-rebuild like exploitdb; vault markdown + shortcut JSON are
#           the source of truth. The live server opens the DB per request, so a
#           rebuild is picked up on the next query — no restart needed.
# ==============================================================================
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || exit 1

PORT="${VQUERY_PORT:-5051}"
HOST="${VQUERY_HOST:-127.0.0.1}"
DB="data/vquery.sqlite"
RUNDIR=".run"
PIDFILE="$RUNDIR/vquery.pid"
LOGFILE="$RUNDIR/vquery.log"

if [ -n "$NO_COLOR" ] || [ ! -t 1 ]; then C_G=""; C_R=""; C_Y=""; C_0=""
else C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_0=$'\033[0m'; fi
info()  { printf '%s%s%s %s\n' "$C_G" "[vquery]" "$C_0" "$*"; }
warn()  { printf '%s%s%s %s\n' "$C_Y" "[vquery]" "$C_0" "$*" >&2; }
error() { printf '%s%s%s %s\n' "$C_R" "[vquery]" "$C_0" "$*" >&2; }

is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; }

ensure_db() {
  if [ ! -f "$DB" ]; then
    info "no index — building"
    python3 build.py || { error "build failed"; exit 1; }
  fi
}

cmd="${1:-start}"

case "$cmd" in
  start)
    if is_running; then info "already running (pid $(cat "$PIDFILE")) on http://${HOST}:${PORT}/"; exit 0; fi
    ensure_db
    mkdir -p "$RUNDIR"
    info "starting on http://${HOST}:${PORT}/"
    nohup python3 -m flask --app app run --host "$HOST" --port "$PORT" \
      >"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if is_running; then info "up (pid $(cat "$PIDFILE")) · log: $LOGFILE"
    else error "failed to start — see $LOGFILE"; tail -n 20 "$LOGFILE" >&2; exit 1; fi
    ;;
  stop)
    if is_running; then
      kill "$(cat "$PIDFILE")" 2>/dev/null && info "stopped (pid $(cat "$PIDFILE"))"
      rm -f "$PIDFILE"
    else warn "not running"; rm -f "$PIDFILE"; fi
    ;;
  status)
    if is_running; then info "running (pid $(cat "$PIDFILE")) on http://${HOST}:${PORT}/"
    else warn "not running"; fi
    if [ -f "$DB" ]; then
      python3 - "$DB" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
ch = c.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
dc = c.execute("SELECT COUNT(DISTINCT doc_path) FROM chunks").fetchone()[0]
sc = c.execute("SELECT COUNT(*) FROM shortcuts").fetchone()[0]
at = c.execute("SELECT MAX(indexed_at) FROM chunk_meta").fetchone()[0]
print(f"[vquery] index: {ch} chunks · {dc} docs · {sc} shortcuts · built {at}")
PY
    else warn "no index built yet (./run.sh rebuild)"; fi
    ;;
  rebuild)
    python3 build.py || { error "rebuild failed"; exit 1; }
    is_running && info "live server will serve the new index on next query"
    ;;
  import-shortcuts)
    if [ ! -f "$DB" ]; then ensure_db
    else python3 build.py shortcuts || { error "shortcut import failed"; exit 1; }; fi
    is_running && info "live server will serve new shortcuts on next query"
    ;;
  *)
    error "usage: $0 [start|stop|status|rebuild|import-shortcuts]"
    exit 2
    ;;
esac
