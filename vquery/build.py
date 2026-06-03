#!/usr/bin/env python3
"""Rebuild the vquery index and/or shortcuts from source.

    python3 build.py            # rebuild index + shortcuts
    python3 build.py shortcuts  # reload shortcuts only (vault untouched)

The DB is a derived artifact (drop-and-rebuild, no migrations), exactly
like exploitdb's load_seed.py. Source of truth stays in the vault
markdown and data/shortcuts/*.json. Idempotent.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import sqlite3

import storage
from indexer.indexer import build_index
from indexer.shortcut_loader import load_shortcuts

HERE = Path(__file__).parent
DB_PATH = HERE / "data" / "vquery.sqlite"
SHORTCUTS_DIR = HERE / "data" / "shortcuts"
VAULT_PATH = Path(os.environ.get(
    "VQUERY_VAULT_PATH", os.path.expanduser("~/scripts/vault"))).resolve()
EXPLOITDB_SEED_DIR = Path(os.environ.get(
    "VQUERY_EXPLOITDB_SEED",
    str(HERE.parent / "exploitdb" / "data" / "seed"))).resolve()

_NC = os.environ.get("NO_COLOR") or not sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return text if _NC else f"\033[{code}m{text}\033[0m"


def main() -> int:
    only_shortcuts = len(sys.argv) > 1 and sys.argv[1] == "shortcuts"
    import re
    excl = [g.strip() for g in re.split(
        r"[,:]", os.environ.get("VQUERY_EXCLUDE", "Not for the engagement/")) if g.strip()]

    try:
        if not only_shortcuts:
            stats = build_index(DB_PATH, VAULT_PATH, excl)
            print(_c("32", "[index]"),
                  f"{stats['chunks']} chunks from {stats['files_indexed']} files "
                  f"({stats['files_skipped']} skipped of {stats['files_seen']})")
            if excl:
                print(_c("33", "[index]"), f"excluded globs: {', '.join(excl)}")
        sc = load_shortcuts(DB_PATH, SHORTCUTS_DIR)
        msg = (f"{sc['shortcuts_loaded']} loaded, "
               f"{sc['shortcuts_skipped']} skipped, {sc['files']} file(s)")
        print(_c("32", "[shortcuts]"), msg)
    except (FileNotFoundError, RuntimeError) as e:
        print(_c("31", "[error]"), e, file=sys.stderr)
        return 1

    # Persistent user tables (gaps, pins) are created here if absent and
    # never dropped — drop-and-rebuild is only the derived index. The
    # xref cache *is* derived, so it's cleared and rebuilt every time.
    conn = sqlite3.connect(DB_PATH)
    try:
        storage.ensure_schema(conn)
        x = storage.rebuild_xref(conn, EXPLOITDB_SEED_DIR)
    finally:
        conn.close()
    if x["status"] == "ok":
        print(_c("32", "[xref]"),
              f"{x['xref_rows']} cross-refs from {x['entries_with_xref']} "
              f"exploitdb entries")
    else:
        print(_c("33", "[xref]"),
              f"exploitdb seed unavailable ({x['seed_dir']}) — "
              f"sidebar will show retry hint")
    print(_c("32", "[ok]"), f"db at {DB_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
