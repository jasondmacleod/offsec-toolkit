"""Shortcut JSON -> `shortcuts` table.

Shortcuts are the killer feature and they live in version-controlled
JSON, not the DB. This loads `data/shortcuts/*.json` into a `shortcuts`
table (dropped and recreated each run).

Each JSON file may be a single shortcut object, a bare array of them,
or `{"shortcuts": [...]}`. A malformed shortcut logs to stderr and is
skipped — one bad file never blocks the others (handoff failure-mode
spec).

A shortcut whose `answer_type` is `chunk_ref` but whose
`target_chunk_id` does not resolve is NOT rejected here: it loads, and
the `/shortcuts` page flags it BROKEN. Validation belongs in the audit
surface, not at load time, so a stale reference can never take search
down.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

SCHEMA = """
DROP TABLE IF EXISTS shortcuts;
CREATE TABLE shortcuts (
    slug            TEXT PRIMARY KEY,
    triggers        TEXT,        -- JSON array of trigger phrases
    title           TEXT,
    answer_type     TEXT,        -- "chunk_ref" | "inline"
    target_chunk_id TEXT,
    inline_answer   TEXT,
    inline_followup TEXT,
    tags            TEXT,
    priority        INTEGER DEFAULT 100,
    source_file     TEXT         -- which JSON it came from (audit aid)
);
"""

VALID_TYPES = {"chunk_ref", "inline"}


def _warn(msg: str) -> None:
    print(f"[shortcut_loader] {msg}", file=sys.stderr)


def _iter_shortcut_objs(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "shortcuts" in data and isinstance(data["shortcuts"], list):
            return data["shortcuts"]
        return [data]
    return []


def _normalize(obj: dict, source: str) -> dict | None:
    slug = (obj.get("slug") or "").strip()
    if not slug:
        _warn(f"{source}: shortcut missing 'slug' — skipped")
        return None
    answer_type = (obj.get("answer_type") or "").strip()
    if answer_type not in VALID_TYPES:
        _warn(f"{source}: '{slug}' has invalid answer_type "
              f"{answer_type!r} — skipped")
        return None
    triggers = obj.get("triggers") or []
    if not isinstance(triggers, list) or not triggers:
        _warn(f"{source}: '{slug}' has no triggers — skipped")
        return None
    if answer_type == "chunk_ref" and not (obj.get("target_chunk_id") or "").strip():
        _warn(f"{source}: '{slug}' is chunk_ref with no target_chunk_id — skipped")
        return None
    if answer_type == "inline" and not (obj.get("inline_answer") or "").strip():
        _warn(f"{source}: '{slug}' is inline with no inline_answer — skipped")
        return None
    return {
        "slug": slug,
        "triggers": json.dumps([str(t).strip() for t in triggers if str(t).strip()]),
        "title": (obj.get("title") or slug).strip(),
        "answer_type": answer_type,
        "target_chunk_id": (obj.get("target_chunk_id") or "").strip() or None,
        "inline_answer": obj.get("inline_answer") or None,
        "inline_followup": (obj.get("inline_followup") or "").strip() or None,
        "tags": (obj.get("tags") or "").strip(),
        "priority": int(obj.get("priority", 100)),
        "source_file": source,
    }


def load_shortcuts(db_path: Path, shortcuts_dir: Path) -> dict:
    """(Re)create the shortcuts table from shortcuts_dir/*.json."""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        loaded = 0
        skipped = 0
        seen_slugs: set[str] = set()
        files = sorted(shortcuts_dir.glob("*.json")) if shortcuts_dir.exists() else []
        for jf in files:
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                _warn(f"{jf.name}: unreadable/invalid JSON ({e}) — file skipped")
                continue
            for obj in _iter_shortcut_objs(data):
                if not isinstance(obj, dict):
                    _warn(f"{jf.name}: non-object shortcut entry — skipped")
                    skipped += 1
                    continue
                row = _normalize(obj, jf.name)
                if row is None:
                    skipped += 1
                    continue
                if row["slug"] in seen_slugs:
                    _warn(f"{jf.name}: duplicate slug '{row['slug']}' — skipped")
                    skipped += 1
                    continue
                seen_slugs.add(row["slug"])
                cols = list(row.keys())
                conn.execute(
                    f"INSERT INTO shortcuts ({', '.join(cols)}) "
                    f"VALUES ({', '.join('?' * len(cols))})",
                    [row[c] for c in cols],
                )
                loaded += 1
        conn.commit()
        return {"shortcuts_loaded": loaded, "shortcuts_skipped": skipped,
                "files": len(files)}
    finally:
        conn.close()
