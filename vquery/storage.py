"""vquery phase 2 — persistent user state + exploitdb cross-reference cache.

Phase 1's index (chunks / chunk_meta / shortcuts) is a derived artifact:
build.py drops and recreates exactly those tables, never the DB file. The
tables here are the opposite — they are *user data* (logged gaps, pins) or
a *derived cache keyed off a sibling app* (xref). They must survive
`./run.sh rebuild`, so:

  - The persistent tables are CREATE … IF NOT EXISTS and never dropped.
    `ensure_schema()` is idempotent and cheap; the app calls it on every
    DB open (single-user engagement tool — microseconds, simplest correct hook).
  - `xref_cache` is the one derived table here. `rebuild_xref()` clears
    and repopulates it from exploitdb's seed JSON. It is the SQLite cache
    backing the spec's "in-memory reverse index": PRIMARY KEY (chunk_id,
    exploitdb_slug) makes the chunk→entry lookup an indexed point read.

Session correlation (needed only for the soft-zero heuristic) rides on an
opaque httponly cookie; the cookie carries no state — every fact lives in
SQLite, per the handoff's "no browser storage APIs" rule.

No AI inference, no network: `rebuild_xref` reads local JSON; everything
else is SQL. exploitdb's banned-entry filter is mirrored here so a banned
slug can never become a live cross-reference.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

SOFT_ZERO_WINDOW_SEC = 15  # handoff: query then re-query within 15s, nothing opened
PIN_TYPES = {"chunk", "shortcut"}
RELEVANCE_ORDER = ["primary", "tool", "prerequisite", "followup", "gotcha"]
RESOLUTION_TYPES = {"shortcut_authored", "content_added", "wont_fix", "noise"}

# Persistent + cache schema. Order matters only for readability — every
# statement is independently idempotent.
SCHEMA = """
CREATE TABLE IF NOT EXISTS query_log (
    query_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    query_text      TEXT NOT NULL,
    normalized_query TEXT NOT NULL,
    result_count    INTEGER,
    shortcut_matched BOOLEAN,
    timestamp       TEXT NOT NULL,
    session_id      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_query_log_session ON query_log(session_id, query_id);
CREATE INDEX IF NOT EXISTS idx_query_log_norm ON query_log(normalized_query);

CREATE TABLE IF NOT EXISTS gap_signals (
    signal_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    query_id        INTEGER REFERENCES query_log(query_id),
    signal_type     TEXT NOT NULL,
    context_chunk_id TEXT,
    notes           TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gap_signals_query ON gap_signals(query_id);

CREATE TABLE IF NOT EXISTS gap_resolutions (
    resolution_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    normalized_query TEXT NOT NULL,
    resolution_type TEXT NOT NULL,
    target_slug     TEXT,
    resolved_at     TEXT NOT NULL,
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_gap_resolutions_norm ON gap_resolutions(normalized_query);

CREATE TABLE IF NOT EXISTS pins (
    pin_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    pinned_at   TEXT NOT NULL,
    note        TEXT,
    sort_order  INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pins_target ON pins(target_type, target_id);

-- Internal support table (not in the handoff DDL): records that the user
-- engaged with a result for a query, so the soft-zero heuristic can tell
-- "dismissed everything" from "found the answer". Implementation detail of
-- the spec's "no result was opened" clause, not a user-facing surface.
CREATE TABLE IF NOT EXISTS query_opens (
    query_id  INTEGER PRIMARY KEY REFERENCES query_log(query_id),
    opened_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xref_cache (
    chunk_id       TEXT NOT NULL,
    exploitdb_slug TEXT NOT NULL,
    relevance      TEXT NOT NULL,
    note           TEXT,
    ingested_at    TEXT NOT NULL,
    PRIMARY KEY (chunk_id, exploitdb_slug)
);

-- Key/value sidecar so the UI can tell "exploitdb unavailable at ingest"
-- (show the retry hint) apart from "available, just no xref for this
-- chunk" (show the honest empty state).
CREATE TABLE IF NOT EXISTS xref_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _warn(msg: str) -> None:
    print(f"[vquery.storage] {msg}", file=sys.stderr)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Idempotently create the persistent + cache tables. Safe to call on
    every DB open; never drops anything."""
    conn.executescript(SCHEMA)


def normalize_query(q: str) -> str:
    """Lowercase, whitespace-collapsed — the grouping key for gaps."""
    return " ".join((q or "").lower().split())


# -- Session ------------------------------------------------------------

def get_or_make_session_id(cookie_val: str | None) -> tuple[str, bool]:
    """Return (session_id, is_new). The id is opaque; all state is in
    SQLite. Caller sets the cookie on the response when is_new."""
    if cookie_val and len(cookie_val) <= 64 and cookie_val.replace("-", "").isalnum():
        return cookie_val, False
    return uuid.uuid4().hex, True


# -- Query logging + gap signals ---------------------------------------

def _prev_query(conn: sqlite3.Connection, session_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM query_log WHERE session_id = ? "
        "ORDER BY query_id DESC LIMIT 1", (session_id,)
    ).fetchone()


def _has_signal(conn: sqlite3.Connection, query_id: int, signal_type: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM gap_signals WHERE query_id = ? AND signal_type = ?",
        (query_id, signal_type),
    ).fetchone() is not None


def log_query(conn: sqlite3.Connection, query_text: str, result_count: int,
              shortcut_matched: bool, session_id: str) -> int:
    """Log one user query. Side effects, in order:

      1. Soft-zero check on the *previous* query in this session: it had
         results, the user opened nothing, and re-queried within 15s →
         it was a dud the user silently abandoned.
      2. Insert this query.
      3. Hard-zero: this query found nothing at all (no chunks, no
         shortcut) → log it immediately; the search page footer surfaces it.

    Returns the new query_id.
    """
    prev = _prev_query(conn, session_id)
    now = _now()

    if prev is not None:
        ts_prev = prev["timestamp"]
        try:
            dt = (datetime.fromisoformat(now)
                  - datetime.fromisoformat(ts_prev)).total_seconds()
        except ValueError:
            dt = SOFT_ZERO_WINDOW_SEC + 1
        opened = conn.execute(
            "SELECT 1 FROM query_opens WHERE query_id = ?", (prev["query_id"],)
        ).fetchone() is not None
        if (0 <= dt <= SOFT_ZERO_WINDOW_SEC
                and (prev["result_count"] or 0) > 0
                and not opened
                and not _has_signal(conn, prev["query_id"], "hard_zero")
                and not _has_signal(conn, prev["query_id"], "soft_zero")):
            conn.execute(
                "INSERT INTO gap_signals "
                "(query_id, signal_type, created_at) VALUES (?, 'soft_zero', ?)",
                (prev["query_id"], now),
            )

    cur = conn.execute(
        "INSERT INTO query_log (query_text, normalized_query, result_count, "
        "shortcut_matched, timestamp, session_id) VALUES (?, ?, ?, ?, ?, ?)",
        (query_text, normalize_query(query_text), result_count,
         1 if shortcut_matched else 0, now, session_id),
    )
    qid = cur.lastrowid

    if result_count == 0 and not shortcut_matched:
        conn.execute(
            "INSERT INTO gap_signals (query_id, signal_type, created_at) "
            "VALUES (?, 'hard_zero', ?)", (qid, now),
        )
    conn.commit()
    return qid


def record_open(conn: sqlite3.Connection, query_id: int) -> None:
    """The user engaged with a result (expand / open / copy) for query_id.
    Suppresses a later soft-zero verdict on it."""
    conn.execute(
        "INSERT OR IGNORE INTO query_opens (query_id, opened_at) VALUES (?, ?)",
        (query_id, _now()),
    )
    conn.commit()


def record_explicit_gap(conn: sqlite3.Connection, query_id: int,
                         chunk_id: str | None) -> None:
    """User clicked 'didn't help' on a result for query_id."""
    if conn.execute("SELECT 1 FROM query_log WHERE query_id = ?",
                     (query_id,)).fetchone() is None:
        return
    conn.execute(
        "INSERT INTO gap_signals (query_id, signal_type, context_chunk_id, "
        "created_at) VALUES (?, 'explicit_gap', ?, ?)",
        (query_id, chunk_id or None, _now()),
    )
    conn.commit()


def last_query_id(conn: sqlite3.Connection, session_id: str) -> int | None:
    row = _prev_query(conn, session_id)
    return row["query_id"] if row else None


# -- Gap aggregation (for /gaps) ---------------------------------------

def _resolved_norms(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    """Latest resolution per normalized_query."""
    out: dict[str, sqlite3.Row] = {}
    for r in conn.execute(
        "SELECT * FROM gap_resolutions ORDER BY resolution_id"
    ):
        out[r["normalized_query"]] = r
    return out


def active_gaps(conn: sqlite3.Connection, sort: str = "count") -> list[dict]:
    """Unresolved gaps grouped by normalized_query.

    A group is unresolved iff its normalized_query has no row in
    gap_resolutions (any resolution — including 'noise' and 'wont_fix' —
    removes it from the active list; 'wont_fix' resurfaces in the history
    section, 'noise' is suppressed everywhere)."""
    resolved = set(_resolved_norms(conn).keys())
    rows = conn.execute(
        """
        SELECT q.normalized_query AS nq,
               COUNT(DISTINCT q.query_id) AS occurrences,
               MAX(q.timestamp) AS last_seen,
               MIN(q.query_text) AS sample_text,
               GROUP_CONCAT(DISTINCT s.signal_type) AS signal_types
          FROM query_log q
          JOIN gap_signals s ON s.query_id = q.query_id
         GROUP BY q.normalized_query
        """
    ).fetchall()
    groups: list[dict] = []
    for r in rows:
        if r["nq"] in resolved:
            continue
        types = sorted(set((r["signal_types"] or "").split(",")))
        groups.append({
            "normalized_query": r["nq"],
            "query_text": r["sample_text"],
            "occurrences": r["occurrences"],
            "last_seen": r["last_seen"],
            "signal_types": types,
        })
    if sort == "date":
        groups.sort(key=lambda g: g["last_seen"], reverse=True)
    elif sort == "alpha":
        groups.sort(key=lambda g: g["normalized_query"])
    else:  # count desc, then most-recent
        groups.sort(key=lambda g: (g["occurrences"], g["last_seen"]),
                    reverse=True)
    return groups


def resolved_gaps(conn: sqlite3.Connection) -> list[dict]:
    """History rows. 'noise' is filtered out entirely (handoff); the rest
    show as resolved, with 'wont_fix' flagged as explicitly skipped."""
    out: list[dict] = []
    for r in conn.execute(
        "SELECT * FROM gap_resolutions ORDER BY resolved_at DESC, resolution_id DESC"
    ):
        if r["resolution_type"] == "noise":
            continue
        out.append(dict(r))
    return out


def resolve_gap(conn: sqlite3.Connection, normalized_query: str,
                resolution_type: str, target_slug: str | None,
                notes: str | None) -> bool:
    if resolution_type not in RESOLUTION_TYPES or not normalized_query:
        return False
    conn.execute(
        "INSERT INTO gap_resolutions (normalized_query, resolution_type, "
        "target_slug, resolved_at, notes) VALUES (?, ?, ?, ?, ?)",
        (normalized_query, resolution_type, (target_slug or "").strip() or None,
         _now(), (notes or "").strip() or None),
    )
    conn.commit()
    return True


def gap_counts(conn: sqlite3.Connection) -> dict:
    """Headline numbers for nav / dashboards."""
    active = len(active_gaps(conn))
    total_signals = conn.execute(
        "SELECT COUNT(*) AS n FROM gap_signals").fetchone()["n"]
    return {"active": active, "signals": total_signals}


# -- Pins ---------------------------------------------------------------

def is_pinned(conn: sqlite3.Connection, target_type: str, target_id: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM pins WHERE target_type = ? AND target_id = ?",
        (target_type, target_id),
    ).fetchone() is not None


def toggle_pin(conn: sqlite3.Connection, target_type: str,
               target_id: str) -> bool:
    """Flip pin state. Returns the new state (True = now pinned)."""
    if target_type not in PIN_TYPES or not target_id:
        raise ValueError(f"bad pin target {target_type!r}/{target_id!r}")
    if is_pinned(conn, target_type, target_id):
        conn.execute(
            "DELETE FROM pins WHERE target_type = ? AND target_id = ?",
            (target_type, target_id),
        )
        conn.commit()
        return False
    nxt = conn.execute(
        "SELECT COALESCE(MAX(sort_order), 0) + 1 AS n FROM pins"
    ).fetchone()["n"]
    conn.execute(
        "INSERT INTO pins (target_type, target_id, pinned_at, sort_order) "
        "VALUES (?, ?, ?, ?)", (target_type, target_id, _now(), nxt),
    )
    conn.commit()
    return True


def list_pins(conn: sqlite3.Connection) -> list[dict]:
    """Pins in manual order (sort_order asc, then newest first)."""
    rows = conn.execute(
        "SELECT * FROM pins ORDER BY sort_order, pinned_at DESC, pin_id"
    ).fetchall()
    return [dict(r) for r in rows]


def set_pin_note(conn: sqlite3.Connection, pin_id: int, note: str) -> None:
    conn.execute("UPDATE pins SET note = ? WHERE pin_id = ?",
                 ((note or "").strip() or None, pin_id))
    conn.commit()


def reorder_pins(conn: sqlite3.Connection, ordered_pin_ids: list[int]) -> None:
    for i, pid in enumerate(ordered_pin_ids):
        conn.execute("UPDATE pins SET sort_order = ? WHERE pin_id = ?",
                     (i, pid))
    conn.commit()


# -- exploitdb cross-reference ingest + reads --------------------------

def _entry_slug(e: dict) -> str | None:
    """Mirror exploitdb/load_seed.normalize_entry: v1 entries key on
    `id`, v2 on `slug`. The served /entry/<slug> uses exactly this."""
    if "id" in e and "slug" not in e:
        return e.get("id")
    return e.get("slug")


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO xref_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value),
    )


def get_xref_status(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT value FROM xref_meta WHERE key = 'status'").fetchone()
    return row["value"] if row else "never_built"


def rebuild_xref(conn: sqlite3.Connection, seed_dir: Path) -> dict:
    """Clear and rebuild xref_cache from exploitdb's seed JSON.

    Source of truth is the exploitdb side: each entry may carry a
    `related_vquery: [{chunk_id, relevance, note}]`. Banned entries are
    skipped (mirrors exploitdb's own load filter — a banned slug must
    never resolve to a live cross-reference). Malformed rows are logged
    and skipped; one bad entry never blocks ingest. Broken chunk_ids are
    *kept* (so /xref-health can report them) — validation is a health
    concern, not an ingest gate.

    If the seed directory is missing the cache is left empty and status
    is 'unavailable' so the sidebar can show the retry hint instead of a
    misleading empty state.
    """
    ensure_schema(conn)
    conn.execute("DELETE FROM xref_cache")
    now = _now()

    if not seed_dir.is_dir():
        _set_meta(conn, "status", "unavailable")
        _set_meta(conn, "ingested_at", now)
        _set_meta(conn, "seed_dir", str(seed_dir))
        conn.commit()
        _warn(f"exploitdb seed dir not found: {seed_dir} — xref unavailable")
        return {"status": "unavailable", "xref_rows": 0,
                "entries_with_xref": 0, "seed_dir": str(seed_dir)}

    files = sorted(p for p in seed_dir.glob("*.json")
                   if not p.name.startswith("AUDIT"))
    rows = 0
    entries_with_xref = 0
    seen: set[tuple[str, str]] = set()
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            _warn(f"{path.name}: unreadable ({e}) — skipped")
            continue
        entries = data["entries"] if isinstance(data, dict) else data
        for e in entries:
            if not isinstance(e, dict):
                continue
            related = e.get("related_vquery")
            if not related:
                continue
            if e.get("compliance") == "offsec_banned":
                continue
            slug = _entry_slug(e)
            if not slug:
                _warn(f"{path.name}: related_vquery on entry with no slug/id")
                continue
            if not isinstance(related, list):
                _warn(f"{path.name}: '{slug}' related_vquery not a list — skipped")
                continue
            counted = False
            for ref in related:
                if not isinstance(ref, dict):
                    _warn(f"{path.name}: '{slug}' related_vquery item not an "
                          f"object — skipped")
                    continue
                cid = (ref.get("chunk_id") or "").strip()
                if not cid:
                    _warn(f"{path.name}: '{slug}' related_vquery item missing "
                          f"chunk_id — skipped")
                    continue
                rel = (ref.get("relevance") or "primary").strip().lower()
                if rel not in RELEVANCE_ORDER:
                    rel = "primary"
                key = (cid, slug)
                if key in seen:
                    continue
                seen.add(key)
                conn.execute(
                    "INSERT OR REPLACE INTO xref_cache (chunk_id, "
                    "exploitdb_slug, relevance, note, ingested_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (cid, slug, rel, (ref.get("note") or "").strip() or None,
                     now),
                )
                rows += 1
                counted = True
            if counted:
                entries_with_xref += 1

    _set_meta(conn, "status", "ok")
    _set_meta(conn, "ingested_at", now)
    _set_meta(conn, "seed_dir", str(seed_dir))
    _set_meta(conn, "xref_rows", str(rows))
    _set_meta(conn, "entries_with_xref", str(entries_with_xref))
    conn.commit()
    return {"status": "ok", "xref_rows": rows,
            "entries_with_xref": entries_with_xref,
            "seed_dir": str(seed_dir)}


def served_exploitdb_slugs(seed_dir: Path) -> set[str] | None:
    """The set of slugs exploitdb would actually serve (non-banned).

    Returns None if the seed dir is unreadable — the caller then skips
    broken-slug detection rather than reporting every xref as broken."""
    if not seed_dir.is_dir():
        return None
    slugs: set[str] = set()
    for path in sorted(seed_dir.glob("*.json")):
        if path.name.startswith("AUDIT"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for e in (data["entries"] if isinstance(data, dict) else data):
            if not isinstance(e, dict) or e.get("compliance") == "offsec_banned":
                continue
            s = _entry_slug(e)
            if s:
                slugs.add(s)
    return slugs


def xref_for_chunk(conn: sqlite3.Connection, chunk_id: str) -> list[dict]:
    """Cross-references for one chunk, grouped + ordered by relevance.

    Returns [] when the chunk simply has none. The caller distinguishes
    that from 'exploitdb unavailable' via get_xref_status()."""
    rows = conn.execute(
        "SELECT exploitdb_slug, relevance, note FROM xref_cache "
        "WHERE chunk_id = ?", (chunk_id,)
    ).fetchall()
    by_rel: dict[str, list[dict]] = {}
    for r in rows:
        by_rel.setdefault(r["relevance"], []).append(
            {"exploitdb_slug": r["exploitdb_slug"], "note": r["note"]})
    groups: list[dict] = []
    for rel in RELEVANCE_ORDER:
        items = by_rel.get(rel)
        if items:
            items.sort(key=lambda x: x["exploitdb_slug"])
            groups.append({"relevance": rel, "items": items})
    return groups


def xref_health(conn: sqlite3.Connection, total_chunks: int,
                exploitdb_slugs: set[str] | None = None) -> dict:
    """Curator dashboard data.

    broken_chunks      : xref chunk_ids with no chunk in this index
    broken_slugs       : xref exploitdb slugs not in the served corpus
                         (only computable when exploitdb_slugs is passed)
    coverage           : entries / chunks that have ≥1 cross-reference
    """
    all_rows = conn.execute(
        "SELECT chunk_id, exploitdb_slug, relevance, note FROM xref_cache "
        "ORDER BY chunk_id, exploitdb_slug"
    ).fetchall()
    valid_chunks = {
        r["chunk_id"] for r in conn.execute("SELECT chunk_id FROM chunk_meta")
    }
    broken_chunks: list[dict] = []
    broken_slugs: list[dict] = []
    chunks_covered: set[str] = set()
    slugs_covered: set[str] = set()
    for r in all_rows:
        d = dict(r)
        if r["chunk_id"] not in valid_chunks:
            broken_chunks.append(d)
        else:
            chunks_covered.add(r["chunk_id"])
        if exploitdb_slugs is not None and r["exploitdb_slug"] not in exploitdb_slugs:
            broken_slugs.append(d)
        else:
            slugs_covered.add(r["exploitdb_slug"])
    return {
        "status": get_xref_status(conn),
        "total_xrefs": len(all_rows),
        "broken_chunks": broken_chunks,
        "broken_slugs": broken_slugs,
        "entries_covered": len(slugs_covered),
        "chunks_covered": len(chunks_covered),
        "total_chunks": total_chunks,
        "ingested_at": (conn.execute(
            "SELECT value FROM xref_meta WHERE key = 'ingested_at'"
        ).fetchone() or {"value": None})["value"],
    }
