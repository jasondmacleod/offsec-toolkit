"""Chunks -> SQLite FTS5 index.

Drop-and-rebuild, mirroring exploitdb's loader philosophy: the DB is a
derived artifact, never migrated. `build_index()` recreates it from the
vault on every call in well under a second for this corpus.

Schema (per the vquery handoff):

  chunks      FTS5 virtual table. heading_anchor / display_path are
              UNINDEXED — they are slugs / display strings, not natural
              language; indexing them only pollutes BM25. The BM25
              column weights implement the spec's ranking boosts
              natively (heading +50%, doc_title +25%, tags +25%).
  chunk_meta  plain table: word_count, line span, indexed_at.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .chunker import chunk_file, discover

SCHEMA = """
DROP TABLE IF EXISTS chunks;
DROP TABLE IF EXISTS chunk_meta;

CREATE VIRTUAL TABLE chunks USING fts5(
    chunk_id UNINDEXED,
    doc_path,
    doc_title,
    heading,
    heading_anchor UNINDEXED,
    body,
    tags,
    wikilinks,
    display_path UNINDEXED,
    tokenize = 'porter unicode61'
);

CREATE TABLE chunk_meta (
    chunk_id   TEXT PRIMARY KEY,
    word_count INTEGER,
    line_start INTEGER,
    line_end   INTEGER,
    indexed_at TEXT
);
"""

# Column order must match the CREATE above — bm25() takes one weight per
# column, positionally. UNINDEXED columns contribute 0 regardless.
INSERT_COLS = (
    "chunk_id", "doc_path", "doc_title", "heading", "heading_anchor",
    "body", "tags", "wikilinks", "display_path",
)


def fts5_available(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE temp.__fts5_probe USING fts5(x)")
        conn.execute("DROP TABLE temp.__fts5_probe")
        return True
    except sqlite3.OperationalError:
        return False


def build_index(db_path: Path, vault_root: Path, exclude_globs: list[str]) -> dict:
    """Rebuild db_path from vault_root. Returns a stats dict.

    Raises FileNotFoundError if the vault is missing, RuntimeError if the
    sqlite build lacks FTS5 — both are surfaced clearly at startup.
    """
    if not vault_root.exists() or not vault_root.is_dir():
        raise FileNotFoundError(
            f"Vault path not found: {vault_root}\n"
            f"Set VQUERY_VAULT_PATH to your Obsidian vault directory."
        )

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        if not fts5_available(conn):
            raise RuntimeError(
                "SQLite FTS5 is not available in this Python's sqlite3. "
                "On Kali: `apt install sqlite3` (FTS5 is compiled in by "
                "default); ensure python3 uses the system libsqlite3."
            )
        conn.executescript(SCHEMA)

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        files = discover(vault_root, exclude_globs)
        total_files = 0
        total_chunks = 0
        for abs_path, doc_path in files:
            chunks = chunk_file(abs_path, doc_path)
            if not chunks:
                continue
            total_files += 1
            for c in chunks:
                conn.execute(
                    f"INSERT INTO chunks ({', '.join(INSERT_COLS)}) "
                    f"VALUES ({', '.join('?' * len(INSERT_COLS))})",
                    (c.chunk_id, c.doc_path, c.doc_title, c.heading,
                     c.heading_anchor, c.body, c.tags, c.wikilinks,
                     c.display_path),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO chunk_meta "
                    "(chunk_id, word_count, line_start, line_end, indexed_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (c.chunk_id, c.word_count, c.line_start, c.line_end, now),
                )
                total_chunks += 1
        conn.commit()
        all_files = sorted(vault_root.rglob("*.md"))
        return {
            "files_indexed": total_files,
            "files_seen": len(all_files),
            "files_skipped": len(all_files) - total_files,
            "chunks": total_chunks,
            "indexed_at": now,
            "vault_root": str(vault_root),
            "exclude_globs": exclude_globs,
        }
    finally:
        conn.close()
