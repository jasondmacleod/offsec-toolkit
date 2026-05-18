"""vquery — Vault Query Engine.

Local, read-only, OffSec-rules-compliant retrieval over the Obsidian
vault. No AI inference at runtime: every shortcut and chunk is
pre-curated and stored in SQLite. The app is pure indexing + retrieval.

Companion to exploitdb (port 5050):
  - exploitdb  = "what command do I run for this exploit"
  - vquery     = "how do I think about this; what's the syntax I keep
                  forgetting; what does my methodology say to do here"
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import markdown as md
from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, url_for)

from indexer.chunker import slugify
from indexer.indexer import build_index
from indexer.shortcut_loader import load_shortcuts

HERE = Path(__file__).parent
DB_PATH = HERE / "data" / "vquery.sqlite"
SHORTCUTS_DIR = HERE / "data" / "shortcuts"

VAULT_PATH = Path(os.environ.get(
    "VQUERY_VAULT_PATH", os.path.expanduser("~/scripts/vault"))).resolve()

# Excluded by default: "Not FOR engagement/" holds banned/irrelevant material
# (sqlmap, AV evasion). Surfacing it in a sub-10s engagement-day tool is a
# compliance footgun (AGENTS.md §9). Override with VQUERY_EXCLUDE
# (comma/colon-separated globs); empty string indexes everything.
_excl_raw = os.environ.get("VQUERY_EXCLUDE", "Not FOR engagement/")
EXCLUDE_GLOBS = [g.strip() for g in re.split(r"[,:]", _excl_raw) if g.strip()]

DEFAULT_N = 12
MAX_N = 50

# bm25() weights, one per FTS5 column, in CREATE order. Implements the
# handoff ranking spec: heading +50%, doc_title +25%, tags +25% over a
# body baseline of 1.0. UNINDEXED columns get 0.0 (ignored anyway).
BM25_WEIGHTS = (0.0, 0.5, 1.25, 1.5, 0.0, 1.0, 1.25, 0.5, 0.0)

app = Flask(__name__)


# -- DB plumbing --------------------------------------------------------

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        if not DB_PATH.exists():
            abort(503, description="Index not built. Run: ./run.sh rebuild")
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# -- Search -------------------------------------------------------------

def build_fts_query(q: str) -> str | None:
    """Quote each whitespace token so `-m`, `13100`, `nt:authority`
    never parse as FTS5 operators."""
    if not q or not q.strip():
        return None
    tokens = [t.strip('"') for t in q.strip().split() if t.strip('"')]
    if not tokens:
        return None
    return " ".join(f'"{t}"' for t in tokens)


def _trigger_match(triggers: list[str], ql: str) -> tuple[int, int, str] | None:
    """Best (tier, trigger_len, trigger) for ql across triggers, or None.

    tier 3 = a trigger equals the query exactly,
    tier 2 = a trigger is fully contained in the query (the query names
             this specific shortcut and then some),
    tier 1 = the query is a fragment of a longer trigger.
    Longer matched trigger breaks ties within a tier.
    """
    best: tuple[int, int, str] | None = None
    for t in triggers:
        tl = t.lower()
        if tl == ql:
            tier = 3
        elif tl in ql:
            tier = 2
        elif ql in tl:
            tier = 1
        else:
            continue
        cand = (tier, len(tl), t)
        if best is None or cand > best:
            best = cand
    return best


def search_shortcuts(q: str) -> list[dict]:
    """Shortcuts whose triggers match q (case-insensitive, either
    direction so fat-fingered or over-typed queries still hit).

    Ranked by match specificity first (exact trigger > specific trigger
    fully present in the query > query is a fragment of a longer
    trigger), then priority desc, then longer trigger. This is a
    deliberate refinement of the spec's "priority desc only": a generic
    high-priority trigger no longer outranks a more specific shortcut
    that the query names exactly (e.g. `ligolo` → setup, but
    `ligolo fails` → the troubleshooting shortcut)."""
    ql = q.strip().lower()
    if not ql:
        return []
    db = get_db()
    out: list[dict] = []
    for row in db.execute("SELECT * FROM shortcuts"):
        try:
            triggers = json.loads(row["triggers"])
        except (json.JSONDecodeError, TypeError):
            triggers = []
        m = _trigger_match(triggers, ql)
        if m is None:
            continue
        s = dict(row)
        s["triggers"] = triggers
        s["matched_trigger"] = m[2]
        s["_rank"] = (m[0], int(row["priority"] or 0), m[1])
        s["is_broken"] = (
            s["answer_type"] == "chunk_ref"
            and not _chunk_exists(s["target_chunk_id"])
        )
        out.append(s)
    out.sort(key=lambda s: (-s["_rank"][0], -s["_rank"][1],
                            -s["_rank"][2], s["slug"]))
    return out


def search_chunks(q: str, limit: int) -> list[dict]:
    fts = build_fts_query(q)
    if fts is None:
        return []
    db = get_db()
    weights = ", ".join(str(w) for w in BM25_WEIGHTS)
    rows = db.execute(
        f"SELECT chunk_id, doc_path, doc_title, heading, heading_anchor, "
        f"       body, tags, display_path, "
        f"       bm25(chunks, {weights}) AS score "
        f"FROM chunks WHERE chunks MATCH ? ORDER BY score LIMIT ?",
        (fts, limit),
    ).fetchall()
    terms = [t.lower() for t in q.split()]
    results: list[dict] = []
    for r in rows:
        d = dict(r)
        d["match_type"] = _match_type(d, terms)
        d["snippet"] = _snippet(d["body"])
        d["tag_list"] = d["tags"].split() if d["tags"] else []
        results.append(d)
    return results


def _match_type(chunk: dict, terms: list[str]) -> str:
    h = (chunk.get("heading") or "").lower()
    t = (chunk.get("tags") or "").lower()
    if any(term in h for term in terms):
        return "heading-match"
    if any(term in t for term in terms):
        return "tag-match"
    return "body-match"


def _snippet(body: str, n: int = 150) -> str:
    """First ~n chars of readable body: drop heading hashes and fence
    lines so the preview is answer-shaped, not `## ...`."""
    lines = []
    for ln in (body or "").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("```") or s.startswith("~~~"):
            continue
        lines.append(s)
        if len(" ".join(lines)) > n:
            break
    text = " ".join(lines)
    return text[:n] + "…" if len(text) > n else text


# -- Chunk / shortcut lookups ------------------------------------------

def _chunk_exists(chunk_id: str | None) -> bool:
    if not chunk_id:
        return False
    db = get_db()
    return db.execute(
        "SELECT 1 FROM chunk_meta WHERE chunk_id = ?", (chunk_id,)
    ).fetchone() is not None


def get_chunk(chunk_id: str) -> dict | None:
    db = get_db()
    row = db.execute(
        "SELECT chunk_id, doc_path, doc_title, heading, heading_anchor, "
        "body, tags, display_path FROM chunks WHERE chunk_id = ?",
        (chunk_id,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    meta = db.execute(
        "SELECT word_count, line_start, line_end, indexed_at "
        "FROM chunk_meta WHERE chunk_id = ?", (chunk_id,)
    ).fetchone()
    if meta:
        d.update(dict(meta))
    d["source_abs"] = str(VAULT_PATH / d["doc_path"])
    d["tag_list"] = d["tags"].split() if d["tags"] else []
    return d


def get_doc_chunks(doc_path: str) -> list[dict]:
    db = get_db()
    rows = db.execute(
        "SELECT c.chunk_id, c.doc_path, c.doc_title, c.heading, "
        "c.heading_anchor, c.body, c.tags, c.display_path "
        "FROM chunks c JOIN chunk_meta m ON m.chunk_id = c.chunk_id "
        "WHERE c.doc_path = ? ORDER BY m.line_start",
        (doc_path,),
    ).fetchall()
    return [dict(r) for r in rows]


def basename_index() -> dict[str, list[str]]:
    """Map `Basename` (no .md) -> [doc_path, ...] for wikilink
    resolution. Obsidian links are by basename; the vault has a few
    colliding names, so the value is a list (first wins, deterministic
    by sorted path)."""
    db = get_db()
    idx: dict[str, list[str]] = {}
    for r in db.execute("SELECT DISTINCT doc_path FROM chunks ORDER BY doc_path"):
        dp = r["doc_path"]
        stem = Path(dp).stem
        idx.setdefault(stem, []).append(dp)
    return idx


# -- Markdown rendering -------------------------------------------------

WIKILINK_RE = re.compile(r"\[\[([^\]]+)\]\]")
CALLOUT_RE = re.compile(
    r"<blockquote>\s*<p>\[!(?P<type>[A-Za-z]+)\]\s*(?P<title>[^\n<]*)",
)


def _resolve_wikilink(raw: str, cur_doc: str, bidx: dict[str, list[str]]) -> str:
    """`[[Doc#Heading|disp]]` -> a markdown link.

    Resolves a known doc to /doc or /chunk; an unknown target falls
    back to a vault search so the link is never dead."""
    inner = raw.strip()
    disp = None
    if "|" in inner:
        inner, disp = inner.split("|", 1)
        disp = disp.strip()
    target, _, anchor = inner.partition("#")
    target = target.strip()
    anchor = anchor.strip()
    label = disp or (f"{target}#{anchor}" if anchor and target else (target or anchor))

    if not target:                       # [[#Heading]] — same document
        doc_path = cur_doc
    else:
        matches = bidx.get(target)
        if not matches:
            return f"[{label}](/search?q={target.replace(' ', '+')})"
        doc_path = matches[0]

    if anchor:
        cid = f"{doc_path}#{slugify(anchor)}"
        return f"[{label}]({url_for('chunk_view', chunk_id=cid)})"
    return f"[{label}]({url_for('doc_view', doc_path=doc_path)})"


def render_markdown(text: str, cur_doc: str = "") -> str:
    """Vault markdown -> HTML. Wikilinks resolved before rendering;
    Obsidian callouts relabeled after. fenced_code + tables are required
    for cheatsheets to render at all (commands live in fences); nothing
    fancier (no highlighting/toc) per the handoff."""
    bidx = basename_index()
    pre = WIKILINK_RE.sub(
        lambda m: _resolve_wikilink(m.group(1), cur_doc, bidx), text or "")
    html = md.markdown(pre, extensions=["fenced_code", "tables", "sane_lists"])

    def _callout(m: re.Match) -> str:
        t = m.group("type").lower()
        title = m.group("title").strip()
        label = t.upper() + (f" · {title}" if title else "")
        return (f'<blockquote class="callout callout-{t}">'
                f'<p class="callout-label">{label}</p><p>')

    return CALLOUT_RE.sub(_callout, html)


@app.template_filter("md")
def _md_filter(text: str) -> str:
    return render_markdown(text or "")


# -- Routes -------------------------------------------------------------

def _popular_shortcuts(n: int = 20) -> list[dict]:
    db = get_db()
    rows = db.execute(
        "SELECT slug, title, tags, answer_type FROM shortcuts "
        "ORDER BY priority DESC, slug LIMIT ?", (n,)
    ).fetchall()
    return [dict(r) for r in rows]


def _result_n() -> int:
    try:
        n = int(request.args.get("n", DEFAULT_N))
    except ValueError:
        n = DEFAULT_N
    return max(1, min(n, MAX_N))


def _do_search(q: str, n: int) -> dict:
    shortcuts = search_shortcuts(q) if q else []
    remaining = max(0, n - len(shortcuts))
    chunks = search_chunks(q, remaining) if q and remaining else []
    return {"q": q, "shortcuts": shortcuts, "chunks": chunks, "n": n}


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    if q:
        return search()
    return render_template(
        "search.html", q="", shortcuts=[], chunks=[],
        popular=_popular_shortcuts(), n=DEFAULT_N)


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    n = _result_n()
    data = _do_search(q, n)
    if request.accept_mimetypes.best == "application/json" or \
       request.args.get("format") == "json":
        return jsonify(data)
    return render_template(
        "search.html", popular=(_popular_shortcuts() if not q else []), **data)


@app.route("/chunk/<path:chunk_id>")
def chunk_view(chunk_id: str):
    c = get_chunk(chunk_id)
    if c is None:
        abort(404)
    c["wikilinks"] = _doc_wikilinks(c["doc_path"], c["chunk_id"])
    body_html = render_markdown(c["body"], cur_doc=c["doc_path"])
    tmpl = "_chunk.html" if request.args.get("partial") else "chunk.html"
    return render_template(tmpl, c=c, body_html=body_html,
                           title=c["display_path"])


def _doc_wikilinks(doc_path: str, chunk_id: str) -> list[dict]:
    """Resolve this chunk's [[links]] to clickable nav (Related footer)."""
    db = get_db()
    row = db.execute(
        "SELECT wikilinks FROM chunks WHERE chunk_id = ?", (chunk_id,)
    ).fetchone()
    if not row or not row["wikilinks"]:
        return []
    bidx = basename_index()
    out: list[dict] = []
    for target in row["wikilinks"].split():
        matches = bidx.get(target)
        if matches:
            out.append({"label": target,
                        "url": url_for("doc_view", doc_path=matches[0])})
        else:
            out.append({"label": target,
                        "url": f"/search?q={target.replace(' ', '+')}"})
    return out


@app.route("/shortcut/<slug>")
def shortcut_view(slug: str):
    db = get_db()
    row = db.execute("SELECT * FROM shortcuts WHERE slug = ?", (slug,)).fetchone()
    if row is None:
        abort(404)
    s = dict(row)
    try:
        s["triggers"] = json.loads(s["triggers"])
    except (json.JSONDecodeError, TypeError):
        s["triggers"] = []
    partial = bool(request.args.get("partial"))

    if s["answer_type"] == "chunk_ref":
        if not _chunk_exists(s["target_chunk_id"]):
            abort(410, description=(
                f"Shortcut '{slug}' points at missing chunk "
                f"'{s['target_chunk_id']}'. See /shortcuts."))
        if partial:
            c = get_chunk(s["target_chunk_id"])
            c["wikilinks"] = _doc_wikilinks(c["doc_path"], c["chunk_id"])
            return render_template(
                "_chunk.html", c=c,
                body_html=render_markdown(c["body"], cur_doc=c["doc_path"]))
        return redirect(url_for("chunk_view", chunk_id=s["target_chunk_id"]))

    answer_html = render_markdown(s["inline_answer"] or "")
    followup = None
    if s["inline_followup"]:
        fu = s["inline_followup"]
        followup = {
            "chunk_id": fu,
            "exists": _chunk_exists(fu),
            "url": url_for("chunk_view", chunk_id=fu),
        }
    tmpl = "_inline.html" if partial else "chunk.html"
    return render_template(tmpl, inline_shortcut=s,
                           answer_html=answer_html, followup=followup,
                           title=s["title"])


@app.route("/doc/<path:doc_path>")
def doc_view(doc_path: str):
    chunks = get_doc_chunks(doc_path)
    if not chunks:
        abort(404)
    rendered = [{
        "heading": c["heading"],
        "anchor": c["heading_anchor"],
        "chunk_id": c["chunk_id"],
        "html": render_markdown(c["body"], cur_doc=doc_path),
    } for c in chunks]
    return render_template(
        "doc.html", doc_path=doc_path, doc_title=chunks[0]["doc_title"],
        chunks=rendered, source_abs=str(VAULT_PATH / doc_path),
        title=Path(doc_path).name)


@app.route("/shortcuts")
def shortcuts_index():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM shortcuts ORDER BY priority DESC, slug").fetchall()
    by_tag: dict[str, list[dict]] = {}
    broken = 0
    for r in rows:
        s = dict(r)
        try:
            s["triggers"] = json.loads(s["triggers"])
        except (json.JSONDecodeError, TypeError):
            s["triggers"] = []
        s["is_broken"] = (s["answer_type"] == "chunk_ref"
                          and not _chunk_exists(s["target_chunk_id"]))
        if s["is_broken"]:
            broken += 1
        primary = (s["tags"].split()[0] if s["tags"] else "untagged")
        by_tag.setdefault(primary, []).append(s)
    return render_template(
        "shortcuts.html",
        groups=sorted(by_tag.items()),
        total=len(rows), broken=broken, title="Shortcuts")


@app.route("/api/healthz")
def healthz():
    if not DB_PATH.exists():
        return jsonify({"status": "no-index"}), 503
    db = get_db()
    chunks = db.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"]
    docs = db.execute(
        "SELECT COUNT(DISTINCT doc_path) AS n FROM chunks").fetchone()["n"]
    scs = db.execute("SELECT COUNT(*) AS n FROM shortcuts").fetchone()["n"]
    broken = 0
    for r in db.execute(
            "SELECT target_chunk_id FROM shortcuts "
            "WHERE answer_type = 'chunk_ref'"):
        if not _chunk_exists(r["target_chunk_id"]):
            broken += 1
    last = db.execute(
        "SELECT MAX(indexed_at) AS t FROM chunk_meta").fetchone()["t"]
    return jsonify({
        "status": "ok",
        "chunks": chunks,
        "docs": docs,
        "shortcuts": scs,
        "broken_shortcuts": broken,
        "indexed_at": last,
        "vault_path": str(VAULT_PATH),
        "exclude_globs": EXCLUDE_GLOBS,
    })


@app.route("/api/rebuild", methods=["POST"])
def api_rebuild():
    try:
        stats = build_index(DB_PATH, VAULT_PATH, EXCLUDE_GLOBS)
        sc = load_shortcuts(DB_PATH, SHORTCUTS_DIR)
    except (FileNotFoundError, RuntimeError) as e:
        return jsonify({"status": "error", "error": str(e)}), 500
    stats.update(sc)
    stats["status"] = "ok"
    stats["rebuilt_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return jsonify(stats)


@app.errorhandler(404)
def _404(e):
    return render_template("error.html", code=404,
                           message="Not found", title="404"), 404


@app.errorhandler(410)
def _410(e):
    return render_template("error.html", code=410,
                           message=getattr(e, "description", "Gone"),
                           title="410"), 410


@app.errorhandler(503)
def _503(e):
    return render_template("error.html", code=503,
                           message=getattr(e, "description", "Unavailable"),
                           title="503"), 503


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5051, debug=False)
