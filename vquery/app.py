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
from flask import (Flask, abort, g, jsonify, make_response, redirect,
                   render_template, request, url_for)

import storage
from indexer.chunker import slugify
from indexer.indexer import build_index
from indexer.shortcut_loader import load_shortcuts

HERE = Path(__file__).parent
DB_PATH = HERE / "data" / "vquery.sqlite"
SHORTCUTS_DIR = HERE / "data" / "shortcuts"

# exploitdb is the source of truth for cross-references (handoff: one
# place to author, no out-of-sync mode). We read its seed JSON at
# rebuild; we link out to its running app for the entry pages.
EXPLOITDB_SEED_DIR = Path(os.environ.get(
    "VQUERY_EXPLOITDB_SEED",
    str(HERE.parent / "exploitdb" / "data" / "seed"))).resolve()
EXPLOITDB_BASE_URL = os.environ.get(
    "VQUERY_EXPLOITDB_URL", "http://127.0.0.1:5050").rstrip("/")

SESSION_COOKIE = "vq_sid"

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
        # Idempotent: the phase-2 persistent tables (gaps, pins) survive
        # ./run.sh rebuild because that drops only the derived index
        # tables, never the DB file. Cheap to assert on every open.
        storage.ensure_schema(conn)
        # First run after a rebuild: populate the xref cache lazily so a
        # bare `./run.sh start` still gets cross-references without a
        # separate step. unavailable exploitdb degrades, doesn't crash.
        if storage.get_xref_status(conn) == "never_built":
            storage.rebuild_xref(conn, EXPLOITDB_SEED_DIR)
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def session_id() -> str:
    """Opaque per-browser id for soft-zero correlation. Stored only in a
    cookie; every fact lives in SQLite. Set on the response in
    _attach_session_cookie when freshly minted."""
    if "session_id" not in g:
        sid, is_new = storage.get_or_make_session_id(
            request.cookies.get(SESSION_COOKIE))
        g.session_id = sid
        g.session_is_new = is_new
    return g.session_id


@app.after_request
def _attach_session_cookie(resp):
    if g.get("session_is_new") and g.get("session_id"):
        resp.set_cookie(SESSION_COOKIE, g.session_id, max_age=60 * 60 * 24 * 365,
                        httponly=True, samesite="Lax")
    return resp


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


HOME_PIN_LIMIT = 15  # handoff: max 15 on the home page, "show all" if more


def _resolve_pins(pins: list[dict]) -> list[dict]:
    """Inflate pin rows into renderable items (title, url, liveness)."""
    db = get_db()
    out: list[dict] = []
    for p in pins:
        tt, tid = p["target_type"], p["target_id"]
        item = {"pin_id": p["pin_id"], "target_type": tt, "target_id": tid,
                "note": p.get("note")}
        if tt == "chunk":
            row = db.execute(
                "SELECT display_path, doc_title, heading FROM chunks "
                "WHERE chunk_id = ?", (tid,)).fetchone()
            item["exists"] = row is not None
            item["title"] = (row["display_path"] if row else tid)
            item["url"] = url_for("chunk_view", chunk_id=tid)
        else:  # shortcut
            row = db.execute(
                "SELECT title FROM shortcuts WHERE slug = ?", (tid,)).fetchone()
            item["exists"] = row is not None
            item["title"] = row["title"] if row else tid
            item["url"] = url_for("shortcut_view", slug=tid)
        out.append(item)
    return out


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    if q:
        return search()
    db = get_db()
    pins = _resolve_pins(storage.list_pins(db))
    return render_template(
        "search.html", q="", shortcuts=[], chunks=[],
        popular=_popular_shortcuts(), n=DEFAULT_N,
        pins=pins[:HOME_PIN_LIMIT], pins_total=len(pins),
        gap_counts=storage.gap_counts(db))


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    n = _result_n()
    data = _do_search(q, n)
    if request.accept_mimetypes.best == "application/json" or \
       request.args.get("format") == "json":
        return jsonify(data)

    # Log only genuine user-facing HTML searches (not the JSON API, not
    # htmx-style partials) so the gap signal isn't polluted by machinery.
    query_id = None
    is_hard_zero = False
    if q and not request.args.get("partial"):
        db = get_db()
        result_count = len(data["shortcuts"]) + len(data["chunks"])
        shortcut_matched = bool(data["shortcuts"])
        query_id = storage.log_query(
            db, q, result_count, shortcut_matched, session_id())
        is_hard_zero = (result_count == 0 and not shortcut_matched)

    return render_template(
        "search.html", popular=(_popular_shortcuts() if not q else []),
        query_id=query_id, is_hard_zero=is_hard_zero, **data)


@app.route("/chunk/<path:chunk_id>")
def chunk_view(chunk_id: str):
    c = get_chunk(chunk_id)
    if c is None:
        abort(404)
    c["wikilinks"] = _doc_wikilinks(c["doc_path"], c["chunk_id"])
    body_html = render_markdown(c["body"], cur_doc=c["doc_path"])
    if request.args.get("partial"):
        # Inline expansion inside the result list — no page chrome.
        return render_template("_chunk.html", c=c, body_html=body_html)
    db = get_db()
    return render_template(
        "chunk.html", c=c, body_html=body_html, title=c["display_path"],
        pinned=storage.is_pinned(db, "chunk", c["chunk_id"]),
        xref_groups=storage.xref_for_chunk(db, c["chunk_id"]),
        xref_status=storage.get_xref_status(db),
        exploitdb_base=EXPLOITDB_BASE_URL)


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
    if partial:
        return render_template("_inline.html", inline_shortcut=s,
                               answer_html=answer_html, followup=followup)
    return render_template(
        "chunk.html", inline_shortcut=s, answer_html=answer_html,
        followup=followup, title=s["title"],
        pinned=storage.is_pinned(db, "shortcut", slug))


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


# -- Feature 1: gaps ----------------------------------------------------

@app.route("/gaps")
def gaps():
    db = get_db()
    sort = request.args.get("sort", "count")
    if sort not in ("count", "date", "alpha"):
        sort = "count"
    return render_template(
        "gaps.html", title="Gaps", sort=sort,
        active=storage.active_gaps(db, sort),
        resolved=storage.resolved_gaps(db),
        resolution_types=sorted(storage.RESOLUTION_TYPES))


@app.route("/gaps/resolve", methods=["POST"])
def gaps_resolve():
    db = get_db()
    ok = storage.resolve_gap(
        db,
        request.form.get("normalized_query", "").strip(),
        request.form.get("resolution_type", "").strip(),
        request.form.get("target_slug"),
        request.form.get("notes"),
    )
    if not ok:
        abort(400, description="invalid gap resolution")
    return redirect(url_for("gaps", sort=request.args.get("sort", "count")))


@app.route("/api/result-open", methods=["POST"])
def api_result_open():
    """Beacon: the user engaged with a result (expand / open / copy).
    Keyed by query_id so a later re-query won't be scored a soft-zero."""
    qid = request.form.get("query_id", type=int)
    if qid is not None:
        storage.record_open(get_db(), qid)
    return ("", 204)


@app.route("/api/gap", methods=["POST"])
def api_gap():
    """Explicit 'didn't help' on a result card."""
    qid = request.form.get("query_id", type=int)
    if qid is None:
        return ("", 400)
    storage.record_explicit_gap(
        get_db(), qid, (request.form.get("chunk_id") or "").strip() or None)
    return ("", 204)


# -- Feature 2: pins ----------------------------------------------------

@app.route("/api/pin", methods=["POST"])
def api_pin():
    tt = (request.form.get("target_type") or "").strip()
    tid = (request.form.get("target_id") or "").strip()
    try:
        pinned = storage.toggle_pin(get_db(), tt, tid)
    except ValueError:
        return jsonify({"error": "bad target"}), 400
    return jsonify({"pinned": pinned})


@app.route("/pins")
def pins_page():
    db = get_db()
    pins = _resolve_pins(storage.list_pins(db))
    return render_template("pins.html", title="Pins", pins=pins)


@app.route("/api/pins/reorder", methods=["POST"])
def api_pins_reorder():
    ids = request.form.getlist("pin_id", type=int)
    if ids:
        storage.reorder_pins(get_db(), ids)
    return ("", 204)


@app.route("/api/pins/note", methods=["POST"])
def api_pins_note():
    pid = request.form.get("pin_id", type=int)
    if pid is not None:
        storage.set_pin_note(get_db(), pid, request.form.get("note", ""))
    return redirect(url_for("pins_page"))


# -- Feature 3: cross-reference health ---------------------------------

@app.route("/xref-health")
def xref_health():
    db = get_db()
    total_chunks = db.execute(
        "SELECT COUNT(*) AS n FROM chunk_meta").fetchone()["n"]
    health = storage.xref_health(
        db, total_chunks,
        storage.served_exploitdb_slugs(EXPLOITDB_SEED_DIR))
    return render_template(
        "xref_health.html", title="Cross-reference health", h=health,
        exploitdb_base=EXPLOITDB_BASE_URL,
        seed_dir=str(EXPLOITDB_SEED_DIR))


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
    conn = sqlite3.connect(DB_PATH)
    try:
        storage.ensure_schema(conn)
        stats["xref"] = storage.rebuild_xref(conn, EXPLOITDB_SEED_DIR)
    finally:
        conn.close()
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
