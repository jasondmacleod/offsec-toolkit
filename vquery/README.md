# vquery — Vault Query Engine

Local, read-only, OffSec-rules-compliant retrieval over the Obsidian vault
(`~/scripts/vault/`). Answer-shaped: returns the relevant ~chunk, not a
whole doc. Companion to **exploitdb** (port 5050):

- exploitdb (5050) — *what command do I run for this exploit*
- **vquery (5051)** — *how do I think about this; what's the syntax I
  keep forgetting; what does my methodology say to do here*

No AI inference at runtime. Every shortcut and chunk is pre-curated and
stored in SQLite. The app is pure FTS5 indexing + retrieval. AI was used
*in prep* to author shortcuts; never *at query time*.

## Launch

```bash
pip install -r requirements.txt     # Flask + markdown
./run.sh start                      # http://127.0.0.1:5051/
./run.sh stop
./run.sh status
./run.sh rebuild                    # re-index vault + reload shortcuts
./run.sh import-shortcuts           # reload data/shortcuts/*.json only
```

The index at `data/vquery.sqlite` is built on first `start` and is
gitignored. Source of truth: the vault markdown + `data/shortcuts/*.json`
(drop-and-rebuild, no migrations — same model as exploitdb). The live
server opens the DB per request, so a `rebuild` is served on the next
query with no restart.

## Keyboard

| Key | Action |
|---|---|
| `/` | Focus the search bar (from anywhere) |
| `↑` `↓` | Move selection through results (`↓` from the search box drops into results) |
| `Enter` | Expand the selected result inline (keeps the search context); again to collapse |
| `Esc` | Collapse an expanded result, else clear the search box |
| `o` | Toggle the source `.md` path + line span (chunk / doc views) |
| `p` | Pin / unpin the current chunk or shortcut |
| `r` | Toggle the *Related in exploitdb* sidebar (chunk view) |

Click a result card to expand it; click its title/links to navigate.
Code blocks get a copy button.

## How content is indexed

- Every `*.md` under the vault is split into **chunks** by H2 heading
  (H3s stay inside their parent H2). Content before the first H2 (and
  files with no H2) is a single file-level chunk. Oversized sections
  (>800 words) split at H3, then `---`, then paragraphs (≤1200 cap);
  the first sub-chunk keeps the bare section slug.
- Frontmatter is stripped; its `tags` are preserved and searchable.
- Code blocks are content and never stripped.
- Ranking: shortcut matches first — ordered by match specificity (exact
  trigger > specific trigger fully in the query > query is a fragment of
  a longer trigger), then `priority` desc — then FTS5 BM25 with heading
  +50%, doc_title +25%, tags +25% over body baseline.

### Chunk identity

```
chunk_id     _CHEATSHEETS/Passwords.md#offline-cracking-hashcat   (canonical; shortcut JSON)
doc_path     _CHEATSHEETS/Passwords.md                            (routing)
display_path Passwords.md → Offline Cracking — Hashcat            (UI)
```

`doc_path` is the **full path relative to the vault root** — the vault
nests files in folders and has colliding basenames, so the bare
basename is not a stable id. See `data/shortcuts/_schema.md` for the
exact slug rule before authoring `chunk_ref` shortcuts.

## Shortcuts

Hand-authored routes from a query phrase to an answer. `inline`
shortcuts carry their own short markdown answer (optionally with an
`inline_followup` chunk for depth); `chunk_ref` shortcuts point at an
indexed vault chunk. Edit `data/shortcuts/*.json`, then
`./run.sh import-shortcuts`. Schema + the chunk_id rule:
`data/shortcuts/_schema.md`. Audit them all at **`/shortcuts`** — a
`chunk_ref` with an unresolvable target shows a red **BROKEN** badge
there (and as `broken_shortcuts` at `/api/healthz`) but never breaks
search.

Phase 1 ships three as format validation: `kerberoast-hashcat-mode`
(inline), `asrep-hashcat-mode` (inline), `windows-seimpersonate-check`
(chunk_ref). The full ~100 are phase 2.

## Phase 2 — gaps, pins, cross-references

These four features front-load curation work into prep (still no AI or
network at runtime — pure SQL + pre-authored data).

**No-result tracking → `/gaps`.** Every user-facing search is logged.
Three gap flavours surface on `/gaps`, grouped by normalized query and
sortable by frequency / recency / A–Z:

- *hard zero* — nothing matched (no chunk, no shortcut). A footer on the
  search page says so and points at `/gaps`.
- *soft zero* — results came back but the user opened nothing and
  re-queried within 15s (silently abandoned).
- *explicit gap* — the user clicked **↓ didn't help** on a result card.

Resolve a gap as `shortcut_authored` / `content_added` / `wont_fix` /
`noise`. Any resolution drops it from the active list; `wont_fix` stays
visible in the history pane, `noise` is hidden everywhere. History is
preserved in `gap_resolutions`.

**Pins.** Press `p` on any chunk or shortcut to pin it. Pinned items
show as a plain list above search on the home page (top 15, "show all"
→ `/pins`). `/pins` supports drag-reorder and an optional per-pin note.
Server-side in SQLite — no browser storage; survives `./run.sh rebuild`.

**exploitdb cross-references.** exploitdb is the single source of truth:
each entry may carry a `related_vquery` array; vquery ingests it into a
cache on `./run.sh rebuild`. A chunk page shows a *Related in exploitdb*
sidebar grouped by relevance; the empty state is explicit ("No curated
cross-references yet for this chunk") — no similarity inference, ever.
`/xref-health` is the curator dashboard: coverage stats + broken
references. See [exploitdb cross-reference schema](#exploitdb-cross-reference-schema).

**Syntax highlighting.** Vendored Prism (`static/prism.js`, ~24 KB, no
CDN) loads *only* on the standalone chunk page — never search/home.
Languages: bash, python, powershell, sql, yaml, json. Untagged or
unknown-language fences render plain; nothing is guessed.

### exploitdb cross-reference schema

Authored on the **exploitdb** side, in each entry's seed JSON:

```json
"related_vquery": [
  {"chunk_id": "_CHEATSHEETS/Passwords.md#offline-cracking-hashcat",
   "relevance": "primary", "note": "Hashcat mode -m 18200"}
]
```

`chunk_id` is a vquery canonical id (see [Chunk identity](#chunk-identity)).
`relevance` ∈ `primary` · `tool` · `prerequisite` · `followup` ·
`gotcha` (drives sidebar grouping/order; unknown values fall back to
`primary`). `note` is optional. Banned exploitdb entries are skipped at
ingest so a banned slug can never become a live cross-reference. A
cross-reference to a non-existent chunk is kept but excluded from the
sidebar and flagged on `/xref-health`. Run `./run.sh rebuild` after
editing exploitdb seed to refresh the cache.

## Routes

| Route | Purpose |
|---|---|
| `/` | Search (landing; empty → popular shortcuts) |
| `/search?q=…` | Ranked results (`&n=` up to 50; JSON via `Accept: application/json` or `&format=json`) |
| `/chunk/<chunk_id>` | Full chunk view (`?partial=1` → fragment, used by inline expansion) |
| `/shortcut/<slug>` | `chunk_ref` → redirect to chunk; `inline` → inline-answer page |
| `/doc/<doc_path>` | Full document — all its chunks in order |
| `/shortcuts` | All shortcuts grouped by tag (BROKEN audit) |
| `/gaps` | No-result tracking + resolution workflow (`?sort=count\|date\|alpha`) |
| `/pins` | All pins; drag-reorder + per-pin notes |
| `/xref-health` | Cross-reference curator dashboard (coverage + broken refs) |
| `/api/healthz` | Index stats |
| `/api/rebuild` (POST) | Rebuild index + shortcuts + xref cache |
| `/api/pin` (POST) | Toggle a pin (`target_type`, `target_id`) |
| `/api/gap` (POST) | Log an explicit "didn't help" (`query_id`, `chunk_id`) |
| `/api/result-open` (POST) | Beacon: result engaged (suppresses soft-zero) |
| `/gaps/resolve` (POST) | Record a gap resolution |

## Environment

| Var | Default | Use |
|---|---|---|
| `VQUERY_VAULT_PATH` | `~/scripts/vault` | Vault root to index |
| `VQUERY_EXCLUDE` | `Not FOR engagement/` | Comma/colon-separated exclude globs (dir prefix or fnmatch). Empty string indexes everything. `Not FOR engagement/` is excluded by default — it holds sqlmap / AV-evasion material that is banned or irrelevant on the engagement (AGENTS.md §9); keeping it out of a sub-10s engagement-day tool is deliberate. |
| `VQUERY_HOST` | `127.0.0.1` | Bind address (localhost only by design) |
| `VQUERY_PORT` | `5051` | Port |
| `VQUERY_EXPLOITDB_SEED` | `../exploitdb/data/seed` | exploitdb seed dir scanned for `related_vquery` at rebuild |
| `VQUERY_EXPLOITDB_URL` | `http://127.0.0.1:5050` | exploitdb base URL for cross-reference click-outs |
| `NO_COLOR` | — | Disables color in `./run.sh` / `build.py` output |

Localhost only. No outbound requests at runtime (the exploitdb seed is a
local sibling file; Prism is vendored). No browser storage — the only
cookie is an opaque session id for soft-zero correlation; all state is
in SQLite. Pins and gap history **persist** across sessions and survive
`./run.sh rebuild` (that drops only the derived index tables, never the
DB file); the xref cache is the one derived table and is rebuilt then.
