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

## Routes

| Route | Purpose |
|---|---|
| `/` | Search (landing; empty → popular shortcuts) |
| `/search?q=…` | Ranked results (`&n=` up to 50; JSON via `Accept: application/json` or `&format=json`) |
| `/chunk/<chunk_id>` | Full chunk view (`?partial=1` → fragment, used by inline expansion) |
| `/shortcut/<slug>` | `chunk_ref` → redirect to chunk; `inline` → inline-answer page |
| `/doc/<doc_path>` | Full document — all its chunks in order |
| `/shortcuts` | All shortcuts grouped by tag (BROKEN audit) |
| `/api/healthz` | Index stats |
| `/api/rebuild` (POST) | Rebuild index + shortcuts |

## Environment

| Var | Default | Use |
|---|---|---|
| `VQUERY_VAULT_PATH` | `~/scripts/vault` | Vault root to index |
| `VQUERY_EXCLUDE` | `Not FOR engagement/` | Comma/colon-separated exclude globs (dir prefix or fnmatch). Empty string indexes everything. `Not FOR engagement/` is excluded by default — it holds sqlmap / AV-evasion material that is banned or irrelevant on the engagement (AGENTS.md §9); keeping it out of a sub-10s engagement-day tool is deliberate. |
| `VQUERY_HOST` | `127.0.0.1` | Bind address (localhost only by design) |
| `VQUERY_PORT` | `5051` | Port |
| `NO_COLOR` | — | Disables color in `./run.sh` / `build.py` output |

Localhost only. No outbound requests. No browser storage. Stateless
between sessions by design (bookmarks/pins are a deferred phase).
