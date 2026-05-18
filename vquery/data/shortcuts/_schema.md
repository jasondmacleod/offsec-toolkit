# Shortcut JSON schema

Shortcuts are the killer feature: hand-authored routes from a query
phrase to a specific answer. They live here as version-controlled JSON,
**not** in the database — the DB is loaded from these files at
`./run.sh import-shortcuts` / `rebuild` time. Edit JSON, reload, done.

Each `*.json` file (except this `_schema.md`) is one of:

- a single shortcut object,
- a bare JSON array of shortcut objects, or
- `{ "shortcuts": [ ... ] }`.

A malformed shortcut is logged to stderr and skipped; the rest of the
file (and other files) still load. Loading never crashes search.

## Fields

| Field | Req | Meaning |
|---|---|---|
| `slug` | ✔ | Stable unique id, kebab-case. Used in `/shortcut/<slug>` URLs. |
| `triggers` | ✔ | JSON array of query phrases. A query matches if it contains a trigger **or** a trigger contains the query (case-insensitive) — so fat-fingered or over-typed queries still hit. Ranking favours an exact trigger, then a specific trigger fully contained in the query, then `priority` — so a broad single-word trigger on a high-priority shortcut won't outrank a more specific shortcut the query names exactly. |
| `title` | ✔ | Short display title. |
| `answer_type` | ✔ | `"inline"` or `"chunk_ref"`. |
| `target_chunk_id` | ✔ if `chunk_ref` | Canonical chunk id: `FULL/RELATIVE/Path.md#heading-slug`. |
| `inline_answer` | ✔ if `inline` | Markdown answer rendered directly. |
| `inline_followup` | — | Optional chunk id for "more depth" on an inline answer. |
| `tags` | — | Space-separated. First tag groups the shortcut on `/shortcuts`. |
| `priority` | — | Higher ranks first among shortcut matches. Default 100; the curated phase-1 set uses 200. |

## chunk_id format (read this before authoring `chunk_ref`)

`chunk_id = <doc_path>#<heading-slug>`

- `doc_path` is the **full path relative to the vault root**, e.g.
  `_CHEATSHEETS/Windows_PrivEsc.md`. (Not the bare basename — the vault
  nests files in folders and has colliding basenames.)
- `heading-slug` is the H2 heading lowercased with every run of
  non-alphanumerics collapsed to a single `-`, trimmed. Example:
  `## 8. SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege → SYSTEM`
  → `8-seimpersonateprivilege-seassignprimarytokenprivilege-system`.
- A file-level chunk (content before the first H2, or a file with no
  H2) has `chunk_id == doc_path` (no `#`).
- If an oversized H2 is split at H3 boundaries, the **first** sub-chunk
  keeps the bare H2 slug — so a `chunk_ref` to the section header stays
  valid even as the section grows. Later sub-chunks are
  `<h2-slug>--<h3-slug>`.

To find the exact id for a heading, open the doc in vquery and read the
breadcrumb link target, or check `/shortcuts` — a `chunk_ref` whose
target does not resolve renders a red **BROKEN** badge there (and at
`/api/healthz` as `broken_shortcuts`). It never breaks search.

## Example

```json
{
  "slug": "kerberoast-hashcat-mode",
  "triggers": ["kerberoast hashcat", "tgs hashcat", "13100"],
  "title": "Kerberoast — hashcat mode",
  "answer_type": "inline",
  "inline_answer": "**hashcat -m 13100** for Kerberoast (TGS-REP).\n\n```\nhashcat -m 13100 kerberoast.txt rockyou.txt -r best64.rule\n```",
  "inline_followup": "_CHEATSHEETS/Passwords.md#offline-cracking-hashcat",
  "tags": "ad kerberos hashcat cracking",
  "priority": 200
}
```
