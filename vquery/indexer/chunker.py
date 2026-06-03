"""Vault markdown -> chunks.

A chunk is a contiguous span of one vault file with a stable identity:

    chunk_id     full-relative-path#heading-slug   (canonical; shortcut JSON)
    doc_path     full relative path                (routing)
    display_path  Basename.md -> Heading            (UI only)

Chunking strategy (per the vquery handoff):
  - Split each file on H2 (`## `). Each H2 section is one chunk; H3s stay
    inside their parent H2.
  - Content before the first H2 (the H1 + intro) is a file-level chunk
    with an empty heading. Files with no H2 become a single file-level
    chunk.
  - A chunk over ~800 words is split at H3 boundaries. The first
    sub-chunk keeps the parent H2 slug so a shortcut that targets the
    section header still resolves even as the section grows. Further
    overflow (>1200 words) splits at `---` then paragraph breaks.
  - Frontmatter is stripped and its `tags` preserved as a field.
  - Code blocks are content; they are never stripped.

No third-party YAML dependency: the only frontmatter we need is `tags`,
and the vault uses a simple, regular block-sequence form. A tolerant
hand parser covers it (see _parse_frontmatter).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# A chunk over this many words is split further (at H3, then `---`, then
# paragraphs). Hard cap stops a pathological section from becoming one
# enormous result.
SOFT_WORD_LIMIT = 800
HARD_WORD_LIMIT = 1200

H1_RE = re.compile(r"^#\s+(.*\S)\s*$")
H2_RE = re.compile(r"^##\s+(.*\S)\s*$")
H3_RE = re.compile(r"^###\s+(.*\S)\s*$")
HR_RE = re.compile(r"^\s*---\s*$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
WIKILINK_RE = re.compile(r"\[\[([^\]]+)\]\]")


@dataclass
class Chunk:
    chunk_id: str
    doc_path: str
    doc_title: str
    heading: str
    heading_anchor: str
    body: str
    tags: str
    wikilinks: str
    display_path: str
    word_count: int
    line_start: int
    line_end: int


def slugify(text: str) -> str:
    """Lowercase, collapse every non-alnum run to a single hyphen, trim.

    Deterministic and stable: this is what shortcut `target_chunk_id`
    values are authored against, so it must not drift.
    """
    s = re.sub(r"[^a-z0-9]+", "-", text.lower())
    return s.strip("-")


def _parse_frontmatter(text: str) -> tuple[str, list[str], int]:
    """Strip a leading `---` YAML block. Return (body, tags, lines_consumed).

    Tolerant of the two shapes the vault actually uses:
        tags: [a, b]
        tags:
          - a
          - b
    Anything else in the block is ignored — only `tags` is needed.
    """
    if not text.startswith("---"):
        return text, [], 0
    lines = text.split("\n")
    if lines[0].strip() != "---":
        return text, [], 0
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            end = i
            break
    if end is None:
        return text, [], 0

    tags: list[str] = []
    i = 1
    while i < end:
        line = lines[i]
        m = re.match(r"^tags\s*:\s*(.*)$", line)
        if m:
            inline = m.group(1).strip()
            if inline and inline not in ("|", ">"):
                inline = inline.strip("[]")
                tags += [t.strip().strip("'\"") for t in inline.split(",") if t.strip()]
            else:
                j = i + 1
                while j < end:
                    item = re.match(r"^\s*-\s+(.*\S)\s*$", lines[j])
                    if not item:
                        break
                    tags.append(item.group(1).strip().strip("'\""))
                    j += 1
                i = j
                continue
        i += 1

    body = "\n".join(lines[end + 1:])
    return body, tags, end + 1


def _word_count(text: str) -> int:
    return len(text.split())


def _extract_wikilinks(text: str) -> list[str]:
    """Distinct `[[Target]]` doc names (drop `#anchor` and `|display`)."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in WIKILINK_RE.findall(text):
        target = raw.split("|", 1)[0].split("#", 1)[0].strip()
        if target and target not in seen:
            seen.add(target)
            out.append(target)
    return out


@dataclass
class _Section:
    heading: str          # "" for the file-level preamble
    lines: list[str] = field(default_factory=list)
    line_start: int = 0   # 1-based, into the post-frontmatter body


def _split_h2(body_lines: list[str]) -> list[_Section]:
    """Split body lines into H2 sections, fence-aware (a `## ` inside a
    fenced code block is not a heading)."""
    sections: list[_Section] = []
    cur = _Section(heading="", line_start=1)
    in_fence = False
    fence_tok = ""
    for idx, line in enumerate(body_lines, start=1):
        fm = FENCE_RE.match(line)
        if fm:
            tok = fm.group(1)
            if not in_fence:
                in_fence, fence_tok = True, tok
            elif tok == fence_tok:
                in_fence = False
        if not in_fence:
            h2 = H2_RE.match(line)
            if h2:
                if cur.lines or cur.heading:
                    sections.append(cur)
                cur = _Section(heading=h2.group(1).strip(), line_start=idx)
                cur.lines.append(line)
                continue
        cur.lines.append(line)
    if cur.lines or cur.heading:
        sections.append(cur)
    # Drop a leading preamble that is only blank lines / nothing.
    if sections and sections[0].heading == "" and not "".join(sections[0].lines).strip():
        sections = sections[1:]
    return sections


def _h3_pieces(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Within an H2 body, break into (h3_heading_or_empty, lines) pieces,
    fence-aware. The first piece (H2 line + intro before any H3) has
    heading ""."""
    pieces: list[tuple[str, list[str]]] = []
    cur_h3 = ""
    cur: list[str] = []
    in_fence = False
    fence_tok = ""
    for line in lines:
        fm = FENCE_RE.match(line)
        if fm:
            tok = fm.group(1)
            if not in_fence:
                in_fence, fence_tok = True, tok
            elif tok == fence_tok:
                in_fence = False
        if not in_fence:
            h3 = H3_RE.match(line)
            if h3:
                pieces.append((cur_h3, cur))
                cur_h3 = h3.group(1).strip()
                cur = [line]
                continue
        cur.append(line)
    pieces.append((cur_h3, cur))
    return pieces


def _para_split(text: str, limit: int) -> list[str]:
    """Last-resort split of an over-long block at `---` then blank lines,
    each piece kept under `limit` words where possible."""
    blocks: list[str] = []
    for part in re.split(r"(?m)^\s*---\s*$", text):
        para = re.split(r"\n\s*\n", part)
        buf: list[str] = []
        for p in para:
            buf.append(p)
            if _word_count("\n\n".join(buf)) >= limit:
                blocks.append("\n\n".join(buf).strip())
                buf = []
        if buf:
            blocks.append("\n\n".join(buf).strip())
    return [b for b in blocks if b]


def chunk_file(abs_path: Path, doc_path: str) -> list[Chunk]:
    """Turn one markdown file into a list of Chunk objects.

    `doc_path` is the canonical full relative path (posix), e.g.
    `_CHEATSHEETS/Passwords.md`.
    """
    raw = abs_path.read_text(encoding="utf-8", errors="replace")
    body, tags, fm_lines = _parse_frontmatter(raw)
    body_lines = body.split("\n")

    doc_title = ""
    for line in body_lines:
        m = H1_RE.match(line)
        if m:
            doc_title = m.group(1).strip()
            break
    if not doc_title:
        doc_title = abs_path.stem
    basename = abs_path.name
    tags_str = " ".join(tags)

    sections = _split_h2(body_lines)
    chunks: list[Chunk] = []
    used_anchors: set[str] = set()

    def _uniq(anchor: str) -> str:
        base = anchor or "doc"
        a = base
        n = 2
        while a in used_anchors:
            a = f"{base}-{n}"
            n += 1
        used_anchors.add(a)
        return a

    def _emit(heading: str, anchor: str, text: str, ln_start: int, ln_end: int) -> None:
        anchor = _uniq(anchor)
        chunk_id = f"{doc_path}#{anchor}" if anchor != "doc" or heading else doc_path
        display = basename if not heading else f"{basename} → {heading}"
        chunks.append(Chunk(
            chunk_id=chunk_id,
            doc_path=doc_path,
            doc_title=doc_title,
            heading=heading,
            heading_anchor=anchor,
            body=text.strip("\n"),
            tags=tags_str,
            wikilinks=" ".join(_extract_wikilinks(text)),
            display_path=display,
            word_count=_word_count(text),
            line_start=ln_start + fm_lines,
            line_end=ln_end + fm_lines,
        ))

    for sec in sections:
        text = "\n".join(sec.lines)
        ln_start = sec.line_start
        ln_end = sec.line_start + len(sec.lines) - 1
        base_anchor = slugify(sec.heading) if sec.heading else ""

        if _word_count(text) <= SOFT_WORD_LIMIT:
            _emit(sec.heading, base_anchor, text, ln_start, ln_end)
            continue

        # Oversized H2: split at H3. First piece keeps the H2 slug so a
        # shortcut targeting the section header stays valid.
        pieces = _h3_pieces(sec.lines)
        offset = ln_start
        first = True
        for h3, plines in pieces:
            ptext = "\n".join(plines)
            if not ptext.strip():
                offset += len(plines)
                continue
            anchor = base_anchor if first else f"{base_anchor}--{slugify(h3)}".strip("-")
            p_start = offset
            p_end = offset + len(plines) - 1
            if _word_count(ptext) <= HARD_WORD_LIMIT:
                _emit(sec.heading, anchor, ptext, p_start, p_end)
            else:
                for k, blk in enumerate(_para_split(ptext, HARD_WORD_LIMIT)):
                    a = anchor if k == 0 else f"{anchor}-p{k + 1}"
                    _emit(sec.heading, a, blk, p_start, p_end)
            offset += len(plines)
            first = False

    return chunks


def discover(vault_root: Path, exclude_globs: list[str]) -> list[tuple[Path, str]]:
    """Return (abs_path, doc_path) for every indexable .md file.

    doc_path is the posix relative path from the vault root. Excludes
    are matched against that relative path.
    """
    out: list[tuple[Path, str]] = []
    for p in sorted(vault_root.rglob("*.md")):
        rel = p.relative_to(vault_root).as_posix()
        if any(_match_glob(rel, g) for g in exclude_globs):
            continue
        out.append((p, rel))
    return out


def _match_glob(rel: str, pattern: str) -> bool:
    """A directory-prefix or fnmatch match. `Not for the engagement/` matches
    anything under that folder; `*.tmp.md` works too."""
    from fnmatch import fnmatch
    pat = pattern.rstrip("/")
    if rel == pat or rel.startswith(pat + "/"):
        return True
    return fnmatch(rel, pattern)
