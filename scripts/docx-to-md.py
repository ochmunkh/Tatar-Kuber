#!/usr/bin/env python3
"""
docs/*.docx -> docs/*.md

The six engineering documents are authored in Word and stay canonical there.
This renders a Markdown copy beside each one so the specs are readable,
greppable and diff-able on GitHub, which will not render .docx at all.

Why not just `pandoc -f docx -t gfm`: pandoc keeps the tables but flattens the
two things that carry the structure in these particular files --

  * headings      some documents use real Heading1/Heading2/Heading3 styles,
                  others mark a section with a bold "4.1 Title" run in a normal
                  paragraph. Both have to become '##'/'###'.
  * code          every code, JSON, YAML and shell block is a normal paragraph
                  whose runs are set in Consolas. pandoc emits those as prose,
                  so a JSON schema arrives as a wall of unfenced text.

Run:  python3 scripts/docx-to-md.py [docs/FILE.docx ...]
      (no arguments = every .docx under docs/)

Regenerate after editing a .docx; the .md is generated, not hand-maintained.
"""

import re
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}


def q(tag):
    return f"{{{W}}}{tag}"


# ---------------------------------------------------------------- inline runs


def run_text(r):
    """Text of a single run, including tabs and explicit breaks."""
    out = []
    for node in r.iter():
        if node.tag == q("t"):
            out.append(node.text or "")
        elif node.tag == q("tab"):
            out.append("\t")
        elif node.tag == q("br"):
            out.append("\n")
    return "".join(out)


def is_mono(r):
    f = r.find("w:rPr/w:rFonts", NS)
    return f is not None and (f.get(q("ascii")) or "").startswith("Consolas")


def has(r, prop):
    el = r.find(f"w:rPr/w:{prop}", NS)
    if el is None:
        return False
    return el.get(q("val"), "true") not in ("false", "0")


# Only what GFM actually reinterprets mid-line. Escaping ".", "-", "(" and ")"
# as well turns ordinary prose into "Enkhbat\\.O — Security Analyst" and makes the
# raw Markdown unreadable for no rendering benefit. Line-start markers ("#", "-",
# "1.") are handled separately, where the line start is actually known.
MD_SPECIAL = re.compile(r"([\\`*\[\]<>|])")
LINE_START = re.compile(r"^(\s*)([#>+]|[-*](?=\s)|\d+[.)](?=\s))")


def escape(text):
    """Escape Markdown metacharacters in prose (never inside code)."""
    return MD_SPECIAL.sub(r"\\\1", text)


def escape_line_start(line):
    """Neutralise a leading character that would start a block element."""
    return LINE_START.sub(lambda m: m.group(1) + "\\" + m.group(2), line, count=1)


def inline(p):
    """A paragraph's runs as inline Markdown, merging adjacent like-styled runs."""
    pieces = []
    for r in p.findall("w:r", NS):
        t = run_text(r)
        if not t:
            continue
        pieces.append((t, is_mono(r), has(r, "b"), has(r, "i")))

    merged = []
    for t, mono, b, i in pieces:
        if merged and merged[-1][1:] == (mono, b, i):
            merged[-1][0] += t
        else:
            merged.append([t, mono, b, i])

    out = []
    for t, mono, b, i in merged:
        if not t.strip():
            out.append(t)
            continue
        lead = len(t) - len(t.lstrip())
        trail = len(t) - len(t.rstrip())
        pre, core, post = t[:lead], t.strip(), t[len(t) - trail :] if trail else ""
        if mono:
            tick = "`"
            while tick in core:
                tick += "`"
            core = f"{tick}{core}{tick}"
        else:
            core = escape(core)
            if b:
                core = f"**{core}**"
            if i:
                core = f"*{core}*"
        out.append(pre + core + post)
    return "".join(out).strip()


def plain(p):
    return "".join(run_text(r) for r in p.findall("w:r", NS))


# ------------------------------------------------------------------ structure


def style_of(p):
    el = p.find("w:pPr/w:pStyle", NS)
    return el.get(q("val")) if el is not None else ""


def all_mono(p):
    runs = [r for r in p.findall("w:r", NS) if run_text(r).strip()]
    return bool(runs) and all(is_mono(r) for r in runs)


def all_bold(p):
    runs = [r for r in p.findall("w:r", NS) if run_text(r).strip()]
    return bool(runs) and all(has(r, "b") for r in runs)


def is_listitem(p):
    return p.find("w:pPr/w:numPr", NS) is not None or style_of(p) == "ListParagraph"


# "1. Title", "4.1 Title", "3.2.1 Title" -- a heading typed as bold body text
NUMBERED = re.compile(r"^(\d+(?:\.\d+)*)\.?\s+(\S.*)$")


def heading_level(p):
    """Markdown heading level for this paragraph, or None.

    These documents number their own sections ("3.", "3.1", "3.2.1"), and that
    numbering is a truer hierarchy than the Word style: some files style a
    subsection as Heading3 while others leave it as bold body text, and one file
    uses no heading style below Heading1 at all. So when a heading carries a
    number, its depth decides the level; the style only decides *whether* the
    paragraph is a heading at all.
    """
    text = plain(p).strip()
    styled = re.fullmatch(r"Heading([1-6])", style_of(p) or "")
    bold_heading = all_bold(p) and not is_listitem(p) and len(text) < 120

    if not styled and not bold_heading:
        return None

    # The "Хувилбарын тэмдэглэл" sections apply Heading1 to what are plainly
    # bullet points -- 85 to 253 characters each, opening with "•". Reproducing
    # that faithfully would emit a 253-character <h2>. A heading is short and
    # does not start with a bullet glyph; anything else is body text whatever
    # style Word carries.
    if text.startswith(("•", "–", "—", "-", "*")) or len(text) > 120:
        return None
    # ...and the same sections open other notes with a bare version marker,
    # "(v1.2) Шинэ флаг --no-rollup: ...", again carrying Heading1.
    if re.match(r"^\(v\d", text):
        return None

    m = NUMBERED.match(text)
    if m:
        # "1." -> '##', "3.1" -> '###', "3.2.1" -> '####'
        return min(1 + len(m.group(1).split(".")), 6)
    if styled:
        # unnumbered styled heading: Heading1 is a section, '#' is the title
        return min(int(styled.group(1)) + 1, 6)
    return None


def guess_lang(lines):
    body = "\n".join(lines).strip()
    if not body:
        return ""
    if body.startswith("{") or body.startswith("["):
        return "json"
    if re.search(r"^\s*(tatar-kuber|kubectl|helm|go |docker|curl|\$ |# )", body, re.M):
        return "bash"
    if re.search(r"^\s*[a-zA-Z_][\w.-]*:\s*($|\S)", body, re.M) and ":" in body:
        return "yaml"
    if re.search(r"\b(func|package|import|type .* struct)\b", body):
        return "go"
    return "text"


# Standalone pipeline lines: "download -> verify -> install"
ARROW = re.compile(r"\s*(?:->|→|⇒|=>)\s*")


def curated(stem, lines):
    """A hand-authored mermaid diagram for this code block, if one exists.

    Some diagrams are branching trees with side annotations -- §4 of the
    repository-structure document is the clearest example. Deriving a flowchart
    from those mechanically drops the annotations, and hand-editing the
    generated .md would be undone by the next run. So the diagram is authored
    once in scripts/diagrams/<doc stem>/<slug of the block's first line>.mmd
    and substituted here, which keeps regeneration safe.
    """
    first = next((l.strip() for l in lines if l.strip()), "")
    if not first:
        return None
    slug = re.sub(r"[^a-z0-9]+", "-", first.lower()).strip("-")[:48]
    path = Path(__file__).resolve().parent / "diagrams" / stem / f"{slug}.mmd"
    if not path.is_file():
        return None
    return ["```mermaid", path.read_text(encoding="utf-8").rstrip(), "```"]


def as_mermaid(lines):
    """A code block that is purely an arrow pipeline becomes a mermaid flowchart.

    A single leading '#' comment is tolerated and becomes the chart title, since
    that is how these documents introduce a pipeline.
    """
    real = [l for l in lines if l.strip()]
    title = ""
    if len(real) == 2 and real[0].lstrip().startswith("#"):
        title = real[0].lstrip("# ").strip().rstrip(":")
        real = real[1:]
    if len(real) != 1:
        return None
    line = real[0].strip().rstrip(".")
    if line.startswith("#"):
        return None
    parts = [p.strip() for p in ARROW.split(line) if p.strip()]
    if len(parts) < 3 or len(parts) > 8:
        return None
    if any(len(p) > 42 or "|" in p for p in parts):
        return None
    out = ["```mermaid", "flowchart LR"]
    if title:
        out.append(f"    %% {title}")
    for i, p in enumerate(parts):
        out.append(f'    n{i}["{p}"]')
    out.append("    " + " --> ".join(f"n{i}" for i in range(len(parts))))
    out.append("```")
    return out


# --------------------------------------------------------------------- tables


def cell_md(tc):
    parts = [inline(p) for p in tc.findall("w:p", NS)]
    parts = [p for p in parts if p]
    return "<br>".join(parts).replace("|", "\\|") or " "


def table_md(tbl):
    rows = []
    for tr in tbl.findall("w:tr", NS):
        rows.append([cell_md(tc) for tc in tr.findall("w:tc", NS)])
    if not rows:
        return []
    width = max(len(r) for r in rows)
    rows = [r + [" "] * (width - len(r)) for r in rows]
    out = ["| " + " | ".join(rows[0]) + " |", "|" + "|".join(["---"] * width) + "|"]
    for r in rows[1:]:
        out.append("| " + " | ".join(r) + " |")
    return out


# ----------------------------------------------------------------- conversion


def convert(path: Path) -> str:
    z = zipfile.ZipFile(path)
    body = ET.fromstring(z.read("word/document.xml")).find("w:body", NS)

    md, code, title_done = [], [], False
    front = []

    def flush_code():
        nonlocal code
        while code and not code[-1].strip():
            code.pop()
        while code and not code[0].strip():
            code.pop(0)
        if not code:
            code = []
            return
        mer = curated(path.stem, code) or as_mermaid(code)
        if mer:
            md.extend([""] + mer)
        else:
            md.extend(["", f"```{guess_lang(code)}"] + code + ["```"])
        code = []

    for el in body:
        if el.tag == q("tbl"):
            flush_code()
            md.append("")
            md.extend(table_md(el))
            continue
        if el.tag != q("p"):
            continue

        raw = plain(el)

        if all_mono(el) or (code and not raw.strip()):
            # blank lines are kept only while a code block is open
            code.append(raw.rstrip())
            continue
        flush_code()

        text = inline(el)
        if not text:
            continue

        lvl = heading_level(el)

        if not title_done:
            # front matter: everything before the first real heading
            if lvl is None:
                front.append(raw.strip())
                continue
            title_done = True

        if lvl is not None:
            md.extend(["", "#" * lvl + " " + re.sub(r"\s+", " ", plain(el).strip())])
        elif is_listitem(el) or raw.strip().startswith("•"):
            # a literal "•" is how the version-note sections mark their bullets
            item = re.sub(r"^\s*(?:\\?•)\s*", "", text).strip()
            md.extend(["", f"- {item}"] if not (md and md[-1].startswith("- ")) else [f"- {item}"])
        else:
            md.extend(["", escape_line_start(text)])

    flush_code()

    head = ["# " + (front[0] if front else path.stem)]
    rest = [f for f in front[1:] if f]
    if rest:
        head.append("")
        head.append("> " + "  \n> ".join(escape(r) for r in rest))
    head += [
        "",
        f"<!-- Generated from {path.name} by scripts/docx-to-md.py -- do not edit by hand. -->",
        f"*Generated from `{path.name}`. The Word document is canonical; regenerate with "
        f"`python3 scripts/docx-to-md.py docs/{path.name}`.*",
    ]

    text = "\n".join(head + md).rstrip() + "\n"
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def main(argv):
    docs = [Path(a) for a in argv[1:]]
    if not docs:
        docs = sorted((Path(__file__).resolve().parent.parent / "docs").glob("*.docx"))
    if not docs:
        print("no .docx found", file=sys.stderr)
        return 1
    for d in docs:
        out = d.with_suffix(".md")
        out.write_text(convert(d), encoding="utf-8")
        print(f"  {d.name} -> {out.name} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
