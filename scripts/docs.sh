#!/usr/bin/env bash
set -euo pipefail
#
# docs/*.docx -> docs/*.md
#
# The six engineering documents exist as a pair: the Word file people write in
# and the Markdown file GitHub can render. EITHER may be edited, but only one
# direction can be generated (scripts/docx-to-md.py converts .docx -> .md and
# there is no converter the other way), so the pair has to be brought back into
# sync before a merge. See CONTRIBUTING.md.
#
#   bash scripts/docs.sh           regenerate every docs/*.md from its .docx
#   bash scripts/docs.sh --check   fail if a committed .md differs from what
#                                  the .docx produces (this is what CI runs)
#
# --check compares CONTENT, never modification times. git does not store
# timestamps, so after a fresh clone every file carries the checkout time and
# an mtime comparison would pass or fail at random. Content also catches the
# case that actually matters: a .md someone edited by hand, whose edit the next
# regeneration would silently throw away.

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
"")
  python3 "$root/scripts/docx-to-md.py"
  ;;
--check)
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  # Convert copies: the converter writes the .md beside its .docx, and a check
  # must not touch the working tree it is checking.
  cp "$root"/docs/*.docx "$tmp/"
  python3 "$root/scripts/docx-to-md.py" "$tmp"/*.docx >/dev/null

  status=0
  count=0
  for docx in "$root"/docs/*.docx; do
    name="$(basename "$docx" .docx)"
    count=$((count + 1))
    if ! diff -u \
      --label "docs/$name.md (committed)" \
      --label "docs/$name.md (regenerated from $name.docx)" \
      "$root/docs/$name.md" "$tmp/$name.md"; then
      status=1
    fi
  done

  # A .md whose .docx was deleted or renamed is invisible to the loop above --
  # it compares generated against committed, and an orphan has nothing to
  # generate from. Without this it would sit in docs/ for ever, looking like a
  # spec, with no source and nothing keeping it true.
  #
  # Only files that CLAIM to be generated are candidates: docs/ also holds
  # hand-written markdown (coverage.md, dedup-example.md, MITRE_ATTACK.md) that
  # never had a .docx and must not be reported as orphaned.
  for md in "$root"/docs/*.md; do
    grep -q "by scripts/docx-to-md.py" "$md" || continue
    name="$(basename "$md" .md)"
    if [ ! -f "$root/docs/$name.docx" ]; then
      echo "docs/$name.md has no docs/$name.docx — it is generated from nothing." >&2
      echo "  Either restore the .docx or delete the .md." >&2
      status=1
    fi
  done

  if [ "$status" -ne 0 ]; then
    echo
    echo "docs/*.md is out of sync with docs/*.docx."
    echo "  If the .docx is the edit:  make docs   (regenerates the .md)"
    echo "  If the .md is the edit:    re-apply it in the .docx, then: make docs"
    echo "                             (the converter only runs .docx -> .md,"
    echo "                              so a .md-only edit cannot survive)"
    exit 1
  fi
  echo "docs/*.md matches docs/*.docx ($count documents)"
  ;;
*)
  echo "usage: bash scripts/docs.sh [--check]" >&2
  exit 2
  ;;
esac
