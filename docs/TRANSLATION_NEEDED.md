# Translation needed — Mongolian

A worklist, not a translation. **Nothing here has been machine-translated**, and
nothing should be: the Mongolian in this repo is written, and a transliterated
stand-in would be worse than an honest gap.

Generated 2026-09-30 by classifying every tracked `.md` as entirely English,
bilingual (carrying a `Монгол хэл дээр` half), or mixed, plus the CLI message
catalogue's own `awaitingMN` list.

**Priority is about who reads it**, not length. This repo's users are platform
and security engineers running a CI gate, so English is less of a barrier here
than in Tatar-Shield — but the CLI was the exception: it says it speaks Mongolian
with `--lang mn`, and where it silently did not, it was breaking its own promise.
That is closed; what is left below is contributor-facing.

---

## Closed 2026-09-30 — the CLI now speaks Mongolian everywhere it claims to

`internal/cli/messages.go` carries an `awaitingMN` list: catalogue IDs with
English text and no Mongolian yet. It held **21 IDs**; it is now **empty**. Every
entry in the catalogue has both an `en` and an `mn` string.

| IDs, all written | What the user sees |
|---|---|
| `update.check.absent` `update.check.changes` `update.check.header` `update.check.uptodate` `update.col.pinned` `update.installed` `update.installed.header` `update.dryrun.header` `update.plan.unpinned` `update.cosign.stub` | everything `tatar-kuber update --check` and `--dry-run` print |
| `flag.update.check` `flag.update.dryrun` `flag.update.home` `flag.update.scanner` | the four `update` flag descriptions in `--help` |
| `err.update.scanner.unknown` | the error for an unknown scanner name |
| `verify.controls` `verify.count` `verify.findings` `verify.min` `verify.missing.header` `verify.total` | the `verify-lab` diagnostic table — **these were English-only before the `update` work too**, not introduced by it |

The empty list stays in the source: `TestCatalogHasEveryLanguage` fails both for
an entry with no `mn` string that is *not* on the list, and for one still on the
list that *has* gained an `mn` string. So the gap for the next message written in
one language only is counted in code, and cannot rot silently.

The terms that stay English inside the Mongolian — `SHA256`, `cosign`, `scanner`,
`exit code`, `tools.lock.yaml`, `dry run` — are the ones the rest of the repo
already leaves English. Column headings were kept inside their `%-10s` field so
`update --check` still lines up: `ПИННЭСЭН` next to `doctor`'s `СУУСАН`.

## Low — contributor-facing

| Section | File | Words | Note |
|---|---|---:|---|
| *(whole file)* | `CODE_OF_CONDUCT.md` | 313 | **Do not hand-translate.** Contributor Covenant v2.1 has an official Mongolian translation — use it rather than writing a second, divergent wording. |
| *(whole file)* | `docs/releases/README.md` | 152 | Index of the release notes. |
| *(whole file)* | `.github/ISSUE_TEMPLATE/*.md`, `PULL_REQUEST_TEMPLATE.md` | 221 | Contributor-facing. |
| *(whole file)* | `BLOCKED.md` | 472 | A working note about what `update` is waiting on; it will be deleted once the pins are filled in. |
| *(whole package)* | `internal/update/*.go` comments | — | The new package's comments are English, unlike the Mongolian comments elsewhere in the repo. Worth a pass for consistency, but it is code commentary, not user-facing text. |

---

## Deliberately *not* a gap

- **`README.md`** carries a full Mongolian half, enforced structurally by
  `internal/canonical/readme_test.go` in CI. The `update` paragraph (checksum
  refusal, `--dry-run`/`--check`, cosign not implemented) now has its Mongolian
  counterpart; so does CONTRIBUTING.md's `.docx`/`.md` section, written as a
  summary because that half is a summary rather than a mirror.
- **The six engineering specs** (`docs/0*.md`) are Mongolian-first already, and
  are generated from the `.docx` — never edit the `.md` to change wording, see
  CONTRIBUTING.md.
- **`ROADMAP.md`, `docs/MITRE_ATTACK.md`, `docs/coverage.md`, the release
  notes** are already Mongolian or mixed.

## If you translate one thing

`docs/releases/README.md` — 152 words, and it is the index a Mongolian reader
lands on when following a release link. Everything user-facing is written; what
is left is contributor plumbing.
