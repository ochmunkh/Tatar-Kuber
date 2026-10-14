# Contributing to TATAR-Kuber

Thanks for your interest — contributions are very welcome! 🎉
TATAR-Kuber is early-stage and there is lots of high-impact work available.

Монголоор: доод хэсгийг үзнэ үү.

## Ways to contribute

- **Add a new scanner adapter** (e.g. kubeaudit, kube-bench, Kubescape frameworks) — the
  cleanest entry point, see below.
- **Improve the canonical control registry** (`schema/canonical-controls.yaml`) — mappings,
  new controls, better compliance references.
- **Bug fixes / tests** — especially CLI test coverage and concurrency (parallel adapters).
- **Docs & translations** — English/Mongolian, or a new language for the reports.

## Dev setup

```bash
git clone https://github.com/ochmunkh/Tatar-Kuber && cd Tatar-Kuber
go build ./...
go test ./...          # 19 packages, must stay green
python3 scripts/validate_registry.py   # canonical registry sanity
```

Requires **Go 1.22+**. The Go module path is lowercase (`github.com/ochmunkh/tatar-kuber`) —
please keep it that way.

## Workflow

1. **Fork** the repo and create a branch: `feat/<short-name>` or `fix/<short-name>`.
2. Make focused changes. Keep PRs small and single-purpose.
3. Ensure `go vet ./...`, `gofmt`, and `go test ./...` all pass.
4. Open a **Pull Request** describing *what* and *why*. Link any related issue.

A maintainer will review. Please be patient and kind — see the Code of Conduct.

## The engineering documents (`.docx` **and** `.md`)

`docs/` holds six engineering specifications, and each one is committed twice: as the Word
file it is written in (`05_CLI-Specification.docx`) and as the Markdown rendered from it
(`05_CLI-Specification.md`). Both are read — GitHub will not render a `.docx` in the
browser, and Markdown is what search, review and `git diff` can actually work with.

**Either file may be edited, but the other must be regenerated before merge.** One command
does it:

```bash
make docs                  # regenerate all six docs/*.md from their .docx
bash scripts/docs.sh       # the same thing, without make
```

CI runs `bash scripts/docs.sh --check`, which regenerates the Markdown into a temporary
directory and fails when it differs from what is committed. It compares **content**, never
modification times — git does not store timestamps, so after a fresh clone every file
carries the checkout time and an mtime comparison would pass or fail at random.

**The asymmetry is real, so plan around it.** `scripts/docx-to-md.py` converts
`.docx` → `.md`, and there is no converter in the other direction. An edit made in the
Markdown therefore cannot be propagated back into the Word file: the next `make docs`
overwrites it, and until then the CI check reports the pair as out of sync. Concretely:

- **Editing the `.docx` is the direction that survives.** Edit in Word, run `make docs`,
  commit both files.
- **Editing the `.md` is fine for drafting or for showing a reviewer what you mean**, but
  the same change has to be re-applied in the `.docx` before merge, or it is lost. This is
  not a round trip and the tooling will not make it one.

Each generated `.md` says the same thing in its own header, so a file opened out of context
still tells the reader where it came from.

## Adding a scanner adapter (step by step)

This is the recommended first contribution. See
[`docs/03_Scanner-Adapter-Interface.md`](docs/03_Scanner-Adapter-Interface.md), the rendered
copy of `03_Scanner-Adapter-Interface.docx`.

1. Create `internal/scanner/<name>/<name>.go` implementing `scanner.ScannerAdapter`
   (`Name`, `Available`, `Version`, `Supports`, `Scan`, `Normalize`).
2. In `Normalize`, convert the scanner's raw output into `[]finding.Finding` via the shared
   `normalizer.Build(...)` helper — it handles canonical mapping, severity, confidence and ID.
3. Add the scanner's rule-ID → canonical mappings in `schema/canonical-controls.yaml`
   (never reuse or renumber a `TATAR-*` id; only `status: deprecated`).
4. Add a fixture under `testdata/<name>/` and a `Normalize` test asserting the expected
   canonical controls.
5. Register the adapter in `internal/cli/pipeline.go` and `internal/orchestrator`.
6. Run `go test ./...` and `python3 scripts/validate_registry.py`.

## Canonical controls & mappings

- `TATAR-*` control IDs are an **immutable contract** (SARIF, history, diff depend on them).
- Scanner rule IDs are **provisional** — validate them against real scanner output. The
  [tatar-kuber-lab](https://github.com/ochmunkh/Tatar-Kuber-Lab) repo is the regression harness:

```bash
tatar-kuber verify-lab --input scan-result.json --expected expected-findings.json
```

### The golden corpus

`testdata/golden/demo.json` freezes the full pipeline output for the real scanner output in
`examples/demo/`. It runs on every PR in about a tenth of a second — no cluster, no network.

Its job is the failure this project keeps hitting: a mapping that breaks **silently**. In v1.0.0
Trivy contributed nothing for an entire release while the totals looked healthy. The golden test
catches exactly that, because it compares per-scanner contribution, not just the total.

If you change a mapping, a severity, dedup, rollup or scoring, this test will fail. **Read the
diff it prints before regenerating** — it reports which findings appeared, disappeared or changed
severity, and how each scanner's contribution moved, rather than dumping the JSON. Every line is
either an improvement you meant or a regression you didn't.

```bash
go test ./internal/cli/ -run TestGolden            # check
go test ./internal/cli/ -run TestGolden -update    # accept, once you have read the diff
```

Regenerating without reading the diff makes the guard worthless.

## Cutting a release

The version string lives in **six** places, and only one of them is injected by the
release tooling. `TestVersionsAgree` catches the two that matter; the rest are manual.

1. `internal/orchestrator/orchestrator.go` — `const Version` (**not** reachable by
   ldflags; this is the one that ends up in every `scan-result.json` and SARIF file)
2. `internal/cli/root.go` — `var Version` (goreleaser overwrites it at build time)
3. `README.md` — release badge, and the `./scripts/build.sh <version>` example in
   both language sections
4. `docs/img/architecture.gen.py` — subtitle, then re-render both PNGs
5. `examples/report/` — regenerate all four files (they embed the version)
6. `ROADMAP.md` / `README.md` — move the new version out of the previous
   "shipped" section into its own

Then:

```bash
go test ./...                      # 19 packages, including the golden corpus
git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z
```

Write the release notes into `docs/releases/vX.Y.Z.md` **before tagging** — that file,
not the GitHub release page, is the source of truth. GoReleaser runs on the tag and
**replaces the release body with an auto-changelog**, so the notes go on afterwards:

```bash
gh release edit vX.Y.Z --notes-file docs/releases/vX.Y.Z.md --title "..." --latest
git push origin :refs/tags/v1 && git tag -f v1 vX.Y.Z && git push origin v1
```

`.github/workflows/release-notes.yml` compares every file in `docs/releases/` against
what is published, daily and on every change to that folder. If a release body is ever
overwritten again, it turns red the next morning and prints the one command that
restores it. A file for a version that has not been released yet is skipped, not failed.

Moving `v1` must come **last**, after the notes are in place. The release workflow
triggers on `v[0-9]+.[0-9]+.[0-9]+*`, which `v1` does not match — it used to match
`v*`, and moving `v1` then re-ran GoReleaser against the *same* release (`v1` and
`vX.Y.Z` point at one commit, so GoReleaser resolved the same version) and wiped the
hand-written notes seconds after they were applied.

One subtlety worth knowing: for a tag push, GitHub reads the workflow file **from the
commit the tag points at**, not from `master`. So a `v1` still pointing at a release
made before this fix will trigger the old `v*` workflow no matter what `master` says.
`v1` has since been moved onto a commit that carries the narrowed filter, so moving it
again reads the new rule and no longer fires. If you ever point `v1` at a release made
before this fix, the old behaviour comes back — cancel the run before it reaches the
release step, then re-apply the notes.

Finally — **download the published binary and run it**. v1.0.0 shipped working code
in a broken artifact; the only way to know is to fetch the release and exercise
`scan`, `report --lang`, `gate`, `diff` and `verify-lab` against it.

## Code style

- `gofmt` + `go vet` clean; small, well-named functions; comments where non-obvious.
- Deterministic output (stable IDs, sorted results) — don't break `result_hash` reproducibility.

## Reporting bugs / requesting features

Open an issue using the templates in `.github/ISSUE_TEMPLATE/`.

---

## Монгол хэл дээр

Хувь нэмэр оруулах хүсэлд баярлалаа! 🎉 Төсөл эрт шатанд байгаа тул хийх ажил их байна.

**Хувь нэмэр оруулах гол чиглэлүүд:**
- Шинэ **scanner adapter** нэмэх (kubeaudit г.м) — хамгийн цэвэр эхлэл.
- **canonical-controls.yaml**-ийг сайжруулах (mapping, шинэ control, compliance).
- **Bug fix / тест** — ялангуяа CLI тест, concurrency (adapter-уудыг зэрэгцүүлэх).
- **Баримт / орчуулга** — англи/монгол, эсвэл тайлангийн шинэ хэл.

**Эхлэх:**
```bash
git clone https://github.com/ochmunkh/Tatar-Kuber && cd Tatar-Kuber
go build ./...   &&   go test ./...
```
Go 1.22+ шаардлагатай. Module path жижиг үсэгтэй (`github.com/ochmunkh/tatar-kuber`) хэвээр.

**Ажлын урсгал:** fork → `feat/...` салбар → фокустай өөрчлөлт → `go test ./...` ногоон →
Pull Request (юу, яагаад хийснийг тайлбарла). Maintainer хянана.

**Инженерийн баримтууд (`.docx` ба `.md`):** `docs/` доторх зургаан тодорхойлолт тус бүр
ХОЁР хувиар commit хийгддэг — бичигддэг Word файл (`05_CLI-Specification.docx`) ба түүнээс
рендерлэсэн Markdown (`05_CLI-Specification.md`). Аль нэгийг нь засаж болох ч merge хийхээс
ӨМНӨ нөгөөг нь дахин үүсгэнэ: `make docs` (эсвэл `bash scripts/docs.sh`). CI нь
`bash scripts/docs.sh --check`-ээр агуулгыг нь тулгаж, зөрвөл унана — цагийн тэмдгийг биш,
АГУУЛГЫГ (git timestamp хадгалдаггүй тул шинэ clone дээр mtime-ийн харьцуулалт санамсаргүй
үр дүн өгнө).

Хөрвүүлэлт НЭГ чиглэлтэй: `scripts/docx-to-md.py` нь `.docx` → `.md` хийдэг, буцах
хөрвүүлэгч алга. Тиймээс **үлддэг чиглэл нь `.docx`** — Word дээр засаад `make docs`
ажиллуулж хоёуланг нь commit хийнэ. `.md`-г ноорог болгох, хянагчид санаагаа үзүүлэхэд
ашиглаж болно, гэхдээ ижил өөрчлөлтийг merge хийхээс өмнө `.docx` дээр давтахгүй бол
дараагийн `make docs` түүнийг дарж алга болгоно.

Асуудал/санал: `.github/ISSUE_TEMPLATE/` доторх template ашиглана. Code of Conduct-ыг дагана уу.
