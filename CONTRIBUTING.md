# Contributing to TATAR-Kuber

Thanks for your interest — contributions are very welcome! 🎉
TATAR-Kuber is early-stage and there is lots of high-impact work available.

Монголоор: доод хэсгийг үзнэ үү.

## Ways to contribute

The goal right now is **depth, not breadth**: take the four scanners already wired up
(Trivy · Kubescape · Checkov · Popeye), reconcile their output as accurately as possible,
and report from that one reconciled result. Most of the value left in this project is in
the mapping, not in another adapter.

- **Improve the canonical control registry** (`schema/canonical-controls.yaml`) — correct a
  mapping, cover a rule that is currently unmapped, add a missing control. *The best place
  to start.*
- **Improve the report** — what an auditor actually hands to a client.
- **Bug fixes / tests** — especially CLI test coverage and concurrency (parallel adapters).
- **Docs & translations** — English/Mongolian, or a new language for the reports.
- **A fifth scanner adapter** — welcome, with eyes open: see *Adding a scanner adapter* below.

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
2. **One PR, one concern.** A large change is harder to review than it was to write, and a
   reviewer who cannot hold it in their head will not merge it. Anything substantial —
   roughly a few hundred lines, or anything touching how findings are produced — starts as
   an issue, so the design is agreed before the work is done.
3. Ensure `go vet ./...`, `gofmt`, and `go test ./...` all pass.
4. Open a **Pull Request** describing *what* and *why*. Link any related issue.

A maintainer will review. Please be patient and kind — see the Code of Conduct.

### What a change has to show

Three things, because this is the kind of tool that fails silently rather than loudly:

1. **A mapping change cites the scanner's own rule definition.** Link it in the PR. "The
   names look similar" is not evidence — an audit during v1.0.1/v1.0.2 found 15 of 77
   mappings wrong, and every one of them had looked plausible.
2. **Fixtures are real scanner output, with the version recorded.** A hand-written JSON that
   resembles Trivy proves nothing, and a mapping is only true for a range of scanner
   versions — rule IDs get renamed, split and retired upstream.
3. **A change to normalization reports per-scanner contribution, not totals.** The golden
   corpus prints that line (`trivy 5->4`); put it in the PR. Totals hide precisely the
   failure this project exists to catch.

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

A fifth scanner is welcome — but an adapter is a one-off PR and a mapping is a standing
obligation. Upstream renames, splits and retires rule IDs, and someone has to notice. So
say in the PR what the scanner adds that the current four do not: a layer nobody looks at
(`kube-bench` checks nodes and the control plane, where all four of ours look at workloads,
manifests and RBAC), a control in `docs/coverage.md` that nothing checks today, or
independent corroboration of findings we already produce — overlap is not waste here,
agreement between scanners is what `found_by` and `confidence` are built on.

Then say who re-verifies the mapping when that scanner's rules move. Nobody is asked to
promise years; the point is that the cost is named rather than discovered later.

See [`docs/03_Scanner-Adapter-Interface.md`](docs/03_Scanner-Adapter-Interface.md), the
rendered copy of `03_Scanner-Adapter-Interface.docx`.

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

## The published schema

`pkg/schema/tatar-schema-v1.json` is the contract for `scan-result.json`:
adopters commit one as a baseline and `gate --baseline` reads it months later.
Adding an optional property is fine; adding to any `required` list, removing a
property or changing what one means is not. `pkg/schema/VERSIONING.md` says
which is which and what a v2 would have to do; `compat_test.go` freezes every
`required` list so the breaking case cannot happen by accident.

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
- **canonical-controls.yaml** — буруу зураглал засах, зураглагдаагүй rule хамрах,
  дутуу control нэмэх. *Хамгийн сайн эхлэл.*
- **Тайлан сайжруулах** — аудиторын үйлчлүүлэгчдээ өгдөг бодит зүйл.
- **5 дахь scanner adapter** — хүлээн авна, гэхдээ зардлыг нь мэдсэн байх:
  adapter бол нэг удаагийн PR, зураглал бол **байнгын үүрэг**.
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

**Нэг PR — нэг асуудал.** Зураглалын засвар, шинэ гаралтын формат, рефактор гурвыг нэг PR-т
бүү нэгтгэ. Зураглалын өөрчлөлтийг нотлохын тулд яг аль хэсэг нь шалтгаан болсныг харах
шаардлагатай; холилдсон PR-т энэ боломжгүй.

### Өөрчлөлт юу нотлох ёстой вэ

1. **Scanner-ийн rule-ийн эх тодорхойлолтыг иш тат.** `CKV_K8S_27` нь юу шалгадгийг upstream
   дээр нь зааж өг. "Тохирч байгаа шиг байна" гэдэг нь зураглалын үндэслэл биш.
2. **Бодит fixture, хувилбарыг нь бичсэн байх.** Гараар бичсэн JSON биш, тухайн scanner-ийн
   бодит гаралт — аль хувилбараар гаргасныг тэмдэглэ. Rule-ууд хувилбар хооронд хөдөлдөг.
3. **Нийт тоо биш, scanner тус бүрийн хувь нэмрийг мэдээл.** "69 → 74 боллоо" гэдэг юу ч
   нотлохгүй. Аль scanner юу нэмсэн, юу нь давхцаж нэгдсэнийг харуул (§6, §9).

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
