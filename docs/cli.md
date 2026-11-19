# TATAR-Kuber — command reference

Every command, flag, exit code and the read-only access it needs. The README keeps only the short version.

English · [Монгол](#монгол-хэл-дээр)

---

## CLI

```
tatar-kuber scan        --kubeconfig | --context | -f | --raw-dir  [--out-dir DIR] [--namespace ns1,ns2] [--no-raw] [--no-rollup]
                        # live scan keeps raw scanner output in <out>/raw/ (evidence; re-ingestable via --raw-dir)
tatar-kuber report      --input scan-result.json --format json | sarif | html | audit | pdf  [--out FILE] [--fail-on high]
                        # audit = print-ready bilingual audit report; pdf = the same, converted on this machine
tatar-kuber gate        --input scan-result.json [--policy .tatar-kuber.yaml] [--fail-on high] [--min-score N]
                        # --baseline prev/scan-result.json : fail only on NEW and WORSENED
                        # refuses (exit 2) a scan-result.json that disagrees with itself; --skip-integrity-check
tatar-kuber doctor      # which scanners are installed, versions, supported modes
tatar-kuber diff        --old prev/scan-result.json --new out/scan-result.json
                        # trending: new / fixed / worsened / improved  [--fail-on-new high] [--format json]
tatar-kuber top         --input scan-result.json [--limit 10]
                        # what to fix first: worst workloads, and the controls that hit the most resources
tatar-kuber attest create --out attestations.yaml [--all] [--cluster NAME]
tatar-kuber attest apply  --input scan-result.json --attestations attestations.yaml [--out-dir DIR]
                        # a human's signed answer for controls no scanner checks
tatar-kuber verify-lab  --input scan-result.json --expected expected-findings.json
tatar-kuber update      [--scanner trivy,popeye] [--dry-run] [--check] [--home ~/.tatar-kuber]
tatar-kuber version

every command also accepts   [--lang en|mn]
```

`scan --out-dir` is a **directory**; `report --format` / `diff --format` is a **format**. Both
still accept the older `-o` spelling, so existing pipelines keep working — but `-o` meant two
different things depending on the command, so the long names are what the docs use. Severity
thresholds (`--fail-on`, `--fail-on-new`, `fail_on:`) are case-insensitive.

**Where to start.** `tatar-kuber top` reads a finished scan and prints two tables: the
workloads carrying the most weight (summed by severity, not just counted) and the controls
that hit the most distinct resources. The second table is the one that usually matters — a
single control failing across thirty workloads is one fix, not thirty. `--limit` sets the
rows per table. It changes nothing on disk; it is a reading of `scan-result.json`.

**Closing a declared gap.** `docs/coverage.md` names every control no scanner checks — today
that is one, `TATAR-NET-004`. Naming it is honest, but it is still a gap. `attest` is how it
gets closed: `attest create` writes a template for exactly those controls, a human fills in a
decision, a reason, their name and an **expiry**, and `attest apply` merges it into the result.

Four things make it an audit record rather than a checkbox:

- **An expiry is mandatory.** When it lapses the control counts as unchecked again and `gate`
  says so by name. An attestation with no expiry gets written once and reads as true forever.
- **`non-compliant` fails the gate** at or above the control's severity. If a person has
  confirmed a control is broken, the result has to show it — otherwise attestation is a way to
  write things down and never act on them.
- **It is not a finding.** Attestations live in their own `attestations[]` block, never in
  `findings`, so `found_by` never claims a scanner saw something it did not — and because
  `metadata.result_hash` covers only the findings, a human's answer cannot quietly alter the
  scanners' evidence.
- **Severity comes from the registry**, not from the file. Letting the attestation set its own
  severity would be a silent way around the gate.

**The audit deliverable.** `report --format html` is a dashboard — filters, collapsible
sections, meant for a screen. What an auditor hands a client is a different document, so it is
a different format: `--format audit` renders a paged, self-contained, bilingual report with the
scope, the method, **what did not run**, the score and how it was derived, the manually attested
controls, and the findings grouped by canonical control with their remediation.

`--format pdf` produces the same document as a PDF. TATAR-Kuber does not write PDF itself: it
converts with a headless browser or `wkhtmltopdf` already on the machine. That is a deliberate
trade — a Go PDF library would double the dependency count and bring font embedding for
Cyrillic with it. **If no converter is found the command refuses and says so**, naming what it
looked for and pointing at `--format audit` plus the browser's own Print → Save as PDF. It does
not emit an empty file and call it done.

**Updating the scanners.** `tatar-kuber update` downloads each scanner, checks its SHA256
against the pin in `~/.tatar-kuber/tools.lock.yaml`, and only then installs it. A mismatch
installs nothing at all — not even the scanners that did verify — and a scanner with no
pinned checksum is refused *before* the download is made, so there is no trust-on-first-use
path. `--dry-run` prints exactly what would be fetched (scanner, version, URL, expected
checksum) and writes nothing; `--check` compares the pins with what the lock records as
installed. The cosign step of the specification is **not implemented yet**: signatures are
not verified, the command says so on every run, and `tools.lock.yaml` records
`cosign: unverified` rather than claiming otherwise.

**Output language.** Everything the tool prints is **English by default**. `--lang mn`
switches all of it — usage, flag descriptions, errors, progress and gate verdicts — to
Mongolian, and `TATAR_LANG=mn` sets it for a whole session (the flag wins over the
environment). Every command takes `--lang`, and an unknown value is a usage error
(exit `3`) on every one of them. On `report`, `--lang` re-renders the report itself as
well; without it the report keeps the language chosen at scan time, so existing
pipelines are unaffected.

One known exception: a few **finding descriptions produced by the scanner adapters**
are still Mongolian-only and are written that way into `scan-result.json`, so they
appear untranslated even in an `en` document — Trivy's secret findings ("Илэрсэн
нууц: …") are the case you will actually hit. These are serialised schema fields
rather than console output, so making them bilingual changes the v1 document shape
and is tracked separately.

### Live Mode B — granting read-only access

Live cluster scanning needs credentials, and "trust me, it's read-only" is not an answer a
platform team should accept. The RBAC is therefore a reviewable file in this repo:

```bash
kubectl apply -f deploy/least-privilege-clusterrole.yaml
tatar-kuber scan --kubeconfig ~/.kube/config --namespace prod --out-dir ./out
```

[`deploy/least-privilege-clusterrole.yaml`](../deploy/least-privilege-clusterrole.yaml) is
self-contained — it creates the ClusterRole `tatar-kuber-reader`, the ServiceAccount
`tatar-kuber` in `kube-system`, and the ClusterRoleBinding between them. Nothing else is
needed. Every rule in it grants only `get` / `list` / `watch`: there is no `create`,
`update`, `patch` or `delete` verb anywhere in the file, which is the whole of the
**Read-Only First** promise in a form you can diff.

Secrets are the one place worth stating plainly: **the ClusterRole does not grant access to
`secrets` at all.**

It used to, with a comment promising that only metadata would be read. That promise cannot be
kept: RBAC has no "metadata only" permission for a Secret, and `get` / `list` return the whole
`data:` field. The role asked for a capability it then pledged not to use — which is a pledge,
not a control. It was removed in v1.0.4.

Nothing is lost by removing it. Which secret is mounted where is written in the pod spec
(`volumes.secret`, `envFrom.secretRef`), which this role already reads, and the RBAC analysis
works from `Role` / `RoleBinding` objects rather than from Secrets themselves.

### Exit codes

The `gate` command exists to be wired into a pipeline, so its exit code is a contract. Under
`set -e`, "policy violated" and "the tool could not read its input" must not look the same:

| Code | Meaning | Where it comes from |
|---|---|---|
| `0` | success / gate passed | every command |
| `1` | policy or threshold violation | `gate` FAILED, `diff --fail-on-new`, `report --fail-on`, `verify-lab` FAIL, `doctor` with **no scanner installed** |
| `2` | runtime error — input unreadable or malformed, **or an unrecognised flag** | a missing or corrupt `scan-result.json` or expected-findings file, or a **corrupt** policy file — a *missing* policy file is not an error (`.tatar-kuber.yaml` is optional: the built-in `fail_on: high` default applies, so the gate still runs and can return `1`); also `--no-such-flag`, which Go's flag parser rejects before the command runs |
| `3` | usage error — unknown command, format or language, or a missing required flag | `tatar-kuber frobnicate`, `report --format nope`, `report --lang de`, `diff` without `--old`, `scan` without an input |

An **unrecognised** severity threshold is deliberately *not* a usage error, so it never
appears as `3`. `report --fail-on` and `diff --fail-on-new` warn on stderr and skip the check
(exit `0`); `gate --fail-on` and `fail_on:` warn and fall back to the built-in `high`, which
is the strict direction. A typo therefore never silently *tightens* a gate — but on `report`
and `diff` it silently *disables* one, so treat that warning as actionable in CI.

`tatar-kuber doctor` returns **1** on a machine with no scanners installed. That is a
deliberate readiness signal, not an error — but it means `doctor` under `set -e` will stop a
fresh runner, so guard it (`tatar-kuber doctor || true`) if you only want the table.

---

## Монгол хэл дээр

### CLI командууд

```
tatar-kuber scan        --kubeconfig | --context | -f | --raw-dir  [--out-dir DIR] [--namespace ns1,ns2] [--no-raw] [--no-rollup]
                        # live scan нь scanner-уудын түүхий гаралтыг <out>/raw/-д хадгална (нотолгоо; --raw-dir-ээр дахин боловсруулна)
tatar-kuber report      --input scan-result.json --format json | sarif | html | audit | pdf  [--out FILE] [--fail-on high]
                        # audit = хуудаслалтад бэлэн хоёр хэлт аудитын тайлан; pdf = түүнийг энэ машин дээр хөрвүүлсэн нь
tatar-kuber gate        --input scan-result.json [--policy .tatar-kuber.yaml] [--fail-on high] [--min-score N]
                        # --baseline prev/scan-result.json : зөвхөн шинэ ба дордсон finding дээр fail болно
tatar-kuber doctor      # ямар scanner суусан, хувилбар, дэмжих горим
tatar-kuber diff        --old prev/scan-result.json --new out/scan-result.json
                        # тренд: шинэ / зассан / дордсон / сайжирсан  [--fail-on-new high] [--format json]
tatar-kuber top         --input scan-result.json [--limit 10]
                        # юунаас эхлэх вэ: хамгийн муу workload, хамгийн олон resource-д нөлөөлсөн control
tatar-kuber attest create --out attestations.yaml [--all] [--cluster НЭР]
tatar-kuber attest apply  --input scan-result.json --attestations attestations.yaml [--out-dir DIR]
                        # scanner шалгадаггүй control-д хүний гарын үсэгтэй хариулт
tatar-kuber verify-lab  --input scan-result.json --expected expected-findings.json
tatar-kuber update      [--scanner trivy,popeye] [--dry-run] [--check] [--home ~/.tatar-kuber]
tatar-kuber version

команд бүр мөн хүлээж авна   [--lang en|mn]
```

`scan --out-dir` нь **хавтас**, `report --format` / `diff --format` нь **формат**. Хоёул `-o`
гэсэн хуучин бичиглэлээ хэвээр хүлээж авна (байгаа pipeline эвдрэхгүй) — гэхдээ `-o` нь
командаас хамаарч хоёр өөр зүйл гэсэн утгатай байсан тул баримтад бүтэн нэрийг ашиглана.
Severity босго (`--fail-on`, `--fail-on-new`, `fail_on:`) нь үсгийн том/жижигт үл хамаарна.

**Юунаас эхлэх вэ.** `tatar-kuber top` нь дууссан scan-ийг уншаад хоёр хүснэгт хэвлэнэ:
хамгийн их ачаа үүрсэн workload-ууд (зүгээр тоолсон биш, severity-гээр нь жигнэсэн), ба
хамгийн олон өөр resource-д тусч байгаа control-ууд. Ихэвчлэн **хоёр дахь хүснэгт** нь
чухал — гучин workload дээр унасан нэг control бол гучин засвар биш, НЭГ засвар.
`--limit` нь хүснэгт тус бүрийн мөрийн тоог тогтооно. Диск дээр юу ч өөрчлөхгүй, зөвхөн
`scan-result.json`-ийг уншина.

**Зарлагдсан цоорхойг хаах.** `docs/coverage.md` нь ямар ч scanner шалгадаггүй control бүрийг
нэрээр нь бичдэг — өнөөдөр нэг, `TATAR-NET-004`. Нэрлэсэн нь шударга, гэвч цоорхой хэвээр.
`attest` бол түүнийг хаах зам: `attest create` нь яг тэр control-уудын загвар гаргана, хүн
шийдвэр, үндэслэл, нэрээ, мөн **хугацаа** бичнэ, `attest apply` нь үр дүнд нэгтгэнэ.

Үүнийг галочка биш, аудитын бүртгэл болгож байгаа дөрвөн зүйл:

- **Хугацаа заавал.** Дуусмагц control нь дахин шалгагдаагүйд тооцогдож, `gate` түүнийг
  нэрээр нь хэлнэ. Хугацаагүй баталгаа нэг удаа бичигдээд үүрд үнэн мэт уншигдана.
- **`non-compliant` нь gate-ийг унагаана** — control-ийн severity-ийн түвшинд. Хүн зөрчил
  байгааг баталсан бол үр дүн түүнийг харуулах ёстой; эс бөгөөс баталгаажуулалт бол бичээд
  мартах арга болно.
- **Энэ нь олдвор БИШ.** Attestation нь тусдаа `attestations[]` дотор амьдарна, `findings`-д
  хэзээ ч орохгүй — тиймээс `found_by` нь scanner хараагүй зүйлээ харсан гэж хэлэхгүй, мөн
  `metadata.result_hash` нь зөвхөн олдворыг хамардаг тул хүний хариулт scanner-ийн нотолгоог
  чимээгүй өөрчилж чадахгүй.
- **Severity нь бүртгэлээс** ирнэ, файлаас биш. Attestation-д өөрийн severity тавих боломж
  өгөх нь gate-ийг тойрох чимээгүй зам болно.

**Аудитын deliverable.** `report --format html` бол ДЭЛГЭЦИЙН самбар — шүүлтүүр, задардаг
хэсэгтэй. Аудиторын үйлчлүүлэгчдээ өгдөг зүйл бол өөр баримт, тиймээс өөр формат:
`--format audit` нь хуудаслагдсан, бие даасан, хоёр хэлт тайлан гаргана — хамрах хүрээ, арга
зүй, **юу ажиллаагүй**, оноо ба түүний гарал, гараар баталсан хяналтууд, мөн canonical
хяналтаар бүлэглэсэн олдворууд засах арга хэмжээтэйгээ.

`--format pdf` нь яг тэр баримтыг PDF болгоно. TATAR-Kuber нь PDF-ийг өөрөө бичдэггүй:
машин дээр БАЙГАА headless хөтөч эсвэл `wkhtmltopdf`-ээр хөрвүүлнэ. Энэ бол ухамсартай
сонголт — Go-гийн PDF сан нэмбэл гадаад хамаарал хоёр дахин нэмэгдэж, кирилл үсэгт шрифт
шигтгэх асуудал дагалдана. **Хөрвүүлэгч олдохгүй бол команд ИЛ ТАТГАЛЗАНА**: юу хайснаа
нэрлээд, `--format audit` болон хөтчийн Print → Save as PDF-ийг зааж өгнө. Хоосон файл
гаргаад "болов" гэж хэлэхгүй.

**Scanner-уудыг шинэчлэх.** `tatar-kuber update` нь scanner бүрийг татаж, SHA256-ыг нь
`~/.tatar-kuber/tools.lock.yaml` доторх pin-тэй тулгаж, дараа нь л суулгана. Нэг нь зөрвөл
ЮУ Ч суухгүй — баталгаажсан scanner-ууд нь ч суухгүй. Пиннэсэн checksum-гүй scanner нь
татагдахаас нь ӨМНӨ татгалзагдана, тиймээс trust-on-first-use гэсэн зам огт байхгүй.
`--dry-run` нь юу татагдахыг яг таг (scanner, хувилбар, URL, хүлээгдэх checksum) хэвлээд
юу ч бичихгүй; `--check` нь pin-үүдийг lock-д суусан гэж бичигдсэнтэй тулгана.
Тодорхойлолтын cosign алхам **хараахан хэрэгжээгүй**: гарын үсэг шалгагддаггүй, команд
үүнийгээ ажиллалт бүрт хэлнэ, `tools.lock.yaml` нь өөрөөр мэдүүлэхийн оронд
`cosign: unverified` гэж бичигдэнэ.

**Гаралтын хэл.** Хэрэгслийн хэвлэдэг бүх зүйл default-оор **англи**. `--lang mn` нь
бүгдийг — usage, флагийн тайлбар, алдаа, явцын мөр, gate-ийн шийдвэрийг — монгол руу
сэлгэнэ, `TATAR_LANG=mn` нь бүтэн session-д тавина (флаг нь орчны хувьсагчийг дарна).
`--lang`-ыг команд бүр хүлээж авах бөгөөд танигдаагүй утга нь команд бүрт хэрэглээний
алдаа (exit `3`). `report` дээр `--lang` нь тайланг өөрийг нь ч дахин үүсгэнэ; өгөөгүй
бол тайлан scan-д сонгосон хэлээрээ үлдэх тул байгаа pipeline хөндөгдөхгүй.

Мэдэгдэж байгаа нэг үл хамаарах зүйл: **scanner adapter-ийн үүсгэдэг зарим finding-ийн
тайлбар** нь монгол хэл дээр хатуу бичигдсэн бөгөөд `scan-result.json`-д тэр чигээрээ
ордог тул `en` баримт дотор ч орчуулагдаагүй харагдана — практикт тааралдах нь Trivy-ийн
нууц илрүүлэлт ("Илэрсэн нууц: …"). Эдгээр нь консолын гаралт биш, схемийн цуваа
талбарууд тул хоёр хэлтэй болгох нь v1 баримтын хэлбэрийг өөрчилнө — тусад нь
шийдвэрлэнэ.

### Live Mode B — read-only хандалт олгох

Амьд кластерыг шалгахад эрх шаардагдана, "read-only гэдэгт минь итгэ" гэдэг нь platform
багийн хүлээж авах хариулт биш. Тиймээс RBAC нь энэ repo дотор хянагдах боломжтой файл юм:

```bash
kubectl apply -f deploy/least-privilege-clusterrole.yaml
tatar-kuber scan --kubeconfig ~/.kube/config --namespace prod --out-dir ./out
```

[`deploy/least-privilege-clusterrole.yaml`](../deploy/least-privilege-clusterrole.yaml) нь
дангаараа бүрэн: `tatar-kuber-reader` ClusterRole, `kube-system`-д `tatar-kuber`
ServiceAccount, мөн тэдгээрийг холбох ClusterRoleBinding-ыг үүсгэнэ. Өөр юу ч нэмэх
шаардлагагүй. Дүрэм бүр нь ЗӨВХӨН `get` / `list` / `watch` эрх олгодог: файлын хаана ч
`create`, `update`, `patch`, `delete` verb байхгүй — **Read-Only First** гэсэн зарчим
бүхэлдээ diff хийж шалгах боломжтой хэлбэрт байна.

Secret-ийн талаар ил хэлэх нь зүйтэй: **ClusterRole нь `secrets`-д огт эрх олгодоггүй.**

Өмнө нь олгодог байсан бөгөөд тайлбартаа "зөвхөн metadata уншина" гэж амладаг байв. Тэр
амлалтыг биелүүлэх боломжгүй: RBAC дээр Secret-д "зөвхөн metadata" гэсэн эрх байдаггүй,
`get` / `list` нь `data:` талбарыг бүхэлд нь буцаана. Өөрөөр хэлбэл эрхийг нь авчхаад
"ашиглахгүй" гэж амлаж байсан хэрэг — тэр нь амлалт, хяналт биш. v1.0.4-д хассан.

Хасснаар алдагдах зүйл алга. Аль secret хаана mount хийгдсэн, env руу орсон нь pod-ийн
тодорхойлолтод (`volumes.secret`, `envFrom.secretRef`) бичигдсэн байдаг бөгөөд энэ эрх түүнийг
аль хэдийн уншдаг; RBAC-ийн шинжилгээ нь Secret объект дээр биш, `Role` / `RoleBinding`
дээр тулгуурладаг.

### Exit code

`gate` команд нь pipeline-д холбогдохын тулд байдаг тул түүний exit code бол гэрээ. `set -e`
дор "бодлого зөрчигдсөн" ба "хэрэгсэл оролтоо уншиж чадсангүй" хоёр ижил харагдаж болохгүй:

| Код | Утга | Хаанаас гардаг |
|---|---|---|
| `0` | амжилттай / gate давсан | бүх команд |
| `1` | бодлого эсвэл босго зөрчигдсөн | `gate` FAILED, `diff --fail-on-new`, `report --fail-on`, `verify-lab` FAIL, `doctor` — **ямар ч scanner суугаагүй** |
| `2` | ажиллагааны алдаа — оролт уншигдсангүй/эвдэрсэн, эсвэл **танигдаагүй флаг** | байхгүй/эвдэрсэн `scan-result.json` эсвэл expected-findings файл, мөн **эвдэрсэн** бодлогын файл — бодлогын файл БАЙХГҮЙ бол алдаа БИШ (`.tatar-kuber.yaml` нь сонголт: built-in `fail_on: high` default хэрэглэгдэж gate ажиллаад `1` буцааж ч болно); мөн `--no-such-flag` — үүнийг Go-ийн flag parser команд ажиллахаас өмнө буцаана |
| `3` | хэрэглээний алдаа — команд, формат, хэл танигдсангүй, эсвэл заавал флаг дутуу | `tatar-kuber frobnicate`, `report --format nope`, `report --lang de`, `--old`-гүй `diff`, оролтгүй `scan` |

Severity босго **танигдаагүй** тохиолдол нь зориуд хэрэглээний алдаа БИШ, тиймээс `3`
болж харагдахгүй. `report --fail-on` ба `diff --fail-on-new` нь stderr-т анхааруулаад
шалгалтыг алгасна (exit `0`); `gate --fail-on` ба `fail_on:` нь анхааруулаад built-in `high`
руу унана — энэ нь ХАТУУ тал. Тиймээс бичиглэлийн алдаа gate-ийг хэзээ ч чимээгүй
ХАТУУРУУЛАХГҮЙ — харин `report` ба `diff` дээр шалгалтыг чимээгүй УНТРААНА, тул CI-д тэр
анхааруулгыг үйлдэл шаардсан гэж авч үзнэ.

`tatar-kuber doctor` нь scanner суугаагүй машин дээр **1** буцаана. Энэ бол алдаа биш,
зориудын бэлэн байдлын дохио — гэхдээ `set -e` дор шинэ runner-ыг зогсооно, тиймээс зөвхөн
хүснэгт хэрэгтэй бол `tatar-kuber doctor || true` гэж хамгаална.
