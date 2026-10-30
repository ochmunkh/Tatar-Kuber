# TATAR-Kuber — Roadmap

> Versions and dates are indicative, not commitments. The North Star drives priorities;
> each release is a step toward it. (Монгол хувилбар доор — see below.)

## North Star

**The unified, bilingual Kubernetes security posture platform.**
One command locally → one continuous service in-cluster → one dashboard and one audit-ready
report for engineers, auditors and CISOs alike — in **English and Mongolian**.

TATAR-Kuber is the **aggregation + canonical-control + risk + reporting layer** for Kubernetes
security: pluggable scanner adapters feed a single, de-duplicated, explainable source of truth.
Not another scanner — the layer that makes every scanner speak one language.

Guiding principles: read-only first · scanner-agnostic · explainable over opaque · bilingual by
default · minimal supply chain · audit-grade output.

---

## v1.0.0 — Foundation ✅ (shipped)

Orchestrator + canonical control model + dedup + confidence + blind-shot + explainable risk;
4 scanners (Trivy · Kubescape · Checkov · Popeye); parallel Live Mode B (validated on a real
`kind` cluster in CI); JSON / SARIF / HTML (bilingual); CI/CD gatekeeper + GitHub Action;
distribution via brew / curl / Docker; govulncheck + gosec in CI.

---

## v1.0.1 / v1.0.2 — Accountability ✅ (shipped)

Theme: **a scanner that contributes nothing must never look like one that found nothing.**

An audit of v1.0.0's own live run showed all 11 findings came from Kubescape alone — Trivy and
Popeye were detected, versioned in the report, and silently contributing zero. Fixed, then the
same audit method was turned on the mapping registry itself.

- **`metadata.scanner_runs[]`** — per-scanner status / duration / findings / unmapped rules,
  surfaced as a *Scanner coverage* table in the report. Graceful degradation is no longer silent.
- **Raw scanner output kept** as evidence in `<out>/raw/` (the same layout `--raw-dir` accepts,
  so any scan is re-processable and auditable).
- **Mapping audit against upstream definitions** — Popeye 7 of 10 mappings wrong, Kubescape 6 of
  28 (two swapped pairs), Checkov 2 of 18, Trivy 0 of 11. All fixed and pinned by tests that force
  any new rule to have its meaning verified.
- **Mode A validated** — a new no-cluster [static-scan workflow](.github/workflows/static-scan.yml)
  runs real Checkov weekly; the real-cluster workflow now asserts **each** scanner individually.
- **Curated severity wins** — a linter's log level no longer overrides a control's
  `default_severity`; adapters set severity only when the scanner gives a real security rating.
- **Pod → controller rollup** (v1.0.2) — Popeye lints a Pod while Trivy/Kubescape lint its
  Deployment, so one pod-template violation was counted twice (and once per replica). Pod-scoped
  findings are now moved onto their owning controller *before* dedup. No cluster call, no guessing:
  a controller-level finding for the same canonical control must already exist in the same
  namespace, and the pod name must be that controller's name plus a suffix from
  `rand.SafeEncodeString`'s vowel-free alphabet — so `api-598c4dc6b8-ldjqq` rolls up to `api`,
  `api-canary` does not. Moved pods stay in the evidence, counts appear in `metadata.rollup`, and
  `--no-rollup` disables it.
- **Correctness fixes** (v1.0.2) — namespace asset context is token-matched (`non-production` is no
  longer scored as production), blind-shot rules are validated at registry load, never-matched
  suppressions and policy rules naming unknown controls are reported, and SARIF findings with a
  file path emit a real file:line location.

---

## v1.0.3 — Trending & honest provenance ✅ (shipped)

Theme: **an audit is not a one-off, and a report must not misstate how it was produced.**

- **Scan trending / diff** — `diff --old a.json --new b.json` compares two scans by the stable
  finding ID: new / fixed / worsened / improved / unchanged, per-severity and score deltas,
  `--fail-on-new <severity>` for CI, and text or JSON output. Because a lower count is not
  always good news, it also diffs `metadata.scanner_runs`: a scanner that used to produce
  findings and now produces none is flagged **COVERAGE REGRESSED** rather than read as "fixed".
  Comparisons that cannot be trusted — different cluster, different mode, one side scanned with
  `--no-rollup` — are called out as warnings instead of silently producing a misleading diff.
- **Language moved from scan to report** — `report --lang en|mn` renders either language from
  one `scan-result.json`, so a second language no longer means re-running the scanners and
  hitting the cluster again. It applies to JSON, SARIF and HTML alike, leaves the source file
  untouched (so `metadata.result_hash` stays valid), and refuses a language the registry does
  not carry instead of silently falling back to English.
- **`scan_mode` tells the truth** — an offline `--raw-dir` ingest reported itself as `remote`,
  claiming a live cluster scan it never performed. It is now `offline`, which also restores
  `diff`'s mode-mismatch warning between a live scan and a replayed one.
- **Version drift guard** — `metadata.tatar_version` comes from a constant that release tooling
  cannot inject, so a release could ship a binary reporting one version and writing another
  into every report and SARIF file. A test now fails when the two disagree.
- **Daily scanner guard** — the live and static workflows run every day instead of weekly, and
  an installer outage no longer sinks the whole run: each install retries, and a scanner that
  still fails is surfaced as `unavailable` while the rest of the scan proceeds.

---

## v1.0.4 — Saying what it actually is 🚧 (in development)

Theme: **close the gap between what the tool does and what it says about itself.**
Every item below was a place where something working was described wrongly, and nothing
turned red.

- **`top`** — ranks a finished scan twice: workloads by summed severity, and controls by how
  many distinct resources they hit. The second table is usually the one that matters — one
  control failing across thirty workloads is one fix, not thirty. Read-only.
- **`confidence_reason`** — `confidence: HIGH` collapsed 70 single-scanner findings, 4
  corroborated ones and 1 heuristic into one word. Each finding now says which it is.
- **Control descriptions reach the report** — 33 curated descriptions sat in the registry
  while 70 of 75 findings printed none. Now bilingual, and scanner-written text is no longer
  overwritten by them.
- **Per-platform checksum pins** — one checksum per scanner was correct on linux/amd64 and a
  mismatch everywhere else, read as a corrupt download rather than an unpinned platform.
  Twelve pins now, each read from the release's own published checksum file.
- **Pin drift is watched** — three of four pins went stale within twelve days and nothing
  said so. A daily job compares each pin against upstream and keeps one issue open; a check
  that cannot reach the API fails rather than reporting "current".
- **Least privilege, honestly** — the suggested ClusterRole asked for Secret read access with
  a comment claiming it would not read the values. RBAC cannot do that; `get`/`list` return
  the whole `data:` field. The permission is gone.
- **Windows** — `update` now refuses clearly instead of failing obscurely (the catalogue
  carries no Windows assets), and CI builds and tests on Windows. The docs parity check,
  which could never pass on the maintainer's own machine, now does.
- **SBOM per release**, schema versioning policy with a frozen `required` list, English
  adapter strings, tightened output file permissions (scan results are a list of a cluster's
  weaknesses, not world-readable data), and the registry no longer misstates when it changed.
- **First outside contribution** — 13 commits from [fg0x0](https://github.com/fg0x0), and
  CONTRIBUTING now states what a change has to show.

---

## Release 2 (v2.0) — Depth & the audit deliverable 🎯

Theme: **make it the tool a security auditor reaches for.**

- **Bilingual professional PDF audit report** — a client-ready deliverable (cover, executive
  summary, methodology, findings, evidence, remediation, appendix) in EN and MN. *Highest
  business lever for consulting.*
- **Compliance mapping** — map canonical controls to **CIS Kubernetes Benchmark, NSA/CISA
  Hardening, ISO/IEC 27001 Annex A, MITRE ATT&CK for Containers**; add a compliance view/section
  to the report ("X% aligned, these gaps").
- **Expanded control coverage** — grow the canonical registry well beyond the current set;
  broaden per-scanner rule mappings. Gaps the v1.0.2 audit already surfaced, visible in every
  report: `TATAR-NET-004` (Ingress without TLS) has no scanner rule mapped at all; and these are
  deliberately unmapped for want of a matching control — Trivy `KSV-0020/0021` (low UID/GID),
  `KSV-0110` (default namespace); Kubescape `C-0079` (a single CVE), `C-0055` (Linux hardening),
  `C-0054` (cluster internal networking); Checkov `CKV_K8S_40` (high UID), `CKV_K8S_21` (default
  namespace), `CKV_K8S_18` (hostIPC), `CKV_K8S_43` (image digest), `CKV_K8S_27` (docker socket —
  deserves its own critical control).
- **Object-aware Mode A for Trivy** — `trivy config` works on manifests but names no Kubernetes
  object (only file:line plus a prose message in five shapes), so file-scoped reporting would
  merge several identical violations in one file into one finding. Needs manifest parsing.
- **5th scanner adapter** — prove the pluggable promise and deepen coverage (candidates:
  kube-bench for CIS node checks, kubeaudit, or Terrascan). One clean adapter = one PR.
- **Waiver/suppression maturity** — richer `.tatar-kuber.yaml` policy, expiring waivers with
  audit trail, per-team baselines.

---

## Release 3 (v3.0) — Continuous & platform 🚀

Theme: **from point-in-time CLI to a living security posture service.**

- **Continuous mode / in-cluster operator** — scheduled scans (CronJob or lightweight operator),
  storing history; posture that updates itself.
- **Web dashboard** — served HTML with trend charts, multi-namespace drill-down, and the
  bilingual views; static-generated first, then a served UI.
- **Findings lifecycle + persistence** — OPEN → ACKNOWLEDGED → FIXED → VERIFIED (the schema
  already defines these), tracked across scans.
- **Multi-cluster aggregation** — one posture view across many clusters / environments.
- **Notifications & integrations** — Slack / Teams / email on new-critical or regression; export
  to Jira / DefectDojo; webhook events.
- **Team features** — org policies, RBAC, audit log (open-core boundary begins here).
- **MCP server (read-only first)** — expose the posture as tools an AI assistant can call, so an
  engineer can ask "what changed since last week" or "why is this CRITICAL" in plain language.
  TATAR-Kuber is unusually well suited to this: the answer to "why" is already machine-readable
  (`canonical_control`, `found_by`, `confidence`, `risk_factors`, `attack`), so the model reads
  rather than guesses. Deliberate constraints, decided up front:
  - **Read-only to start.** Tools that analyse an existing `scan-result.json` (`top_risks`,
    `findings(filter)`, `explain(id)`, `diff`) come first — fast, no credentials, no blast radius.
    A live `scan` holds a kubeconfig and takes minutes; it comes last, behind an explicit
    confirmation, and never returns the kubeconfig itself.
  - **Summarise, never dump.** A 300-finding result would fill the model's context. Every tool
    filters or aggregates; none returns the whole file.
  - **Findings are data, not instructions.** Image names, annotations, secret matches and scanner
    messages are attacker-influenced strings. The server marks them as untrusted content, so a
    security tool never becomes the injection path into the assistant.
  - Order: after v2. MCP is a distribution channel, not the differentiator — mapping accuracy is.
    An AI-connected tool that answers confidently and wrongly is worse than no integration.

---

## Beyond v3 — the bold vision

- **Open-core KSPM/ASPM layer** — the de-facto open-source layer that unifies K8s security
  scanners into one canonical, explainable, bilingual posture — with an optional hosted/SaaS and
  team tier (a natural managed-service offering for security consultancies).
- **Compliance-as-evidence** — generate ISO 27001 / CIS / regulatory **evidence packs**
  (bilingual) straight from a scan — turning a scan into an audit artifact.
- **Beyond Kubernetes** — extend the canonical model outward to cloud posture (CSPM) and IaC at
  scale, keeping the same "many scanners → one truth" philosophy.
- **Adapter ecosystem** — a documented adapter SDK so the community adds scanners; TATAR-Kuber
  becomes the aggregation standard, not a single tool.

Be ambitious: the end state is a platform, and a 5th (or 15th) scanner is just another adapter.

---

# TATAR-Kuber — Замын зураг (Монгол)

> Хувилбар, огноо нь чиглэл заасан төлөвлөгөө — амлалт биш. Алсын хараа (North Star) тэргүүлэх
> ач холбогдлыг тодорхойлно; release бүр түүн рүү хийх нэг алхам.

## Алсын хараа (North Star)

**Нэгдсэн, хоёр хэлт Kubernetes аюулгүй байдлын posture платформ.**
Локал нэг команд → cluster дотор тасралтгүй үйлчилгээ → инженер, аудитор, CISO бүгдэд
зориулсан нэг dashboard, нэг аудитад бэлэн тайлан — **англи ба монгол** хэлээр.

TATAR-Kuber бол Kubernetes аюулгүй байдлын **нэгтгэх + canonical-control + эрсдэл + тайлангийн
давхарга**: залгаж болох scanner adapter-ууд нэг давхардалгүй, тайлбарлагдах эх сурвалжийг
тэжээнэ. Өөр нэг scanner биш — scanner бүрийг **нэг хэлээр ярьдаг болгодог давхарга**.

Зарчим: read-only эхэнд · scanner-агностик · тайлбарлагдах нь хар хайрцгаас дээр · анхнаасаа
хоёр хэлт · минимал supply chain · аудитын түвшний гаралт.

---

## v1.0.0 — Суурь ✅ (гарсан)

Orchestrator + canonical загвар + dedup + confidence + blind-shot + тайлбарлагдах эрсдэл;
4 scanner (Trivy · Kubescape · Checkov · Popeye); зэрэгцээ Live Mode B (бодит `kind` cluster дээр
CI-д батлагдсан); JSON / SARIF / HTML (хоёр хэлт); CI/CD gatekeeper + GitHub Action; brew / curl
/ Docker түгээлт; CI-д govulncheck + gosec.

---

## v1.0.1 / v1.0.2 — Шударга байдал ✅ (гарсан)

Сэдэв: **юу ч өгөөгүй scanner нь "юу ч олдсонгүй" гэж харагдах ёсгүй.**

v1.0.0-ийн бодит live run-ыг аудит хийхэд 11 finding бүгд зөвхөн Kubescape-ээс ирсэн нь
тогтоогдов — Trivy, Popeye хоёул танигдаж, хувилбар нь тайланд бичигдээд, чимээгүй юу ч
өгөөгүй. Зассаны дараа мөнөөх аудитын аргыг зураглалын registry дээр өөр дээр нь хэрэглэв.

- **`metadata.scanner_runs[]`** — scanner тус бүрийн төлөв / хугацаа / finding / зураглалгүй
  rule, тайланд *Scanner хамрах хүрээ* хүснэгтээр гарна. Graceful degradation чимээгүй биш болов.
- **Түүхий scanner гаралт** `<out>/raw/`-д нотолгоо болж хадгалагдана (`--raw-dir` хүлээж авдаг
  яг тэр бүтэц тул scan бүрийг дахин боловсруулж, аудит хийж болно).
- **Зураглалыг upstream-ийн тодорхойлолттой тулгасан аудит** — Popeye 10-аас 7 буруу,
  Kubescape 28-аас 6 (хоёр хос сольсон), Checkov 18-аас 2, Trivy 11-ээс 0. Бүгд зассан ба шинэ
  rule нэмэхэд утгыг батлахыг албадах тестээр бэхлэгдсэн.
- **Mode A батлагдсан** — cluster шаардахгүй шинэ
  [static-scan workflow](.github/workflows/static-scan.yml) бодит Checkov-ыг 7 хоног тутам
  ажиллуулна; real-cluster workflow одоо scanner **тус бүрийг** шалгана.
- **Curated severity дийлнэ** — линтерийн log-level нь control-ийн `default_severity`-г дарахаа
  болив; adapter нь зөвхөн scanner бодит аюулгүй байдлын үнэлгээ өгсөн үед severity тавина.
- **Pod → controller rollup** (v1.0.2) — Popeye нь Pod-ыг, Trivy/Kubescape нь түүний Deployment-ыг
  шалгадаг тул pod template-ийн нэг зөрчил хоёр удаа (replica тутамд бас нэг удаа) тоологдож байв.
  Одоо pod хэмжээний finding нь dedup-аас ӨМНӨ эзэмшигч controller руу зөөгдөнө. Cluster руу
  хандахгүй, таамаглахгүй: тухайн canonical control дээр ижил namespace-д controller хэмжээний
  finding аль хэдийн байх ёстой, мөн pod-ийн нэр нь тэр controller-ийн нэр дээр
  `rand.SafeEncodeString`-ийн эгшиггүй алфавитын дагавар нэмсэн байх ёстой — тиймээс
  `api-598c4dc6b8-ldjqq` нь `api` руу зөөгдөнө, `api-canary` зөөгдөхгүй. Зөөгдсөн pod нотолгоонд
  үлдэнэ, тоо нь `metadata.rollup`-д гарна, `--no-rollup`-аар болино.
- **Зөв байдлын засварууд** (v1.0.2) — namespace-ийн asset context token-оор тулгагдана
  (`non-production` нь production гэж үнэлэгдэхээ болив), blind-shot rule нь registry уншихад
  шалгагдана, юунд ч таараагүй suppression ба байхгүй control нэрлэсэн бодлогын rule мэдээлэгдэнэ,
  файлын зам агуулсан SARIF finding нь бодит file:line гаргана.

---

## v1.0.3 — Тренд ба үнэн гарал үүсэл ✅ (гарсан)

Сэдэв: **аудит бол нэг удаагийн ажил биш, мөн тайлан өөрийн гарал үүслээ худал хэлж болохгүй.**

- **Scan trending / diff** — `diff --old a.json --new b.json` нь хоёр scan-ыг тогтвортой
  finding ID-гаар тулгана: шинэ / зассан / дордсон / сайжирсан / хэвээр, severity тус бүрийн
  ба онооны зөрүү, CI-д `--fail-on-new <severity>`, text эсвэл JSON гаралт. Тоо буурсан нь
  үргэлж сайн мэдээ биш тул `metadata.scanner_runs`-ыг мөн тулгана: өмнө finding өгч байсан
  scanner одоо 0 өгвөл **ХАМРАХ ХҮРЭЭ БУУРСАН** гэж тэмдэглэнэ, "зассан" гэж уншигдахгүй.
  Итгэх боломжгүй харьцуулалтыг (өөр cluster, өөр горим, нэг тал нь `--no-rollup`) чимээгүй
  өнгөрөөхгүй, анхааруулга болгож хэлнэ.
- **Хэл scan-аас report руу шилжив** — `report --lang en|mn` нь нэг `scan-result.json`-оос аль
  ч хэлээр гаргана; хоёр дахь хэлийн төлөө scanner-уудыг дахин ажиллуулж, cluster руу дахин
  хандах шаардлагагүй болов. JSON, SARIF, HTML гурвуулд үйлчилнэ, эх файлыг хөндөхгүй тул
  `metadata.result_hash` хүчинтэй хэвээр, мөн registry-д байхгүй хэлийг чимээгүй англи руу
  унагахгүй, шууд хэлнэ.
- **`scan_mode` үнэнээ хэлдэг болов** — `--raw-dir` офлайн ingest нь өөрийгөө `remote` гэж
  зарлаж, хийгээгүй амьд кластерын scan-ыг хийсэн мэт харуулдаг байв. Одоо `offline` болсноор
  `diff`-ийн горим зөрүүгийн анхааруулга амьд scan ба дахин тоглуулсныг ялгадаг боллоо.
- **Хувилбар зөрөхөөс хамгаалах** — `metadata.tatar_version` нь release хэрэгслийн хүрдэггүй
  const-оос ирдэг тул нэг хувилбар хэлж, тайлан бүрт өөр хувилбар бичдэг binary гарах
  боломжтой байв. Одоо хоёр нь зөрвөл тест унана.
- **Өдөр тутмын scanner хамгаалалт** — амьд ба статик workflow долоо хоног тутмын оронд өдөр
  бүр ажиллана; суулгагчийн саатал бүхэл run-ыг унагахаа болив: суулгалт бүр дахин оролдоно,
  тэгсэн ч бүтэхгүй scanner нь `unavailable` гэж гарч, үлдсэн scan үргэлжилнэ.

---

## v1.0.4 — Байгаа байдлаа үнэн хэлэх 🚧 (хөгжүүлэлтэд)

Сэдэв: **хэрэгсэл юу хийдэг, өөрийгөө юу гэж хэлдэг хоёрын зөрүүг хаах.**
Доорх зүйл бүр нь ажиллаж байгаа зүйлийг буруу тайлбарлаж байсан газар бөгөөд
аль нь ч улаан болоогүй.

- **`top`** — дууссан scan-ийг хоёр талаас эрэмбэлнэ: workload-ууд severity-ийн нийлбэрээр,
  control-ууд тусч байгаа өөр resource-ийн тоогоор. Ихэвчлэн хоёр дахь хүснэгт нь чухал нь —
  гучин workload дээр унасан нэг control бол гучин засвар биш, НЭГ засвар. Зөвхөн уншина.
- **`confidence_reason`** — `confidence: HIGH` нь 70 ганц-scanner, 4 баталгаажсан, 1 эвристик
  олдворыг нэг үгэнд нийлүүлж байв. Одоо олдвор бүр алинд нь хамаарахаа хэлнэ.
- **Control-ийн тайлбар тайланд хүрдэг болов** — бүртгэлд 33 тайлбар бичээстэй байхад 75
  олдвороос 70 нь тайлбаргүй хэвлэгддэг байв. Одоо хоёр хэлээр, бас scanner-ийн өөрийнх нь
  бичсэн текстийг дарж бичихгүй.
- **Платформ тус бүрийн checksum** — нэг scanner-т нэг checksum нь linux/amd64 дээр зөв,
  бусад бүх платформ дээр зөрж, "эвдэрсэн татаж авалт" гэж уншигддаг байв. Одоо 12 pin,
  тус бүр нь release-ийн өөрийнх нь нийтэлсэн checksum файлаас уншигдсан.
- **Pin хоцрохыг харж байна** — 4-өөс 3 нь 12 хоногийн дотор хоцорсон атлаа хэн ч хэлээгүй.
  Өдөр тутмын ажил upstream-тэй тулгаж нэг issue нээлттэй барина; API-д хүрч чадаагүй
  шалгалт нь "цэгцтэй" гэж хэлэхгүй, унана.
- **Хамгийн бага эрх, үнэнээр** — санал болгож байсан ClusterRole нь Secret унших эрх гуйж,
  "утгыг нь уншихгүй" гэсэн тайлбартай байв. RBAC дээр энэ боломжгүй: `get`/`list` нь `data:`
  талбарыг бүхэлд нь буцаана. Эрхийг нь хассан.
- **Windows** — `update` нь ойлгомжгүй унахын оронд шалтгаанаа хэлж татгалздаг болов
  (каталогт Windows-ийн файл байхгүй), CI нь Windows дээр build, тест ажиллуулна.
  Арчилагчийн өөрийнх нь машин дээр хэзээ ч давдаггүй байсан баримтын шалгалт одоо давна.
- **Release бүрт SBOM**, схемийн хувилбарлалтын бодлого ба царцаасан `required` жагсаалт,
  adapter-ийн англи хэллэг, гаралтын файлын эрхийн чангалалт (scan-ийн үр дүн бол кластерын
  сул талуудын жагсаалт, нийтэд уншуулах өгөгдөл биш), мөн бүртгэл сүүлд хэзээ өөрчлөгдсөнөө
  худал хэлэхээ болив.
- **Эхний гадны хувь нэмэр** — [fg0x0](https://github.com/fg0x0)-оос 13 commit, мөн
  CONTRIBUTING нь өөрчлөлт юу нотлох ёстойг тодорхой бичив.

---

## Release 2 (v2.0) — Гүн ба аудитын deliverable 🎯

Сэдэв: **аудиторын гар татдаг багаж болгох.**

- **Хоёр хэлт мэргэжлийн PDF аудит тайлан** — үйлчлүүлэгчид бэлэн deliverable (нүүр хуудас,
  гүйцэтгэх хураангуй, аргачлал, олдворууд, нотолгоо, засварын зөвлөмж, хавсралт) EN/MN.
  *Консалтингийн хамгийн том хөшүүрэг.*
- **Compliance mapping** — canonical control-уудыг **CIS Kubernetes Benchmark, NSA/CISA,
  ISO/IEC 27001 Annex A, MITRE ATT&CK for Containers**-т зурах; тайланд compliance хэсэг нэмэх
  ("X% нийцсэн, эдгээр цоорхой").
- **Trivy-д объект танидаг Mode A** — `trivy config` манифест дээр ажилладаг ч K8s объектын
  нэрийг өгдөггүй (зөвхөн файл:мөр ба 5 хэлбэртэй проз мессеж), тиймээс файлын хэмжээнд
  тайлагнавал нэг файл дахь хэд хэдэн ижил зөрчил нэг finding болж нийлнэ. Манифестыг парслах
  шаардлагатай.
- **Зураглалын хийдлүүд** (v1.0.2 аудитаар илэрсэн, тайлан бүрт ил): `TATAR-NET-004`-д ямар ч
  scanner rule зурагдаагүй; тохирох control байхгүйн улмаас зориудаар зураглаагүй — Trivy
  `KSV-0020/0021`, `KSV-0110`; Kubescape `C-0079`, `C-0055`, `C-0054`; Checkov `CKV_K8S_40`,
  `CKV_K8S_21`, `CKV_K8S_18`, `CKV_K8S_43` (digest), `CKV_K8S_27` (docker socket — тусдаа
  critical control болох ёстой).
- **Control хамрах хүрээг өргөтгөх** — canonical registry-г одоогийнхоос хамаагүй нэмэгдүүлэх;
  scanner тус бүрийн rule mapping-ийг өргөжүүлэх.
- **5 дахь scanner adapter** — "залгаж болно" гэдгийг батлаж, хамрах хүрээг гүнзгийрүүлэх
  (нэр дэвшигч: CIS node-д kube-bench, эсвэл kubeaudit, Terrascan). Нэг цэвэр adapter = нэг PR.
- **Waiver/suppression боловсронгуй** — илүү баялаг `.tatar-kuber.yaml`, хугацаатай waiver +
  аудитын мөр, багийн baseline.

---

## Release 3 (v3.0) — Тасралтгүй ба платформ 🚀

Сэдэв: **point-in-time CLI-аас амьд posture үйлчилгээ рүү.**

- **Тасралтгүй горим / cluster доторх operator** — товлосон scan (CronJob эсвэл хөнгөн operator),
  түүх хадгалах; өөрөө шинэчлэгддэг posture.
- **Веб dashboard** — trend график, олон namespace, хоёр хэлт харагдацтай served HTML; эхлээд
  статик, дараа нь served UI.
- **Олдворын амьдралын мөчлөг + persistence** — OPEN → ACKNOWLEDGED → FIXED → VERIFIED (схемд
  аль хэдийн тодорхойлсон), scan хооронд хөтлөх.
- **Олон cluster нэгтгэл** — олон cluster/орчны нэг posture харагдац.
- **Мэдэгдэл ба интеграци** — шинэ-critical/регресст Slack / Teams / имэйл; Jira / DefectDojo руу
  export; webhook.
- **Багийн боломжууд** — байгууллагын бодлого, RBAC, аудит лог (open-core хил эндээс эхэлнэ).
- **MCP сервер (эхлээд зөвхөн уншдаг)** — posture-ыг AI туслах дуудаж болох tool болгон гаргана:
  инженер "өнгөрсөн долоо хоногоос юу өөрчлөгдсөн бэ", "энэ яагаад CRITICAL вэ" гэж энгийн хэлээр
  асууна. TATAR-Kuber үүнд ер бусын сайн тохирно: "яагаад" гэсэн асуултын хариу нь аль хэдийн
  машин уншигдах хэлбэртэй (`canonical_control`, `found_by`, `confidence`, `risk_factors`,
  `attack`) тул загвар таамаглахын оронд УНШИНА. Эхнээс нь тогтоосон хязгаарлалт:
  - **Эхлээд зөвхөн уншдаг.** Байгаа `scan-result.json`-ыг задлах tool-ууд (`top_risks`,
    `findings(filter)`, `explain(id)`, `diff`) эхэлнэ — хурдан, credential-гүй, эрсдэлгүй. Амьд
    `scan` нь kubeconfig барьж, хэдэн минут ажилладаг тул хамгийн сүүлд, тодорхой
    баталгаажуулалтын ард; kubeconfig-ийг өөрийг нь хэзээ ч буцаахгүй.
  - **Хураангуйл, бүхлээр нь бүү өг.** 300 finding-тэй үр дүн загварын контекстийг дүүргэнэ. Tool
    бүр шүүх эсвэл нэгтгэх ёстой; аль нь ч бүтэн файлыг буцаахгүй.
  - **Finding бол өгөгдөл, заавар БИШ.** Image нэр, annotation, secret-ийн таарал, scanner-ийн
    мессеж нь халдагчийн нөлөөлж болох текст. Сервер тэдгээрийг итгэмжлэгдээгүй агуулга гэж
    тэмдэглэнэ — аюулгүй байдлын хэрэгсэл өөрөө туслах руу орох инъекцийн гарц болох ёсгүй.
  - Дараалал: v2-ын ДАРАА. MCP бол түгээх суваг, ялгарах давуу тал биш — давуу тал нь зураглалын
    нарийвчлал. Итгэлтэйгээр БУРУУ хариулдаг "AI-д холбогдсон" хэрэгсэл бол холбоогүй байснаас дор.

---

## v3-аас цааш — зоригтой алсын хараа

- **Open-core KSPM/ASPM давхарга** — K8s аюулгүй байдлын scanner-уудыг нэг canonical,
  тайлбарлагдах, хоёр хэлт posture болгон нэгтгэдэг de-facto open-source давхарга — сонголтоор
  hosted/SaaS ба багийн tier-тэй (аюулгүй байдлын консалтингийн managed-service санал болгоход
  төгс тохирно).
- **Compliance-as-evidence** — scan-аас шууд ISO 27001 / CIS / зохицуулалтын **нотолгооны багц**
  (хоёр хэлт) гаргах — scan-ыг аудитын баримт болгох.
- **Kubernetes-ээс цааш** — canonical загварыг cloud posture (CSPM), IaC руу өргөтгөх, "олон
  scanner → нэг үнэн" гэсэн зарчмаа хадгалан.
- **Adapter экосистем** — олон нийт scanner нэмэх adapter SDK; TATAR-Kuber ганц багаж биш,
  **нэгтгэлийн стандарт** болно.

Зоригтой бай: эцсийн төлөв бол платформ, 5 дахь (эсвэл 15 дахь) scanner бол зүгээр нэг adapter.
