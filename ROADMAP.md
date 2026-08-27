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

## Release 2 (v2.0) — Depth & the audit deliverable 🎯

Theme: **make it the tool a security auditor reaches for.**

- **Bilingual professional PDF audit report** — a client-ready deliverable (cover, executive
  summary, methodology, findings, evidence, remediation, appendix) in EN and MN. *Highest
  business lever for consulting.*
- **Compliance mapping** — map canonical controls to **CIS Kubernetes Benchmark, NSA/CISA
  Hardening, ISO/IEC 27001 Annex A, MITRE ATT&CK for Containers**; add a compliance view/section
  to the report ("X% aligned, these gaps").
- **Expanded control coverage** — grow the canonical registry well beyond the current set;
  broaden per-scanner rule mappings.
- **Scan trending / diff** — compare two scans (the schema already carries `result_hash` and
  finding IDs): new / fixed / regressed findings, and score delta over time.
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

## Release 2 (v2.0) — Гүн ба аудитын deliverable 🎯

Сэдэв: **аудиторын гар татдаг багаж болгох.**

- **Хоёр хэлт мэргэжлийн PDF аудит тайлан** — үйлчлүүлэгчид бэлэн deliverable (нүүр хуудас,
  гүйцэтгэх хураангуй, аргачлал, олдворууд, нотолгоо, засварын зөвлөмж, хавсралт) EN/MN.
  *Консалтингийн хамгийн том хөшүүрэг.*
- **Compliance mapping** — canonical control-уудыг **CIS Kubernetes Benchmark, NSA/CISA,
  ISO/IEC 27001 Annex A, MITRE ATT&CK for Containers**-т зурах; тайланд compliance хэсэг нэмэх
  ("X% нийцсэн, эдгээр цоорхой").
- **Control хамрах хүрээг өргөтгөх** — canonical registry-г одоогийнхоос хамаагүй нэмэгдүүлэх;
  scanner тус бүрийн rule mapping-ийг өргөжүүлэх.
- **Scan trending / diff** — хоёр scan-ыг харьцуулах (схемд `result_hash` + finding ID бэлэн):
  шинэ / зассан / буцаж гарсан олдвор, оноо хугацааны туршид хэрхэн өөрчлөгдсөн.
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
