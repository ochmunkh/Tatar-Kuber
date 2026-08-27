# Deduplication — before / after

TATAR-Kuber's signature feature: when several scanners flag the **same issue on the
same resource**, you get **one** finding — not three — with `found_by` listing every
scanner that saw it, merged evidence, preserved original rule IDs, and a confidence
level that reflects the agreement.

This example is real: it is produced from the demo data shipped in
[`examples/demo/`](../examples/demo). Reproduce it in ~5 seconds:

```bash
tatar-kuber scan --raw-dir examples/demo -o out
# → out/scan-result.json  (look for TATAR-CON-001 on deployment/api)
```

## Case: privileged container on `deployment/api` (namespace `production`)

Three scanners independently detect the same misconfiguration — each with its own
rule ID, severity vocabulary and JSON shape.

### Before — three separate findings (raw scanner output)

**Trivy**
```json
{ "AVDID": "AVD-KSV0017", "Title": "Privileged container",
  "Severity": "HIGH", "Resource": "Deployment/api", "Namespace": "production" }
```

**Kubescape**
```json
{ "resourceID": "apps/v1//production/Deployment/api",
  "controlID": "C-0057", "name": "Privileged container",
  "status": { "status": "failed" } }
```

**Checkov**
```json
{ "check_id": "CKV_K8S_16", "check_name": "Container should not be privileged",
  "resource": "Deployment.production.api", "file_path": "/lab/broken/api.yaml" }
```

Three tools, three rule IDs (`AVD-KSV0017` / `C-0057` / `CKV_K8S_16`), three formats.
A human has to notice they describe the **same** problem and reconcile them by hand —
across every resource, every scan.

### After — one unified finding (TATAR-Kuber)

```json
{
  "canonical_control": "TATAR-CON-001",
  "resource": "deployment/api",
  "namespace": "production",
  "severity": "HIGH",
  "title": "Privileged container enabled",
  "found_by": ["checkov", "kubescape", "trivy"],
  "confidence": "HIGH",
  "risk_contribution": 12.6,
  "risk_factors": { "base_weight": 7, "asset_context": 1.5, "exposure": 1, "confidence": 1.2, "contribution": 12.6 },
  "remediation": "Set securityContext.privileged=false.",
  "raw_refs": [
    { "scanner": "checkov",   "rule_id": "CKV_K8S_16" },
    { "scanner": "kubescape", "rule_id": "C-0057" },
    { "scanner": "trivy",     "rule_id": "AVD-KSV0017" }
  ]
}
```

One finding. `found_by` lists all three scanners. Confidence is **HIGH** because three
independent tools agree. The original rule IDs are preserved in `raw_refs` for full
traceability, and the risk contribution is explained by `risk_factors`
(`7 × 1.5 × 1 × 1.2 = 12.6`).

**Net effect:** `3 findings → 1`. Instead of "3 scanners, 3 alerts, is this the same
thing?", the reviewer sees one prioritized issue with the strength of three tools
behind it.

---

## Монгол — давхардлыг арилгах: өмнө / дараа

TATAR-Kuber-ийн гол онцлог: хэд хэдэн scanner **нэг resource дээрх нэг асуудлыг**
илрүүлэхэд, гурван finding биш **нэг** finding гарна — олсон бүх scanner-ыг `found_by`-д
жагсааж, нотолгоог нэгтгэж, эх rule ID-г хадгалж, санал нийлэлтийг тусгасан итгэлийн
түвшинтэй.

Энэ жишээ бол жинхэнэ: [`examples/demo/`](../examples/demo)-д багтсан demo датагаас
гарна. ~5 секундэд давтах:

```bash
tatar-kuber scan --raw-dir examples/demo -o out
# → out/scan-result.json  (TATAR-CON-001 / deployment/api-г хар)
```

### Кейс: `deployment/api` (namespace `production`) дээрх privileged контейнер

Гурван scanner ижил misconfiguration-ыг тус тусдаа олно — тус бүр өөрийн rule ID,
severity үг, JSON бүтэцтэй.

### Өмнө — гурван тусдаа finding (боловсруулаагүй raw)

**Trivy** → `AVD-KSV0017` · **Kubescape** → `C-0057` · **Checkov** → `CKV_K8S_16`
(дээрх raw хэсгүүдийг үз). Гурван багаж, гурван rule ID, гурван формат. Эдгээр нь **нэг**
асуудал мөн эсэхийг хүн өөрөө ойлгож, resource бүр дээр, scan бүрд гараар нэгтгэх ёстой.

### Дараа — нэг нэгдсэн finding (TATAR-Kuber)

Дээрх JSON-той ижил: `canonical_control = TATAR-CON-001`,
`found_by = [checkov, kubescape, trivy]`, `confidence = HIGH` (3 scanner санал нийлсэн),
эх rule ID-ууд `raw_refs`-д хадгалагдсан, эрсдэлийн оноо `risk_factors`-оор тайлбарлагдсан
(`7 × 1.5 × 1 × 1.2 = 12.6`).

**Үр дүн:** `3 finding → 1`. "3 scanner, 3 дохио, энэ ижил үү?" гэхийн оронд, шалгагч нь
гурван багажийн жинтэй, нэг эрэмбэлэгдсэн асуудлыг л харна.
