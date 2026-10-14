# TATAR-Kuber

> Kubernetes Security Posture Assessment Framework  
> Engineering Document #2  
> Canonical Control Mapping  
> Scanner rule → TATAR canonical control — dedup-ийн суурь  
> Version 1.2  ·  кодтой тулгасан (2026-09-07)  
> Enkhbat.O — Security Analyst  
> 2026-07-24

<!-- Generated from 02_Canonical-Control-Mapping.docx by scripts/docx-to-md.py -- do not edit by hand. -->
*Generated from `02_Canonical-Control-Mapping.docx`. The Word document is canonical; regenerate with `python3 scripts/docx-to-md.py docs/02_Canonical-Control-Mapping.docx`.*

## 1. Зорилго

Deduplication-ийн жинхэнэ гол нь энэ баримт юм. Trivy, Kubescape, Checkov, Popeye нэг л асуудлыг тус тусын дугаар/нэрээр гаргадаг. String таарч дедуп хийвэл найдваргүй. Тиймээс scanner бүрийн rule ID-г TATAR-ийн нэг canonical control ID руу зурсан хөрвүүлэлтийн бүртгэл (registry) хэрэгтэй. Энэ бол TATAR-Kuber-ийн хамгийн том оюуны өмч (knowledge asset) бөгөөд ирээдүйд TATAR Security Knowledge Base болж өргөжинө.

## 2. Canonical control ID схем

Canonical ID нь TATAR-\<CATEGORY\>-NNN хэлбэртэй. Ангилал бүр өөрийн prefix-тэй бөгөөд эхнээс нь бүрэн тогтоогдсон. 1000+ rule болоход ч эмх цэгцтэй байлгах зорилготой.

| **Prefix** | **Ангилал** | **Хамрах хүрээ (жишээ)** |
|---|---|---|
| TATAR-CON | Container Security | privileged, runAsRoot, capability abuse, hostPID/hostNetwork, readOnlyRootFilesystem |
| TATAR-RBAC | RBAC Security | cluster-admin abuse, wildcard verbs/resources, excessive bindings, escalate/bind эрх |
| TATAR-NET | Network Security | NetworkPolicy байхгүй, hostPort, LoadBalancer ил, ingress TLS дутуу |
| TATAR-IMG | Image Security | CVE (OS/library), latest tag, unsigned image, эмзэг base image |
| TATAR-SEC | Secret Management | hardcoded secret, задарсан token, env доторх нууц, mounted secret эрсдэл |
| TATAR-OPS | Operational Security | probe дутуу, resource limit дутуу, orphan/dead service, broken reference (Popeye) |

## 3. Naming ба амьдралын мөчлөгийн дүрэм

- **Формат:** `TATAR-<CAT>-NNN`, NNN нь 3 оронтой дугаар (001-999). Шаардвал 4 орон болгож өргөтгөнө.
- **Тогтвортой байдал:** ID нэг олгогдсон бол ХЭЗЭЭ Ч дахин ашиглагдахгүй, дугаар нь өөрчлөгдөхгүй. ID бол гэрээ — SARIF, history, diff бүгд түүн дээр тогтдог.
- **Deprecation:** Хуучирсан control-ыг устгахгүй, зөвхөн `status: deprecated` төлөв авч, `superseded_by` талбараар шинэ ID руу зааж болно.
- **Эх сурвалж:** Бүх canonical control нэг файлд — `schema/canonical-controls.yaml` — төвлөрч, кодоос generate хийгддэг.

## 4. canonical-controls.yaml — бүтэц

```bash
# schema/canonical-controls.yaml — single source of truth
controls:
  - id: TATAR-CON-001
    title: { en: "Privileged container enabled", mn: "Эрх нэмэгдүүлсэн (privileged) контейнер" }
    category: "Container Security"
    type: misconfiguration
    default_severity: HIGH
    status: active               # active | deprecated
    references:
      - "CIS-5.2.1"
      - "MITRE-T1610"
    mappings:
      trivy:     ["AVD-KSV-0017"]
      kubescape: ["C-0057"]
      checkov:   ["CKV_K8S_16"]
      popeye:    []

  - id: TATAR-CON-002
    title: { en: "Container running as root", mn: "Root эрхээр ажиллаж буй контейнер" }
    category: "Container Security"
    type: misconfiguration
    default_severity: MEDIUM
    status: active
    mappings:
      trivy:     ["AVD-KSV-0012"]
      kubescape: ["C-0013"]
      checkov:   ["CKV_K8S_23"]
      popeye:    []
```

## 5. Хөрвүүлэлтийн матриц — жишээ

Дараах хүснэгт нь түгээмэл control-уудын scanner rule → canonical зураглалыг харуулна (бодит registry-ээс шууд уншигдсан, 2026-09-07). Бүрэн жагсаалт нь schema/canonical-controls.yaml — тэр бол single source of truth. ЧУХАЛ: scanner-ийн rule ID нь тогтвортой ч тухайн ID ЮУ шалгадаг нь хувилбар хооронд өөрчлөгддөг (ж: Popeye 0.22-д POP-101 = ":latest", POP-106 = "resources/limits"; өмнөх хувилбарт өөр байсан). Тиймээс rule нэмэх/солиход утгыг upstream-ийн эх сурвалжтай тулгаж батлах ба internal/canonical-ийн meaning-lock тестэд бүртгэх нь ЗААВАЛ.

| **Canonical ID** | **Гарчиг** | **Trivy** | **Kubescape** | **Checkov** | **Popeye** | **Severity** |
|---|---|---|---|---|---|---|
| TATAR-CON-001 | Privileged container enabled | AVD-KSV0017 | C-0057 | CKV_K8S_16 | — | HIGH |
| TATAR-CON-002 | Container running as root | AVD-KSV0012 | C-0013 | CKV_K8S_23 | POP-302, POP-306 | MEDIUM |
| TATAR-CON-003 | Allow privilege escalation | AVD-KSV0001 | C-0016 | CKV_K8S_20 | — | HIGH |
| TATAR-CON-004 | Dangerous capabilities added | AVD-KSV0004, AVD-KSV0003, AVD-KSV0106 | C-0046 | CKV_K8S_25, CKV_K8S_28, CKV_K8S_37, CKV_K8S_39 | — | HIGH |
| TATAR-CON-010 | Missing CPU/memory limits | AVD-KSV0011, AVD-KSV0015, AVD-KSV0016, AVD-KSV0018 | C-0009, C-0270, C-0271 | CKV_K8S_10, CKV_K8S_11, CKV_K8S_12, CKV_K8S_13 | POP-106, POP-107 | LOW |
| TATAR-RBAC-001 | cluster-admin binding overuse | — | C-0035, C-0272, C-0267 | — | — | CRITICAL |
| TATAR-RBAC-002 | Wildcard permissions in role | — | C-0187 | CKV_K8S_49 | — | HIGH |
| TATAR-NET-001 | Missing NetworkPolicy | AVD-KSV0038 | C-0260 | CKV2_K8S_6 | POP-1204 | MEDIUM |
| TATAR-IMG-001 | Critical CVE in container image | CVE-\* | — | — | — | CRITICAL |
| TATAR-IMG-003 | Image uses :latest tag | AVD-KSV0013 | — | CKV_K8S_14 | POP-100, POP-101 | MEDIUM |
| TATAR-SEC-001 | Secret exposed in environment variable | secret | C-0012 | CKV_K8S_35 | — | HIGH |
| TATAR-OPS-001 | Missing readiness probe | — | C-0018 | CKV_K8S_9 | POP-102 | LOW |
| TATAR-OPS-003 | Orphan / dead service (no endpoints) | — | — | — | POP-1100, POP-1110 | INFO |

## 6. Deduplication алгоритм

Normalize хийгдсэн бүх finding нэг pool-д орж, canonical_control + resource + namespace-аар бүлэглэгдэнэ. Ижил түлхүүртэй findings нэг болж нэгтгэгдэнэ. ЧУХАЛ: dedup-аас ӨМНӨ Pod хэмжээний finding-ийг эзэмшигч controller руу зөөнө (rollup) — эс бөгөөс scanner-ууд өөр өөр объектын хэмжээнд тайлагнадгаас (Popeye нь pod, Trivy/Kubescape нь workload) нэг зөрчил хоёр өөр түлхүүртэй болж давхар тоологдоно.

```go
func Deduplicate(findings []Finding) []Finding {
    groups := map[string][]Finding{}
    for _, f := range findings {
        key := f.CanonicalControl + "|" + f.Resource + "|" + f.Namespace
        groups[key] = append(groups[key], f)
    }
    out := []Finding{}
    for _, g := range groups {
        merged := g[0]
        foundBy := set{}
        for _, f := range g {
            foundBy.addAll(f.FoundBy)
            merged.Severity = maxSeverity(merged.Severity, f.Severity)  // хамгийн муугаар
            merged.References = union(merged.References, f.References)
            merged.RawRefs = append(merged.RawRefs, f.RawRefs...)
        }
        merged.FoundBy = foundBy.sorted()
        merged.Confidence = confidenceFrom(len(merged.FoundBy)) // §scoring
        merged.ID = stableID(merged)                            // §schema 7.1
        out = append(out, merged)
    }
    return sortByID(out)  // detrministik дараалал → тогтвортой result_hash
}
```

## 7. Нэгтгэх дүрмүүд

- **Severity:** хамгийн өндөр (муу) severity-г авна. Scanner-ууд зөрвөл аюулгүй тал руу.
- **found_by:** бүх scanner-ийн нэгдэл (union), эрэмбэлэгдсэн.
- **confidence:** found_by-ийн тооноос: 3+ → HIGH, 2 → MEDIUM, 1 → LOW.
- **references / raw_refs:** бүх эх сурвалжийг нэгтгэж хадгална — нотолгоо алдагдахгүй.
- **id:** нэгтгэсний дараа canonical+resource+namespace-аас дахин тооцоолж тогтвортой болгоно.

## 8. Арчилгааны ажлын урсгал

Шинэ scanner эсвэл шинэ rule гарахад: (1) canonical-controls.yaml-д тухайн rule-ыг одоо байгаа canonical control-ын mappings-д нэмэх, эсвэл шинэ canonical control үүсгэх; (2) хэрэв ижил утгатай control байхгүй бол шинэ дугаар олгох (хэзээ ч дахин ашиглахгүй); (3) unit test-ээр mapping бүр хүчинтэй canonical ID руу зааж байгааг шалгах; (4) хувилбар нэмэгдүүлж changelog-д тэмдэглэх. Canonical registry нь семантик хувилбартай (semver) байна.

## Хувилбарын тэмдэглэл — v1.1 / v1.2 (2026-09-07)

- Хөрвүүлэлтийн матриц (§5) бодит registry-ээс дахин үүсгэгдсэн. Өмнөх хүснэгтийн canonical ID-ууд хэрэгжүүлэлттэй зөрж байсан (ж: TATAR-CON-003 нь "Dangerous capabilities" гэж бичигдсэн байсан ч registry-д "Allow privilege escalation"; TATAR-OPS-001 нь "Missing resource limits" гэж бичигдсэн ч registry-д "Missing readiness probe", limits нь TATAR-CON-010).
- 2026-09-07-ны зураглалын аудит: дөрвөн scanner бүрийн зурагдсан rule-ыг upstream-ийн өөрийн тодорхойлолттой (Popeye codes.yaml, Checkov resource/k8s/\*.py, Trivy Misconfigurations\[\].Title, Kubescape control каталог) тулгав. Зөрүү: Popeye 10-аас 7, Kubescape 28-аас 6, Checkov 18-аас 2, Trivy 11-ээс 0. Бүгд зассан.
- Хамгийн ноцтой зөрүүнүүд: POP-108 "unnamed port" -\> "Missing CPU/memory limits"; POP-1500 "is suspended" -\> "Missing NetworkPolicy"; CKV_K8S_43 "image should use digest" -\> ":latest tag" (зөв пиннэсэн image-ийг ":latest" гэж тайлагнах false positive); Kubescape C-0187 (wildcard) ба C-0272 (admin roles) хоёр сольж бичигдсэн; C-0078 "allowed registry" нь image CVE гэж зурагдсан.
- Дедуп түлхүүр (§6) нь canonical_control\|resource\|namespace хэвээр. Гэхдээ resource нэр ХООСОН байвал түлхүүр давхцаж өөр өөр объект нэг finding болж нийлдэг. Kubescape-ийн RBAC subject-ууд (Group/User) нэрээ дээд түвшний "name" талбарт өгдгийг adapter уншаагүй тул "group/", "user/" гэж хоосон нэртэй гарч яг тэр давхцал үүсч байв — зассан.
- Confidence (§6-ийн confidenceFrom) нь зөвхөн scanner тооноос БИШ, scanner тоо БА шалгалтын determinism хоёулангаас тодорхойлогдоно: 2+ scanner -\> HIGH; 1 scanner + deterministic -\> HIGH; 1 scanner + эвристик -\> MEDIUM; 0 -\> LOW.

(v1.2) Дедуп түлхүүрийн өмнө ROLLUP алхам нэмэгдсэн: Pod хэмжээний finding нь ижил canonical control ба namespace-д controller хэмжээний finding АЛЬ ХЭДИЙН байгаа, мөн pod-ийн нэр нь Kubernetes-ийн үүсгэсэн дагавартай (эгшиггүй алфавит) таарсан үед л controller руу зөөгдөнө. Объект зохиохгүй, таамаглахгүй; тохирохгүй бол pod хэвээр үлдэнэ.
