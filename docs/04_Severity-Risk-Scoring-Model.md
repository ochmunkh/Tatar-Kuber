# TATAR-Kuber

> Kubernetes Security Posture Assessment Framework  
> Engineering Document #4  
> Severity & Risk Scoring Model  
> v1.2 — Level 1 Finding Risk + Level 2 Cluster Score  
> Version 1.2  ·  кодтой тулгасан (2026-09-07)  
> Enkhbat.O — Security Analyst  
> 2026-07-24

<!-- Generated from 04_Severity-Risk-Scoring-Model.docx by scripts/docx-to-md.py -- do not edit by hand. -->
*Generated from `04_Severity-Risk-Scoring-Model.docx`. The Word document is canonical; regenerate with `python3 scripts/docx-to-md.py docs/04_Severity-Risk-Scoring-Model.docx`.*

## 1. Зорилго

Auditor болон CISO-д тайлбарлаж болох, давтагдах, өрөөсгөлгүй эрсдэлийн оноо гаргах нь энэ загварын зорилго. Хоёр асуудлыг шийднэ: (1) scanner бүрийн өөр severity шатыг нэг стандарт руу хөрвүүлэх; (2) эрсдэлийг ХОЁР ТҮВШИНД тооцох — Level 1 (finding бүрийн эрсдэл) ба Level 2 (cluster-ийн ерөнхий оноо). "Яагаад энэ оноо гарсан бэ?" гэдэгт finding болон canonical control бүр рүү задрах чадвартай.

## 2. Severity normalization матриц

Scanner бүр өөр severity илэрхийлдэг. Дараах хүснэгтээр TATAR-ийн 5 түвшинд буулгана.

| **TATAR** | **Trivy (CVSS/severity)** | **Kubescape** | **Checkov** | **Popeye (severity өгдөггүй)** |
|---|---|---|---|---|
| CRITICAL | CRITICAL (CVSS ≥ 9.0) | Critical / score ≥ 9 | — | — |
| HIGH | HIGH (7.0–8.9) | High / 7–8.9 | severity HIGH | — |
| MEDIUM | MEDIUM (4.0–6.9) | Medium / 4–6.9 | severity MEDIUM | — |
| LOW | LOW (0.1–3.9) | Low / \< 4 | severity LOW | — |
| INFO | UNKNOWN / informational | manual review | INFO | — |

**Тэмдэглэл: Popeye-ийн level (0–3) нь ЛИНТЕРИЙН зэрэглэл (ok/info/warn/error), аюулгүй байдлын severity БИШ. Тиймээс v1.0.1-ээс хойш түүнийг severity болгож хөрвүүлэхээ БОЛИВ — canonical control-ийн curated default_severity дийлнэ, level нь нотолгоонд (evidence.value = "popeye warning") ил үлдэнэ. Ерөнхий дүрэм: adapter нь ЗӨВХӨН scanner бодит аюулгүй байдлын severity өгдөг үед (Trivy AVD/CVE, Checkov) severity дамжуулна. Checkov policy бүр severity-тэй биш тул байхгүй үед default_severity-г canonical registry-ээс авна.**

## 3. TATAR severity жин (base weight) — LOCK

Normalize хийсэн severity бүр CVSS-төст суурь жинтэй. Эдгээр нь Level 1 эрсдэл тооцох эх цэг.

| **Severity** | **Base weight** | **Тайлбар** |
|---|---|---|
| CRITICAL | 10 | Шууд ашиглаж болох, өндөр нөлөөтэй. |
| HIGH | 7 | Ноцтой, гэхдээ нэмэлт нөхцөл шаардаж болно. |
| MEDIUM | 3 | Дунд зэрэг эрсдэл. |
| LOW | 1 | Бага эрсдэл (доор pool-оор хязгаарлагдана). |
| INFO | 0 | Мэдээллийн зорилготой, оноонд нөлөөлөхгүй. |

## 4. Level 1 — Finding Risk Score

Finding бүрийн эрсдэл нь суурь жинг гурван контекст үржүүлэгчээр тохируулж гарна. Ингэснээр "production дахь internet-facing HIGH" нь "dev дэх internal LOW"-оос хамаагүй өндөр жинтэй болно.

```text
Finding Risk = base_weight × asset_context × exposure × confidence
```

### 4.1 Asset Context

| **Контекст** | **Үржүүлэгч** | **Илрүүлэх** |
|---|---|---|
| Production | 1.5 | namespace-ийн ТОКЕН бүтэн таарна: prod / production / prd / live (label env — v2) |
| Unknown | 1.0 | токен таарахгүй, эсвэл prod ба dev шинж хоёулаа байвал (дорд ч үнэлэхгүй, хөөрөгдөхгүй) |
| Development | 0.8 | dev / develop / test / stage / staging / qa / uat / sandbox / demo; мөн non-prod, pre-prod |

### 4.2 Exposure

| **Exposure** | **Үржүүлэгч** | **Илрүүлэх** |
|---|---|---|
| Internet-facing | 1.5 | LoadBalancer, NodePort, Ingress (external), hostNetwork |
| Unknown | 1.0 | тодорхойгүй |
| Internal | 1.0 | ClusterIP only, internal-д хязгаарлагдсан |

### 4.3 Confidence Mapping — LOCK

Итгэлийн зэрэг нь finding хэр найдвартай болохыг илэрхийлнэ. Олон scanner баталсан бол false positive магадлал бага; зөвхөн контекстээс хамаарсан эвристик finding бол эргэлзээтэй.

| **Confidence** | **Multiplier** | **Тодорхойлолт** |
|---|---|---|
| HIGH | 1.2 | 2+ scanner баталсан, ЭСВЭЛ 1 scanner + deterministic шалгалт (CVE, тодорхой талбар) |
| MEDIUM | 1.0 | 1 scanner + эвристик шалгалт (canonical control-д heuristic: true) |
| LOW | 0.8 | Ямар ч scanner баталгаагүй — зөвхөн контекст/дүгнэлт |

### 4.4 Жишээ тооцоо

Privileged container, production, internet-facing, гурван scanner баталсан:

```text
Severity HIGH        = 7
Asset Context (prod) = 1.5
Exposure (internet)  = 1.5
Confidence (HIGH)    = 1.2

Finding Risk = 7 × 1.5 × 1.5 × 1.2 = 18.9
```

Энэ утга finding-ийн `risk_contribution` талбарт хадгалагдаж, Level 2 cluster онооны penalty болно.

## 5. Blind shot-ийн нөлөө

Blind shot finding нь **устгагдахгүй**. Оноо тооцохын өмнө severity нь downgrade хийгддэг (ихэвчлэн INFO болно), ингэснээр base weight 0 болж cluster оноонд нөлөөлөхгүй. Гэвч finding нь тайланд `original_severity` болон `blind_shot_reason`-тэйгээ ил үлдэнэ. Аудитор "юуг яагаад бууруулсан"-ыг бүрэн харна.

## 6. Level 2 — Cluster Security Score (0–100)

Dashboard дээр гарах ерөнхий оноо. v1.2.1-ээс DIMINISHING загвар: penalty өссөөр оноо жигд буурах ч хэзээ ч яг 0 болохгүй, эрэмбэ хадгалагдана. Шалтгаан: linear загвар (100 − P) нь penalty 100-д хүрэхэд SATURATE болж "дөнгөж босго давсан" ба "гамшигт" cluster хоёрыг ялгахаа болино.

```text
Security Score = 100 / (1 + Total Penalty / K)      # K = 100 (ScoreScale)

Total Penalty = Σ FindingRisk (CRITICAL/HIGH/MEDIUM)
              + min(10, Σ FindingRisk (LOW))     # LOW pool cap
Score нь 1..100 хооронд хязгаарлагдана (хэзээ ч 0 болохгүй)
```

**LOW pool cap (10 оноо):** бүх LOW finding нийлээд хамгийн ихдээ 10 оноо л хасна. Ингэснээр "100 LOW" нь оноог үерлүүлэхгүй бөгөөд critical/high давамгайлна.

## 7. Тайлбарлах чадвар — CISO breakdown

"Яагаад 62 болсон бэ?" гэсэн асуултад тайлан оноог canonical control бүр рүү задална:

| **Canonical Control** | **Асуудал** | **Penalty** |
|---|---|---|
| TATAR-CON-001 | Privileged container | 18.9 |
| TATAR-RBAC-002 | Wildcard permission | 15.75 |
| TATAR-NET-001 | Missing NetworkPolicy | 3.0 |
| … (LOW pool) | Бусад бага асуудлууд | 10.0 (cap) |
|   | Total Penalty | ≈ 48 |
|   | Security Score | ≈ 68  (100/(1+48/100)) |

Үржүүлэгч бүр (context/exposure/confidence) ил байх тул CISO-д "энэ HIGH яагаад бодит жинтэй болсон"-ыг зөвтгөж болно.

## 8. Эрсдэлийн зурвас (Risk Band)

| **Оноо** | **Band** | **Тайлбар** |
|---|---|---|
| 90–100 | Excellent | Маш цөөн/бага эрсдэл. |
| 70–89 | Good | Хүлээн зөвшөөрөгдөх, тодорхой сайжруулалттай. |
| 50–69 | Fair | Анхаарал шаардсан асуудлууд бий. |
| 30–49 | Poor | Ноцтой эрсдэл, яаралтай арга хэмжээ. |
| 0–29 | Critical | Ноцтой байдал, шуурхай залруулга шаардлагатай. |

## 9. Ажилласан жишээ

Хоёр cluster-ийг харьцуулъя — загвар тэдгээрийг ялгаж чадаж байгааг харуулна.

#### Cluster A: 100 LOW (dev, internal, 1 scanner) + 1 CRITICAL (prod, internal, 1 scanner)

```yaml
CRITICAL: 10 × 1.5(prod) × 1.0(internal) × 1.0(MEDIUM conf) = 15.0
100× LOW: 1 × 0.8(dev) × 1.0 × 1.0 = 0.8 each ×100 = 80 → min(10,80)=10
Total Penalty = 15 + 10 = 25   →   Score = 100/(1+25/100) = 80  (Good)
```

#### Cluster B: 10 HIGH (prod, internet-facing, 1 scanner)

```yaml
HIGH: 7 × 1.5(prod) × 1.5(internet) × 1.0(MEDIUM conf) = 15.75 each ×10 = 157.5
Total Penalty = 157.5   →   Score = 100/(1+157.5/100) = 39  (Poor)
```

**Дүн: Cluster A = 80 (Good), Cluster B = 39 (Poor). Загвар production-д ил гарсан 10 HIGH-ийг нэг critical + олон бага асуудлаас илт ноцтойгоор ялгаж байна. Diminishing загвар нь Cluster B-г 0 болгож "цаашид дордохгүй" гэсэн дүр төрх үүсгэхийн оронд 39 гэж үнэлж, дараагийн 10 HIGH нэмэгдвэл оноо дахин буурах орон зай үлдээнэ. LOW pool cap нь бага асуудлын үерийг хазаарлана. Бүх жин, cap ба K-г тохируулж болох ч анхны утгыг энд түгжсэн.**

## Хувилбарын тэмдэглэл — v1.1 / v1.2 (2026-09-07)

- **• §2 severity normalization: Popeye-ийн level -\> TATAR severity хөрвүүлэлт УСТСАН. Линтерийн log-level нь аюулгүй байдлын severity биш; canonical control-ийн curated default_severity дийлнэ. Өмнөх хүснэгтээр dead service (popeye level 3) нь HIGH болж байсан ч registry түүнийг зориудаар INFO гэж үнэлдэг — тайлан болон эрсдэлийн онооны хоёуланг хөөрөгдөж байв.**
- **• §6 Level 2: linear (100 − P) -\> diminishing 100/(1 + P/K), K=100. §9-ийн ажилласан жишээ дахин тооцоологдов (Cluster A 75 -\> 80, Cluster B 0 -\> 39). Оноо хэзээ ч 0 болохгүй, 1..100.**
- **• §4.3 Confidence: scanner тооноос гадна шалгалтын determinism-ийг тооцно. 2+ scanner -\> HIGH; 1 scanner + deterministic -\> HIGH; 1 scanner + эвристик -\> MEDIUM; 0 -\> LOW.**
- **• Тайлан одоо оноог хэрхэн гаргасны бүрэн задаргааг агуулна: finding бүрт risk_factors (base_weight × asset_context × exposure × confidence) ба cluster-д risk_breakdown (high_penalty, low_penalty_raw/capped, scale, formula, top_contributors).**

**(v1.2) §4.1 Asset Context: namespace-ийг ТОКЕНООР (- _ . -аар хуваан) тааруулна. v1.0.2 хүртэл strings.Contains ашигласнаас "non-prod", "nonprod", "reproduction" нь production (1.5x) гэж үнэлэгдэж, dev namespace-ийн эрсдэлийг ~87%-иар хөөрөгдөж байв; "device" нь dev (0.8x) болж эсрэгээр дорд үнэлэгдэж байв. Одоо non-/pre- үгүйсгэлийг тооцно, эргэлзээтэй үед Unknown (1.0).**
