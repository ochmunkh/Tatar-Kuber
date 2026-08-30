# MITRE ATT&CK mapping

> **Important — "may enable", not "detected".** TATAR-Kuber is a *posture / misconfiguration*
> tool, not a threat-detection tool. A finding here is a **weakness that could enable** an
> adversary technique — it is **not** evidence that the technique was executed. Mappings use the
> **MITRE ATT&CK for Containers** matrix and are intentionally framed as *exposure*.

Each mapping is curated in the canonical registry ([`schema/canonical-controls.yaml`](../schema/canonical-controls.yaml))
under a control's `attack:` field, so it is one source of truth across all scanners. Only
controls with a clear attack path are mapped — image CVEs, resource limits and probe hygiene are
**not** force-mapped (that would dilute the signal). The report surfaces per-finding technique
badges and an **ATT&CK exposure** summary (findings per tactic).

## Mappings (v1.x — lightweight)

| Canonical control | Weakness | ATT&CK technique | Tactic |
|---|---|---|---|
| TATAR-CON-001 | Privileged container | T1611 Escape to Host | Privilege Escalation |
| TATAR-CON-003 | Allow privilege escalation | T1611 Escape to Host | Privilege Escalation |
| TATAR-CON-005 | Host PID namespace shared | T1611 Escape to Host | Privilege Escalation |
| TATAR-CON-006 | Host network enabled | T1611 Escape to Host | Privilege Escalation |
| TATAR-SEC-001 | Secret in environment variable | T1552.007 Unsecured Credentials: Container API | Credential Access |
| TATAR-SEC-003 | Service-account token auto-mounted | T1528 Steal Application Access Token | Credential Access |
| TATAR-RBAC-001 | cluster-admin binding overuse | T1078 Valid Accounts | Privilege Escalation |
| TATAR-RBAC-002 | Wildcard permissions in role | T1078 Valid Accounts | Privilege Escalation |
| TATAR-NET-001 | Missing NetworkPolicy | T1046 Network Service Discovery | Discovery |
| TATAR-IMG-003 | Unpinned / `:latest` image | T1525 Implant Internal Image | Persistence |

Coming in v2 (see [ROADMAP.md](../ROADMAP.md)): full ATT&CK-for-Containers **tactic coverage
heatmap**, broader technique coverage, and CIS Kubernetes Benchmark / ISO 27001 compliance views
alongside ATT&CK — giving each finding a **technical (MITRE)**, **compliance (CIS/ISO)** and
**operational (severity)** lens.

---

# MITRE ATT&CK харгалзуулалт (Монгол)

> **Чухал — "боломжжуулна", "илрүүлсэн" биш.** TATAR-Kuber бол *posture / misconfiguration*
> багаж, threat-detection биш. Энд гарах finding нь халдлагын техникийг **боломжтой болгож
> болзошгүй сул тал** — тухайн техник **гүйцэтгэгдсэн** гэсэн нотолгоо **биш**. Харгалзуулалт нь
> **MITRE ATT&CK for Containers** матрицыг ашигладаг ба зориудаар *exposure* хүрээтэй.

Харгалзуулалт бүр canonical registry-д ([`schema/canonical-controls.yaml`](../schema/canonical-controls.yaml))
control-ийн `attack:` талбарт curate хийгдсэн тул бүх scanner дээр нэг эх сурвалж болно. Зөвхөн
халдлагын зам тодорхой control-уудыг харгалзуулсан — image CVE, resource limit, probe эрүүл ахуйд
**хүчээр наагаагүй** (тэр нь дохиог сулруулна). Тайланд finding бүрийн техник badge болон
**ATT&CK exposure** хураангуй (tactic тус бүрийн finding тоо) харагдана.

## Харгалзуулалт (v1.x — хөнгөн)

| Canonical control | Сул тал | ATT&CK техник | Tactic |
|---|---|---|---|
| TATAR-CON-001 | Privileged контейнер | T1611 Escape to Host | Privilege Escalation |
| TATAR-CON-003 | Privilege escalation зөвшөөрсөн | T1611 Escape to Host | Privilege Escalation |
| TATAR-CON-005 | Host PID namespace хуваалцсан | T1611 Escape to Host | Privilege Escalation |
| TATAR-CON-006 | Host network идэвхжсэн | T1611 Escape to Host | Privilege Escalation |
| TATAR-SEC-001 | Secret орчны хувьсагчид | T1552.007 Unsecured Credentials: Container API | Credential Access |
| TATAR-SEC-003 | Service-account token auto-mount | T1528 Steal Application Access Token | Credential Access |
| TATAR-RBAC-001 | cluster-admin binding хэтрүүлсэн | T1078 Valid Accounts | Privilege Escalation |
| TATAR-RBAC-002 | Role дахь wildcard эрх | T1078 Valid Accounts | Privilege Escalation |
| TATAR-NET-001 | NetworkPolicy дутуу | T1046 Network Service Discovery | Discovery |
| TATAR-IMG-003 | Тогтоогоогүй / `:latest` image | T1525 Implant Internal Image | Persistence |

v2-д нэмэгдэх (үз [ROADMAP.md](../ROADMAP.md)): бүрэн ATT&CK-for-Containers **tactic coverage
heatmap**, өргөн техник хамралт, мөн CIS Kubernetes Benchmark / ISO 27001 compliance харагдац —
finding бүрийг **техник (MITRE)**, **нийцэл (CIS/ISO)**, **үйл ажиллагаа (severity)** гэсэн 3
өнцгөөр харуулна.
