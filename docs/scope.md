# TATAR-Kuber — features, scope and positioning

What the tool covers, what it deliberately does not, and what to run beside it.

English · [Монгол](#монгол-хэл-дээр)

---

## Features

- **Live Mode B** — scans a running cluster (read-only) by orchestrating the real scanner CLIs
- Local (Mode A) + **offline ingest** of pre-collected raw output
- **Parallel adapters** — scanners run concurrently, each with its own timeout; one failing scanner never drops the others (graceful degradation), output stays deterministic
- **Canonical Control Mapping** — every scanner's rule IDs unified into stable `TATAR-*` controls
- **Deduplication** — merges the same issue across scanners; keeps `found_by` + evidence
- **Confidence engine** — multi-scanner agreement and check determinism (a Trivy-only CVE is still HIGH)
- **Blind-shot engine** — context-aware severity down-grade (never suppresses; stays visible)
- **Explainable risk scoring v1.2.1** — per-finding `risk_factors` (base × context × exposure × confidence) + a cluster `risk_breakdown` with formula and top contributors
- **MITRE ATT&CK for Containers** — findings map to the adversary techniques they *may enable* (e.g. privileged container → T1611 Escape to Host), with a per-tactic **ATT&CK exposure** summary. Framed as exposure, **not** detection — see [`docs/MITRE_ATTACK.md`](MITRE_ATTACK.md)
- **CI/CD gatekeeper** — `.tatar-kuber.yaml` policy (`fail_on`, `min_score`, `suppress` with expiry) + `gate` command + GitHub Action + SARIF upload to Code Scanning
- **Reports** — JSON · SARIF 2.1.0 (GitHub/GitLab/Azure) · HTML dashboard (bilingual)
- **verify-lab** — regression check against an expected-findings baseline
- **Self-contained binary** — canonical registry embedded; `brew` / `curl | sh` / Docker

## Scope & positioning

TATAR-Kuber focuses on **security posture, configuration, IaC, image and RBAC analysis
with unified reporting**. It is **complementary to — not a replacement for** — runtime
detection, admission control and secrets management. Run it *alongside* Falco/Tetragon,
Kyverno/OPA and Vault for full coverage.

**In scope**

| Domain | | Notes |
|---|:--:|---|
| Cluster configuration & posture | ✅ | via Kubescape / Trivy (live Mode B) |
| Kubernetes misconfiguration | ✅ | Trivy · Kubescape · Checkov |
| RBAC security | ✅ | excessive permissions, wildcard, cluster-admin |
| Pod / Workload security | ✅ | privileged, hostPath, capabilities, runAsRoot… |
| Image vulnerabilities | ✅ | CVEs via Trivy |
| IaC security | ✅ | YAML / Helm (Terraform partial, via Checkov) |
| Compliance mapping | ✅ | NSA / CIS / MITRE refs via canonical controls (partial) |
| Reporting & risk scoring | ✅ | dedup, risk score, JSON / SARIF / HTML |
| Runtime hygiene | ⚠️ | Popeye (dead / unused / broken refs) — not threat detection |

**Out of scope (by design) — use alongside**

| Not covered | Use instead |
|---|---|
| Runtime threat detection | Falco · Tetragon |
| Network traffic monitoring (eBPF) | Cilium/Hubble · Falco |
| Container behavioral detection | Falco · Tetragon |
| Admission control (block deploys) | Kyverno · OPA Gatekeeper |
| Secrets management | HashiCorp Vault · External Secrets |

---

## Монгол хэл дээр

### Онцлог

- **Live Mode B** — ажиллаж буй cluster-ийг (read-only) бодит scanner CLI-ууд ажиллуулан шалгана
- Local (Mode A) + **offline ingest** (урьдчилан цуглуулсан raw)
- **Parallel adapters** — scanner-ууд зэрэг ажиллана, тус бүр өөрийн timeout-той; нэг нь унахад бусад нь үргэлжилнэ (graceful degradation), гаралт нь тогтмол, давтагдахуйц хэвээр
- **Canonical Control Mapping** — scanner бүрийн rule ID-г нэг `TATAR-*` control руу
- **Deduplication** — олон scanner-ийн ижил асуудлыг нэгтгэж `found_by`-г хадгална
- **Confidence engine** — олон scanner-ийн санал нийлэлт + determinism (Trivy ганц CVE ч HIGH)
- **Blind-shot engine** — контекстээр severity бууруулна (устгахгүй, ил үлдэнэ)
- **Тайлбарлагдах risk scoring v1.2.1** — finding бүрийн `risk_factors` (суурь × орчин × ил гарц × итгэл) + cluster `risk_breakdown` (томьёо + топ хувь нэмэгчид)
- **MITRE ATT&CK for Containers** — finding нь ямар халдлагын техникийг *боломжжуулж* болзошгүйг харуулна (ж: privileged контейнер → T1611 Escape to Host), tactic тус бүрээр **ATT&CK exposure** хураангуйтай. "Илрүүлсэн" биш, "боломжжуулна" хүрээтэй — үз [`docs/MITRE_ATTACK.md`](MITRE_ATTACK.md)
- **CI/CD gatekeeper** — `.tatar-kuber.yaml` бодлого (`fail_on`, `min_score`, хугацаатай `suppress`) + `gate` команд + GitHub Action + SARIF upload
- **Reports** — JSON · SARIF 2.1.0 · HTML dashboard (хоёр хэлт)
- **verify-lab** — expected baseline-тай тулгаж regression шалгах
- **Дангаар ажиллах binary** — canonical registry шигтгэсэн; `brew` / `curl | sh` / Docker

### Хамрах хүрээ (Scope)

TATAR-Kuber нь **posture / configuration / IaC / image / RBAC + нэгдсэн тайлан**-д
төвлөрдөг. Runtime threat detection (Falco/Tetragon), admission control (Kyverno/OPA),
secrets management (Vault)-ыг **орлохгүй — тэдгээртэй хамт ажилладаг (complementary).**

**Хийдэг**

| Домэйн | | Тайлбар |
|---|:--:|---|
| Cluster configuration & posture | ✅ | Kubescape / Trivy (live Mode B) |
| Kubernetes misconfiguration | ✅ | Trivy · Kubescape · Checkov |
| RBAC аюулгүй байдал | ✅ | хэт их эрх, wildcard, cluster-admin |
| Pod / Workload аюулгүй байдал | ✅ | privileged, hostPath, capabilities, runAsRoot… |
| Image эмзэг байдал | ✅ | Trivy CVE |
| IaC аюулгүй байдал | ✅ | YAML / Helm (Terraform хэсэгчлэн, Checkov) |
| Compliance mapping | ✅ | NSA / CIS / MITRE (canonical, хэсэгчлэн) |
| Тайлан & risk scoring | ✅ | dedup, оноо, JSON / SARIF / HTML |
| Runtime hygiene | ⚠️ | Popeye — threat detection БИШ |

**Хамрахгүй (зориудаар) — хамт ашиглана**

| Хамрахгүй | Оронд нь |
|---|---|
| Runtime threat detection | Falco · Tetragon |
| Network traffic monitoring (eBPF) | Cilium/Hubble · Falco |
| Container behavioral detection | Falco · Tetragon |
| Admission control (deploy блоклох) | Kyverno · OPA Gatekeeper |
| Secrets management | HashiCorp Vault · External Secrets |
