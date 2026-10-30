<!-- ҮҮСГЭСЭН ФАЙЛ — гараар засахгүй.
     Эх сурвалж: schema/canonical-controls.yaml
     Шинэчлэх:   go test ./internal/canonical/ -run TestCoverageDoc -update -->

# Control coverage

Which canonical controls TATAR-Kuber actually checks, and with which scanner rules.

A control with no rule mapped to it is **not checked** — it is a placeholder, and it
is listed here rather than hidden. Numbers are how many scanner rule IDs map to that
control, so a higher number is not "better": it means that scanner spells the same
issue several ways.

Энэ бол үүсгэсэн баримт: аль control бодитоор шалгагддаг, алийг нь огт шалгадаггүйг
ил гаргана. Rule зураглагдаагүй control нь **шалгагддаггүй** — нуулгүй энд гарна.

## Summary

| | |
|---|---|
| Controls in the registry | **33** |
| Checked by at least one scanner | **32** |
| **Not checked** (no rule mapped) | **1** |
| Heuristic (context-dependent, lower confidence) | 2 |
| Registry schema / last updated | 1.0 / 2026-10-18 |

| Scanner | Controls it can reach | Rule IDs mapped |
|---|---:|---:|
| trivy | 19 | 25 |
| kubescape | 24 | 35 |
| checkov | 19 | 28 |
| popeye | 10 | 15 |

## Not checked

These controls exist in the registry but no scanner rule maps to them. They are reported by no scan.

- **TATAR-NET-004** — Ingress without TLS

## Matrix

Each cell is the number of scanner rule IDs mapped to that control.

### Container Security

| Control | Title | Severity | Trivy | Kubescape | Checkov | Popeye |
|---|---|---|---:|---:|---:|---:|
| `TATAR-CON-001` | Privileged container enabled | HIGH | 1 | 1 | 1 | — |
| `TATAR-CON-002` | Container running as root | MEDIUM | 1 | 1 | 1 | 2 |
| `TATAR-CON-003` | Allow privilege escalation | HIGH | 1 | 1 | 1 | — |
| `TATAR-CON-004` | Dangerous capabilities added | HIGH | 3 | 1 | 4 | — |
| `TATAR-CON-005` | Host PID namespace shared | HIGH | 1 | 1 | 1 | — |
| `TATAR-CON-006` | Host network enabled | HIGH | 1 | 1 | 1 | — |
| `TATAR-CON-007` | Host filesystem mounted (hostPath) | HIGH | 1 | 1 | — | — |
| `TATAR-CON-008` | Missing securityContext | MEDIUM | 1 | 1 | 1 | — |
| `TATAR-CON-009` | Read-only root filesystem disabled | MEDIUM | 1 | 1 | 1 | — |
| `TATAR-CON-010` | Missing CPU/memory limits | LOW | 4 | 3 | 4 | 2 |
| `TATAR-CON-011` | Default seccomp profile not set | MEDIUM | 2 | 1 | 1 | — |

### RBAC & Authorization

| Control | Title | Severity | Trivy | Kubescape | Checkov | Popeye |
|---|---|---|---:|---:|---:|---:|
| `TATAR-RBAC-001` | cluster-admin binding overuse | CRITICAL | — | 3 | — | — |
| `TATAR-RBAC-002` | Wildcard permissions in role | HIGH | — | 1 | 1 | — |
| `TATAR-RBAC-003` | Excessive / risky permissions *(heuristic)* | HIGH | — | 8 | 4 | — |
| `TATAR-RBAC-004` | Anonymous / unauthenticated access | HIGH | — | 1 | — | — |
| `TATAR-RBAC-005` | Default service account in use | MEDIUM | — | — | — | 1 |

### Network Security

| Control | Title | Severity | Trivy | Kubescape | Checkov | Popeye |
|---|---|---|---:|---:|---:|---:|
| `TATAR-NET-001` | Missing NetworkPolicy | MEDIUM | 1 | 1 | 1 | 1 |
| `TATAR-NET-002` | No default-deny NetworkPolicy | HIGH | — | 1 | — | — |
| `TATAR-NET-003` | Service exposed externally *(heuristic)* | MEDIUM | — | 1 | — | — |
| `TATAR-NET-004` | Ingress without TLS | HIGH | — | — | — | — |

### Image Security

| Control | Title | Severity | Trivy | Kubescape | Checkov | Popeye |
|---|---|---|---:|---:|---:|---:|
| `TATAR-IMG-001` | Critical CVE in container image | CRITICAL | 1 | — | — | — |
| `TATAR-IMG-002` | High CVE in container image | HIGH | 1 | — | — | — |
| `TATAR-IMG-003` | Image uses :latest tag | MEDIUM | 1 | — | 1 | 2 |
| `TATAR-IMG-004` | Image from unapproved registry | MEDIUM | — | 1 | — | — |

### Secret Management

| Control | Title | Severity | Trivy | Kubescape | Checkov | Popeye |
|---|---|---|---:|---:|---:|---:|
| `TATAR-SEC-001` | Secret exposed in environment variable | HIGH | 1 | 1 | 1 | — |
| `TATAR-SEC-002` | Hardcoded secret in image/manifest | HIGH | 1 | — | — | — |
| `TATAR-SEC-003` | Service account token auto-mounted | MEDIUM | 1 | 1 | 1 | 1 |
| `TATAR-SEC-004` | Sensitive data in ConfigMap | MEDIUM | 1 | — | — | — |

### Operational Health

| Control | Title | Severity | Trivy | Kubescape | Checkov | Popeye |
|---|---|---|---:|---:|---:|---:|
| `TATAR-OPS-001` | Missing readiness probe | LOW | — | 1 | 1 | 1 |
| `TATAR-OPS-002` | Missing liveness probe | LOW | — | 1 | 1 | 1 |
| `TATAR-OPS-003` | Orphan / dead service (no endpoints) | INFO | — | — | — | 2 |
| `TATAR-OPS-004` | Unused ConfigMap / Secret | INFO | — | — | — | 2 |
| `TATAR-OPS-005` | imagePullPolicy not set correctly | LOW | — | 1 | 1 | — |

---

A scanner column being empty does not mean that scanner is broken — most rules exist in one tool only. What matters is the **Not checked** section above, and that every scanner listed as reachable actually produces findings in the daily live run (`.github/workflows/real-cluster.yml`).
