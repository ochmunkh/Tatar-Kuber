# TATAR-Kuber

**English** · [Монгол](README.mn.md)

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-security-326CE5?logo=kubernetes&logoColor=white)
![Scanners](https://img.shields.io/badge/scanners-Trivy%20%C2%B7%20Kubescape%20%C2%B7%20Checkov%20%C2%B7%20Popeye-2A4D69)
![Output](https://img.shields.io/badge/output-JSON%20%C2%B7%20SARIF%20%C2%B7%20HTML-1F6F54)
[![CI](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/ci.yml/badge.svg)](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/ci.yml)
[![Real cluster](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/real-cluster.yml/badge.svg)](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/real-cluster.yml)
![Tests](https://img.shields.io/badge/tests-23%20packages%20green-brightgreen)
![Release](https://img.shields.io/badge/release-v1.0.6-brightgreen)

**Kubernetes security posture assessment — one command, four scanners, one report.**

TATAR-Kuber is not a scanner. It runs **Trivy · Kubescape · Checkov · Popeye**, maps their
different rule IDs onto one set of **canonical controls**, merges duplicates ("3 scanners found
1 issue", not "3 findings"), scores the risk, and writes a single report — **JSON, SARIF or
HTML, in English or Mongolian** — that engineers, auditors and managers can all read.

```bash
tatar-kuber scan   --kubeconfig ~/.kube/config --out-dir out     # live cluster, read-only
tatar-kuber scan   --raw-dir ./raw --out-dir out                 # or: offline, from saved scanner output
tatar-kuber report --input out/scan-result.json --format html --out report.html
```

## Report — one issue, every scanner, both languages

The same scan rendered in **English** and **Mongolian** (`--lang en|mn`). Note
`found_by = checkov · kubescape · trivy` on the privileged container: one finding, three tools
agreeing, with confidence, evidence and remediation.

![TATAR-Kuber report — English](docs/img/report-en.jpg)

![TATAR-Kuber тайлан — Монгол](docs/img/report-mn.jpg)

See a real report without installing anything: **https://ochmunkh.github.io/Tatar-Kuber/**
([English](https://ochmunkh.github.io/Tatar-Kuber/report.html) ·
[Монгол](https://ochmunkh.github.io/Tatar-Kuber/report-mn.html) ·
[SARIF](https://ochmunkh.github.io/Tatar-Kuber/tatar-kuber.sarif)), or open the files in
[`examples/report/`](examples/report).

## How it works

![TATAR-Kuber architecture](docs/img/architecture.png)

```
sources → scanners (parallel) → normalize → canonical + dedup → blind-shot → risk score → report → CI gate
```

1. **Collect.** From a live cluster (read-only), local manifests (`-f`), or saved scanner output (`--raw-dir`).
   The four scanners run in parallel, each with its own timeout; if one fails the others still finish.
2. **Normalize.** Every scanner's rule IDs become stable `TATAR-*` controls.
3. **De-duplicate.** The same issue seen by several scanners becomes one finding with `found_by` and a confidence level.
   Example: Trivy `AVD-KSV0017`, Kubescape `C-0057` and Checkov `CKV_K8S_16` are all the same privileged
   container → one `TATAR-CON-001` on `deployment/api`, confidence HIGH. See [`docs/dedup-example.md`](docs/dedup-example.md).
4. **Score.** Risk is explainable: every finding carries its factors, and the cluster score shows its formula and top contributors.
   Findings that are only reachable in unusual contexts are down-graded, never hidden.
5. **Report and gate.** JSON, SARIF 2.1.0 and a bilingual HTML dashboard; a `gate` command fails a pipeline when a policy is broken.

Design rules: **read-only first** (`get`/`list`/`watch` only), **scanner agnostic** (adapters are pluggable),
**honest about gaps** (a control no scanner checks is listed as *not checked*, never counted as passed).

## Install

```bash
# Homebrew (macOS / Linux)
brew install ochmunkh/tap/tatar-kuber

# Linux / macOS — downloads the release binary and verifies its checksum
curl -fsSL https://raw.githubusercontent.com/ochmunkh/Tatar-Kuber/master/install.sh | sh

# Docker
docker run --rm -v "$PWD:/work" -w /work ghcr.io/ochmunkh/tatar-kuber:latest \
    scan --raw-dir ./raw --out-dir .

# From source
go install github.com/ochmunkh/tatar-kuber/cmd/tatar-kuber@latest
```

For live scanning the four scanners must be installed. `tatar-kuber doctor` shows which are, and
`tatar-kuber update` installs the pinned versions after verifying each checksum.

## Quick start (offline, no cluster, no scanner install)

This repository ships real scanner output in [`examples/demo`](examples/demo), so the whole
pipeline runs in about 30 seconds:

```bash
git clone https://github.com/ochmunkh/Tatar-Kuber && cd Tatar-Kuber
tatar-kuber scan   --raw-dir examples/demo --out-dir out
tatar-kuber report --input out/scan-result.json --format html --out report.html
tatar-kuber report --input out/scan-result.json --format html --lang mn --out report-mn.html
```

`--lang` re-renders the report, so switching language never re-runs the scanners or touches the
cluster. The CLI itself speaks English by default; `--lang mn` or `TATAR_LANG=mn` switches it to Mongolian.
A larger regression corpus (vulnerable and hardened manifests) lives in
[**tatar-kuber-lab**](https://github.com/ochmunkh/tatar-kuber-lab).

## Scanners

| Scanner | Purpose | Live-tested with |
|---|---|---|
| Trivy | Image CVEs, secrets, misconfiguration | 0.76 |
| Kubescape | NSA / MITRE / RBAC / compliance (primary posture engine) | 4.0 |
| Checkov | IaC (YAML / Helm / Terraform) | 3.4 |
| Popeye | Runtime hygiene (dead service, unused, broken reference) | 0.22 |

The versions are the ones pinned in [`tools.lock.yaml`](tools.lock.yaml) and exercised daily by the
[real-cluster workflow](.github/workflows/real-cluster.yml). A scanner that renames a flag shows up as
`error` / `unavailable` in the report's *Scanner coverage* table, not as a silent zero.

## Commands

| Command | What it does |
|---|---|
| `scan` | Run the scanners (or read `--raw-dir`) and write `scan-result.json`; live scans also keep the raw scanner output as evidence |
| `report` | Render a result as `json`, `sarif`, `html`, `audit` or `pdf` (`--format`, `--lang`) |
| `gate` | Fail (exit 1) when the result breaks the policy in `.tatar-kuber.yaml` (`--fail-on`, `--baseline`) |
| `diff` | What is new, fixed or worse between two scans |
| `top` | What to fix first: the worst workloads and the controls that hit the most resources |
| `attest` | A person's signed answer, with an expiry, for controls no scanner checks |
| `doctor`, `update` | Which scanners are installed; install the pinned versions |

Every command takes `--lang en|mn`. Exit codes: `0` ok, `1` policy violated, `2` runtime error,
`3` usage error. Full flags, exit codes and the read-only RBAC for live scans:
[`docs/cli.md`](docs/cli.md).

## CI/CD gate

Add a `.tatar-kuber.yaml` ([example](.tatar-kuber.yaml.example)) and gate the pipeline, or use the GitHub Action:

```yaml
- uses: ochmunkh/Tatar-Kuber@v1
  with:
    raw-dir: ./raw      # or path: ./k8s
    fail-on: high
```

The first scan of a real cluster returns a lot, and a gate that fails on all of it on day one gets
switched off. Accept today's findings with a **baseline** (`gate --baseline`) and fail only on new or
worse ones; accept single findings with a reason and an expiry date through `suppress`. How, with
examples: [`docs/gate.md`](docs/gate.md).

## Security

A security tool should hold itself to the standard it enforces. In short:

- **Read-only.** The cluster role grants only `get` / `list` / `watch`, and does not include Secrets.
- **Small supply chain.** One direct dependency (`gopkg.in/yaml.v3`); every GitHub Action and container image is pinned; `govulncheck` and `gosec` run on every push.
- **Scanners are untrusted programs.** The report records which binary ran and its SHA-256; a binary changed after `update` verified it is not run; forge credentials are not passed to scanners; raw output carries a `SHA256SUMS` manifest.
- **The gate checks its input.** A `scan-result.json` that disagrees with itself is refused. This is a consistency check, not a signature.
- **Inputs are bounded and output is owner-only** (mode `0600`).

Details and the network behaviour measured for each scanner: [`docs/security.md`](docs/security.md).
Found a vulnerability? See [`SECURITY.md`](SECURITY.md) — GitHub's **Security → Report a vulnerability** (private disclosure).

## Scope

TATAR-Kuber covers **posture, configuration, IaC, image and RBAC analysis with unified reporting**. It is
**complementary to** runtime detection, admission control and secrets management — run it alongside
Falco/Tetragon, Kyverno/OPA and Vault, not instead of them. Features, what is and is not covered:
[`docs/scope.md`](docs/scope.md). Every control against every scanner, including the one no scanner
checks: [`docs/coverage.md`](docs/coverage.md).

## Build

```bash
go build ./...
go test ./...          # 23 packages, all green
./scripts/build.sh 1.0.6
```

## Documentation

Six engineering documents in `docs/` as **Word (`.docx`) files** (GitHub does not render them in the browser):
[01 Unified Schema](docs/01_Unified-Schema-JSON-v1.docx) ·
[02 Canonical Mapping](docs/02_Canonical-Control-Mapping.docx) ·
[03 Scanner Adapter Interface](docs/03_Scanner-Adapter-Interface.docx) ·
[04 Severity & Risk Scoring](docs/04_Severity-Risk-Scoring-Model.docx) ·
[05 CLI Spec](docs/05_CLI-Specification.docx) ·
[06 Repository Structure](docs/06_Repository-Structure.docx).
Guides in Markdown: [commands](docs/cli.md) · [CI gate](docs/gate.md) · [security model](docs/security.md) ·
[scope](docs/scope.md) · [coverage](docs/coverage.md). The JSON Schema of `scan-result.json` is
[`pkg/schema/tatar-schema-v1.json`](pkg/schema/tatar-schema-v1.json). Release notes: [`docs/releases/`](docs/releases).

## Status

**v1.0.6** — see [`docs/releases/`](docs/releases) for what each release changed and [`ROADMAP.md`](ROADMAP.md)
for what comes next. Every mapped rule of all four scanners is pinned by a test against the scanner's own
definition, so a scanner renaming or renumbering a check fails the build.

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and
[`docs/03_Scanner-Adapter-Interface.docx`](docs/03_Scanner-Adapter-Interface.docx); please keep `go test ./...`
green and read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Contact

**Author:** Enkhbat Oyunbayar — Security Analyst

[![Facebook](https://img.shields.io/badge/Facebook-Enkhbat%20Oyunbayar-1877F2?logo=facebook&logoColor=white)](https://www.facebook.com/enkhbat.o/)
[![GitHub](https://img.shields.io/badge/GitHub-ochmunkh-181717?logo=github&logoColor=white)](https://github.com/ochmunkh)

## License

Apache-2.0 — see [LICENSE](LICENSE).
