# Examples

**`demo/`** — a small, self-contained set of **real scanner output** (Trivy · Kubescape · Checkov ·
Popeye) so you can run the full TATAR-Kuber pipeline offline — no cluster, no scanner install:

```bash
tatar-kuber scan   --raw-dir examples/demo -o out
tatar-kuber report --input out/scan-result.json -o html --out report.html
```

This is the dataset used by the committed `report/` example, the
[GitHub Pages demo](https://ochmunkh.github.io/Tatar-Kuber/) and the `security-gate` CI workflow.
Its headline story: a privileged container on `deployment/api` flagged by **three** scanners
(→ `found_by=[checkov,kubescape,trivy]`, `confidence=HIGH`, `attack=[T1611]`).

**`report/`** — a committed, ready-to-open example report (HTML 🇬🇧/🇲🇳 + SARIF + JSON) generated
from `demo/`.

## `examples/demo` vs the lab (not a duplicate)

For the **full training + regression corpus** — vulnerable & hardened manifests, richer scenarios
and the `expected-findings.json` baseline for `tatar-kuber verify-lab` — see the companion repo
**[tatar-kuber-lab](https://github.com/ochmunkh/tatar-kuber-lab)**.

The two are **intentionally separate, not duplicated**:

| | `examples/demo` (here) | `tatar-kuber-lab` (companion repo) |
|---|---|---|
| Purpose | minimal **embedded** demo shipped in the engine | full **training + regression** corpus |
| Ships with | the engine repo (for CI, Pages, quick start) | its own repo (manifests + baseline) |
| Story | privileged on `deployment/api` (3 scanners) | many `broken/` vs `fixed/` manifests |

---

## Монгол

**`demo/`** — Trivy · Kubescape · Checkov · Popeye-ийн **бодит scanner гаралт**-ын жижиг,
дангаараа ажилладаг багц — cluster/суулгацгүйгээр бүтэн pipeline-ийг offline ажиллуулна.
Committed `report/`, [GitHub Pages demo](https://ochmunkh.github.io/Tatar-Kuber/), `security-gate`
CI үүнийг ашигладаг. Гол түүх: `deployment/api` дээрх privileged контейнерыг **3 scanner** олсон
(→ `found_by=[checkov,kubescape,trivy]`, `confidence=HIGH`, `attack=[T1611]`).

**`report/`** — `demo/`-оос үүсгэсэн, нээхэд бэлэн жишээ тайлан (HTML 🇬🇧/🇲🇳 + SARIF + JSON).

Бүрэн сургалт + regression corpus (эмзэг/hardened manifest, `verify-lab`-ийн baseline)-ыг
[**tatar-kuber-lab**](https://github.com/ochmunkh/tatar-kuber-lab)-аас үз. Хоёулаа **зориудаар
тусдаа, давхардал биш**: `examples/demo` нь engine-д шигтгэсэн жижиг demo; lab нь бүрэн corpus.
