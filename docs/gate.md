# TATAR-Kuber — CI/CD gate

Policy file, GitHub Action, and how to adopt the gate on a cluster that already has findings.

English · [Монгол](#монгол-хэл-дээр)

---

## CI/CD gate

Add a `.tatar-kuber.yaml` (see [`.tatar-kuber.yaml.example`](../.tatar-kuber.yaml.example)) and gate your pipeline, or use the GitHub Action:

```yaml
- uses: ochmunkh/Tatar-Kuber@v1
  with:
    raw-dir: ./raw      # or path: ./k8s
    fail-on: high
```

The action produces a SARIF file; upload it with `github/codeql-action/upload-sarif` to see findings in the **Security → Code scanning** tab (see [`.github/workflows/security-gate.yml`](../.github/workflows/security-gate.yml)).

### Adopting the gate on an existing cluster

The first scan of a real cluster returns a lot. A gate that fails on all of it on day one
gets switched off in a week, and a switched-off gate is not a gate. Two mechanisms exist so
that does not happen — use them in this order.

**1. Baseline — accept today, fail on tomorrow.** Keep the current scan as a reference and
let the gate count only what is new or has got worse:

```bash
tatar-kuber gate --input out/scan-result.json --baseline baseline/scan-result.json
```

Findings already in the baseline are not counted. Findings that were there but whose
severity has risen **are** counted — a LOW that becomes CRITICAL is new risk, not an old
problem. `min_score` stays absolute: it is a property of the cluster, not of the diff.

If the comparison cannot be trusted — a different cluster, a different mode, one side
scanned with `--no-rollup` — the baseline is **ignored** and every finding counts. A
security gate fails closed when it is unsure.

*Where to keep it.* Commit `baseline/scan-result.json` to the repo. It is a few hundred KB
of JSON, it belongs under review like any other accepted risk, and `git log` then answers
"when did we accept this, and who signed it off". A CI cache or artifact works too, but it
expires, and a baseline that silently disappears turns the gate red on a Monday for no
reason anyone can explain. Refresh it deliberately — a commit that moves the baseline is a
commit that says "we accept this list now".

**2. Suppression — accept one finding, with a reason and an expiry date.** For the handful
you decide to live with, name them in `.tatar-kuber.yaml`:

```yaml
suppress:
  - control: TATAR-CON-001
    resource: deployment/legacy-api
    reason: "Legacy system, migrating Q1 2027 (JIRA-1234)"
    expires: 2027-03-31
```

`expires` is not decoration: the rule stops applying on that date and the finding comes
back. A date that cannot be read (`2026-13-45`, `tomorrow`) is **not** "no expiry": the rule is
not applied and the gate says so. The gate also reports rules that have expired, rules
pointing at a control that does not exist, and rules that matched nothing — a suppression
nobody notices is how an accepted risk becomes a forgotten one.

Baseline is for the bulk at adoption; suppression is for the few you consciously keep.

---

## Монгол хэл дээр

### Байгаа кластерт gate нэвтрүүлэх

Бодит кластерын анхны шалгалт олон зүйл буцаана. Эхний өдөр бүгдэд нь унадаг gate нэг
долоо хоногийн дараа унтраагдана — унтраасан gate бол gate биш. Ингэхээс сэргийлэх хоёр
механизм бий, энэ дарааллаар ашиглана.

**1. Baseline — өнөөдрийн төлөвийг хүлээн зөвшөөрч, маргаашийн өөрчлөлтийг шалгах.** Одоогийн шалгалтыг лавлагаа
болгож үлдээгээд, зөвхөн шинэ ба дордсоныг тооцуулна:

```bash
tatar-kuber gate --input out/scan-result.json --baseline baseline/scan-result.json
```

Baseline-д аль хэдийн байгаа олдвор тооцогдохгүй. Харин байсан атлаа severity нь өссөн бол
**тооцогдоно** — LOW нь CRITICAL болох нь шинэ эрсдэл, хуучин асуудал биш. `min_score` нь
үнэмлэхүй хэвээр: тэр бол кластерын шинж чанар, зөрүүнийх биш.

Харьцуулалт итгэх боломжгүй бол — өөр cluster, өөр горим, нэг тал нь `--no-rollup` —
baseline **хэрэгсэгдэхгүй**, бүх олдвор тооцогдоно. Аюулгүй байдлын gate эргэлзээтэй үедээ
fail-closed зарчмаар ажиллана.

*Хаана хадгалах вэ.* `baseline/scan-result.json`-ыг repo-д commit хийнэ. Хэдэн зуун KB JSON,
бусад хүлээн зөвшөөрсөн эрсдэлийн адил хянагдах ёстой, мөн `git log` нь "хэзээ, хэн үүнийг
зөвшөөрсөн" гэсэн асуултад хариулна. CI cache/artifact ч болно, гэхдээ хугацаа нь дуусдаг —
чимээгүй алга болсон baseline нь даваа гарагт gate-ийг хэн ч тайлбарлаж чадахгүйгээр улаан
болгоно. Шинэчлэхдээ зориудаар: baseline-ыг хөдөлгөсөн commit бол "бид энэ жагсаалтыг одоо
хүлээн зөвшөөрч байна" гэсэн мэдэгдэл.

**2. Suppress — нэг олдворыг шалтгаан ба хугацаатайгаар хүлээн зөвшөөрөх.** Ухамсартай
үлдээхээр шийдсэн цөөн эрсдэлийг `.tatar-kuber.yaml`-д нэрлэнэ:

```yaml
suppress:
  - control: TATAR-CON-001
    resource: deployment/legacy-api
    reason: "Хуучин систем, 2027 Q1-д шилжүүлнэ (JIRA-1234)"
    expires: 2027-03-31
```

`expires` нь чимэглэл биш: тэр өдөр дүрэм идэвхгүй болж, олдвор буцаж гарна. Мөн gate нь
хугацаа дууссан дүрэм, байхгүй control руу заасан дүрэм, юунд ч тохироогүй дүрмийг
мэдэгдэнэ — хэн ч анзаардаггүй suppress бол мартагдсан эрсдэл болох зам. Уншигдахгүй огноо
(`2026-13-45`, `tomorrow`) нь "хугацаагүй" гэсэн үг **биш**: дүрэм хэрэглэгдэхгүй, gate үүнийг
мэдэгдэнэ.

Baseline нь нэвтрүүлэх үеийн олон тоонд, suppress нь ухамсартай үлдээсэн цөөнд.
