# TATAR-Kuber

[English](README.md) · **Монгол**

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-security-326CE5?logo=kubernetes&logoColor=white)
![Scanners](https://img.shields.io/badge/scanners-Trivy%20%C2%B7%20Kubescape%20%C2%B7%20Checkov%20%C2%B7%20Popeye-2A4D69)
![Output](https://img.shields.io/badge/output-JSON%20%C2%B7%20SARIF%20%C2%B7%20HTML-1F6F54)
[![CI](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/ci.yml/badge.svg)](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/ci.yml)
[![Real cluster](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/real-cluster.yml/badge.svg)](https://github.com/ochmunkh/Tatar-Kuber/actions/workflows/real-cluster.yml)
![Tests](https://img.shields.io/badge/tests-23%20packages%20green-brightgreen)
![Release](https://img.shields.io/badge/release-v1.0.6-brightgreen)

**Kubernetes аюулгүй байдлын үнэлгээ — нэг команд, дөрвөн scanner, нэг тайлан.**

TATAR-Kuber өөрөө scanner биш. Энэ нь **Trivy · Kubescape · Checkov · Popeye**-ийг ажиллуулж, тэдний өөр
өөр rule ID-г нэг **canonical control**-ийн багц руу буулгаж, давхардлыг арилгаж ("3 scanner нэг асуудал
олсон" — 3 finding биш), эрсдэлийг үнэлээд нэг тайлан гаргана — **JSON, SARIF эсвэл HTML, англи эсвэл
монгол хэлээр**. Инженер, аудитор, удирдлага бүгд ойлгоно.

```bash
tatar-kuber scan   --kubeconfig ~/.kube/config --out-dir out     # ажиллаж буй cluster, зөвхөн унших
tatar-kuber scan   --raw-dir ./raw --out-dir out                 # эсвэл offline: хадгалсан scanner гаралтаас
tatar-kuber report --input out/scan-result.json --format html --lang mn --out report.html
```

Суулгалгүйгээр жинхэнэ тайлан үзэх: **https://ochmunkh.github.io/Tatar-Kuber/**
([Англи](https://ochmunkh.github.io/Tatar-Kuber/report.html) ·
[Монгол](https://ochmunkh.github.io/Tatar-Kuber/report-mn.html) ·
[SARIF](https://ochmunkh.github.io/Tatar-Kuber/tatar-kuber.sarif)), эсвэл
[`examples/report/`](examples/report)-д байгаа файлуудыг нээ.

## Хэрхэн ажилладаг

![TATAR-Kuber архитектур](docs/img/architecture-mn.png)

```
эх сурвалж → scanner-ууд (зэрэг) → normalize → canonical + dedup → blind-shot → risk score → тайлан → CI gate
```

1. **Цуглуулна.** Ажиллаж буй cluster (зөвхөн унших), локал манифест (`-f`), эсвэл хадгалсан scanner гаралт (`--raw-dir`)-аас.
   Дөрвөн scanner зэрэг ажиллана, тус бүр өөрийн timeout-той; нэг нь унахад бусад нь дуусгана.
2. **Normalize хийнэ.** Scanner бүрийн rule ID тогтвортой `TATAR-*` control болно.
3. **Давхардлыг арилгана.** Хэд хэдэн scanner-ийн олсон ижил асуудал `found_by` болон итгэлийн түвшинтэй нэг finding болно.
   Жишээ: Trivy `AVD-KSV0017`, Kubescape `C-0057`, Checkov `CKV_K8S_16` бүгд нэг privileged контейнер →
   `deployment/api` дээр нэг `TATAR-CON-001`, итгэл HIGH. Харах: [`docs/dedup-example.md`](docs/dedup-example.md).
4. **Оноо өгнө.** Эрсдэл тайлбарлагдахуйц: finding бүр өөрийн хүчин зүйлтэй, cluster-ийн оноо томьёо болон гол
   нөлөөлөгчдөө харуулна. Зөвхөн ер бусын нөхцөлд хүрэх боломжтой finding-ийг бууруулна, хэзээ ч нууж болохгүй.
5. **Тайлан ба gate.** JSON, SARIF 2.1.0, хоёр хэлт HTML dashboard; бодлого зөрчигдвөл `gate` команд pipeline-ийг унагана.

Зарчим: **эхлээд зөвхөн унших** (`get`/`list`/`watch`), **scanner-аас хамаарахгүй** (adapter солигдох боломжтой),
**цоорхойгоо нуухгүй** (ямар ч scanner шалгадаггүй control-ыг "шалгаагүй" гэж харуулна, "тэнцсэн" гэж тоолохгүй).

## Суулгах

```bash
# Homebrew (macOS / Linux)
brew install ochmunkh/tap/tatar-kuber

# Linux / macOS — release binary татаж checksum шалгана
curl -fsSL https://raw.githubusercontent.com/ochmunkh/Tatar-Kuber/master/install.sh | sh

# Docker
docker run --rm -v "$PWD:/work" -w /work ghcr.io/ochmunkh/tatar-kuber:latest scan --raw-dir ./raw --out-dir .

# Эх кодоос
go install github.com/ochmunkh/tatar-kuber/cmd/tatar-kuber@latest
```

Live scan хийхэд дөрвөн scanner суусан байх ёстой. `tatar-kuber doctor` аль нь суусныг харуулна,
`tatar-kuber update` нь пиннэсэн хувилбаруудыг checksum шалгаад суулгана.

## Түргэн эхлэл (offline — cluster ба scanner суулгах шаардлагагүй)

Энэ repo-д жинхэнэ scanner гаралт [`examples/demo`](examples/demo)-д байдаг тул бүтэн pipeline ~30 секундэд ажиллана:

```bash
git clone https://github.com/ochmunkh/Tatar-Kuber && cd Tatar-Kuber
tatar-kuber scan   --raw-dir examples/demo --out-dir out
tatar-kuber report --input out/scan-result.json --format html --out report.html
tatar-kuber report --input out/scan-result.json --format html --lang mn --out report-mn.html
```

`--lang` нь тайланг дахин зурдаг тул хэл сэлгэхэд scanner дахин ажиллахгүй, cluster руу дахин хандахгүй.
CLI өөрөө default-оор англи хэлээр ярина; `--lang mn` эсвэл `TATAR_LANG=mn` нь монгол руу сэлгэнэ.
Том regression corpus (эмзэг ба hardened manifest) нь [**tatar-kuber-lab**](https://github.com/ochmunkh/tatar-kuber-lab)-д байна.

## Scanner-ууд

| Scanner | Зорилго | Бодит орчинд шалгасан |
|---|---|---|
| Trivy | Image CVE, secret, misconfiguration | 0.76 |
| Kubescape | NSA / MITRE / RBAC / compliance (үндсэн posture engine) | 4.0 |
| Checkov | IaC (YAML / Helm / Terraform) | 3.4 |
| Popeye | Runtime hygiene (dead service, unused, broken reference) | 0.22 |

Хувилбарууд нь [`tools.lock.yaml`](tools.lock.yaml)-д пиннэгдсэн, [real-cluster workflow](.github/workflows/real-cluster.yml)
өдөр бүр бодитоор ажиллуулдаг хувилбарууд. Флагаа сольсон scanner нь тайлангийн *Scanner хамрах хүрээ*
хүснэгтэд `error` / `unavailable` гэж харагдана — чимээгүй тэг болохгүй.

## Командууд

| Команд | Юу хийдэг |
|---|---|
| `scan` | Scanner-уудыг ажиллуулж (эсвэл `--raw-dir` уншиж) `scan-result.json` бичнэ; live scan нь scanner-ийн түүхий гаралтыг нотолгоо болгон хадгална |
| `report` | Үр дүнг `json`, `sarif`, `html`, `audit`, `pdf` болгон зурна (`--format`, `--lang`) |
| `gate` | `.tatar-kuber.yaml` бодлогыг зөрчвөл унана (exit 1) (`--fail-on`, `--baseline`) |
| `diff` | Хоёр scan-ийн хооронд юу шинэ, засагдсан, дордсоныг харуулна |
| `top` | Юуг түрүүлж засах: хамгийн муу workload-ууд, хамгийн олон resource-д хүрсэн control-ууд |
| `attest` | Ямар ч scanner шалгадаггүй control-д хүний өгсөн, хугацаатай хариулт |
| `doctor`, `update` | Аль scanner суусныг харуулах; пиннэсэн хувилбаруудыг суулгах |

Команд бүр `--lang en|mn` авна. Exit code: `0` амжилттай, `1` бодлого зөрчигдсөн, `2` ажиллалтын алдаа,
`3` хэрэглээний алдаа. Бүрэн флаг, exit code, live scan-д хэрэгтэй read-only RBAC:
[`docs/cli.md`](docs/cli.md).

## CI/CD gate

`.tatar-kuber.yaml` ([жишээ](.tatar-kuber.yaml.example)) нэмж pipeline-ээ gate-лэ, эсвэл GitHub Action ашигла:

```yaml
- uses: ochmunkh/Tatar-Kuber@v1
  with:
    raw-dir: ./raw      # эсвэл path: ./k8s
    fail-on: high
```

Жинхэнэ cluster-ийн анхны scan олон юм буцаадаг, эхний өдрөөс бүгдэд нь унадаг gate нэг долоо хоногийн дотор
унтарна. Өнөөдрийн finding-үүдийг **baseline**-аар (`gate --baseline`) хүлээн зөвшөөрч зөвхөн шинэ эсвэл
дордсон дээр унага; нэг finding-ийг шалтгаан, дуусах огноотойгоор `suppress`-ээр хүлээн зөвшөөр.
Хэрхэн, жишээтэй: [`docs/gate.md`](docs/gate.md).

## Аюулгүй байдал

Аюулгүй байдлын хэрэгсэл өөрөө мөрддөг стандартаа өөртөө хэрэглэх ёстой. Товчоор:

- **Зөвхөн унших.** Cluster role нь зөвхөн `get` / `list` / `watch` олгоно, Secret-ийг агуулахгүй.
- **Жижиг supply chain.** Нэг шууд хамаарал (`gopkg.in/yaml.v3`); GitHub Action, container image бүр пиннэгдсэн; `govulncheck`, `gosec` push бүрд ажиллана.
- **Scanner бол итгэлгүй програм.** Тайлан аль binary ажилласан, түүний SHA-256-г бичдэг; `update` шалгасны дараа өөрчлөгдсөн binary ажиллахгүй; forge credential scanner-т дамжихгүй; түүхий гаралт `SHA256SUMS` manifest-тэй.
- **Gate өөрийн оролтыг шалгана.** Өөртэйгөө зөрсөн `scan-result.json`-оос татгалзана. Энэ бол тууштай байдлын шалгалт, гарын үсэг биш.
- **Оролт хязгаартай, гаралт зөвхөн эзэмшигчид** (эрх `0600`).

Дэлгэрэнгүй ба scanner бүрийн хэмжсэн сүлжээний зан төлөв: [`docs/security.md`](docs/security.md).
Эмзэг байдал олсон уу? [`SECURITY.md`](SECURITY.md) — GitHub-ын **Security → Report a vulnerability** (хаалттай мэдээлэл).

## Хамрах хүрээ

TATAR-Kuber нь **posture, тохиргоо, IaC, image, RBAC-ийн шинжилгээг нэгдсэн тайлантайгаар** хамарна. Runtime
илрүүлэлт, admission control, нууц удирдлагыг **орлохгүй, нөхөж** ажиллана — Falco/Tetragon, Kyverno/OPA, Vault-тай
хамт ажиллуул. Онцлог, юуг хамарч юуг хамаргүйг: [`docs/scope.md`](docs/scope.md). Control бүрийг scanner бүртэй
тулгасан матриц, ямар ч scanner шалгадаггүй нэгийг оролцуулан: [`docs/coverage.md`](docs/coverage.md).

## Build

```bash
go build ./...
go test ./...          # 23 багц, бүгд ногоон
./scripts/build.sh 1.0.6
```

## Баримт бичиг

`docs/` дотор 6 инженерийн баримт **Word (`.docx`)** хэлбэрээр (GitHub тэдгээрийг browser дээр харуулахгүй):
[01 Unified Schema](docs/01_Unified-Schema-JSON-v1.docx) ·
[02 Canonical Mapping](docs/02_Canonical-Control-Mapping.docx) ·
[03 Scanner Adapter Interface](docs/03_Scanner-Adapter-Interface.docx) ·
[04 Severity & Risk Scoring](docs/04_Severity-Risk-Scoring-Model.docx) ·
[05 CLI Spec](docs/05_CLI-Specification.docx) ·
[06 Repository Structure](docs/06_Repository-Structure.docx).
Markdown гарын авлага: [командууд](docs/cli.md) · [CI gate](docs/gate.md) · [аюулгүй байдлын загвар](docs/security.md) ·
[хамрах хүрээ](docs/scope.md) · [coverage](docs/coverage.md). `scan-result.json`-ы JSON Schema нь
[`pkg/schema/tatar-schema-v1.json`](pkg/schema/tatar-schema-v1.json). Хувилбарын тэмдэглэл: [`docs/releases/`](docs/releases).

## Төлөв

**v1.0.6** — хувилбар бүр юуг өөрчилсөн нь [`docs/releases/`](docs/releases)-д, цаашид юу ирэх нь [`ROADMAP.md`](ROADMAP.md)-д.
Дөрвөн scanner-ийн зураглагдсан rule бүр scanner-ийн өөрийн тодорхойлолттой тестээр тулгагдсан тул scanner
шалгалтаа нэрлэж сольсон эсвэл дугаарыг нь өөрчилсөн бол build унана.

## Хувь нэмэр оруулах

Хувь нэмэр оруулахад таатай. [CONTRIBUTING.md](CONTRIBUTING.md) болон
[`docs/03_Scanner-Adapter-Interface.docx`](docs/03_Scanner-Adapter-Interface.docx)-аас эхэл; `go test ./...`-ийг
ногоон байлгаж, [Code of Conduct](CODE_OF_CONDUCT.md)-ийг унш.

## Холбоо барих

**Зохиогч:** Enkhbat Oyunbayar — Security Analyst

[![Facebook](https://img.shields.io/badge/Facebook-Enkhbat%20Oyunbayar-1877F2?logo=facebook&logoColor=white)](https://www.facebook.com/enkhbat.o/)
[![GitHub](https://img.shields.io/badge/GitHub-ochmunkh-181717?logo=github&logoColor=white)](https://github.com/ochmunkh)

## Лиценз

Apache-2.0 — [LICENSE](LICENSE)-ийг үз.
