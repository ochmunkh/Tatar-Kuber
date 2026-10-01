# TATAR-Kuber

> Kubernetes Security Posture Assessment Framework  
> Engineering Document #5  
> CLI Specification  
> Команд, флаг, гаралт, exit code, тохиргоо  
> Version 1.6  ·  кодтой тулгасан (2026-09-28)  
> Enkhbat.O — Security Analyst  
> 2026-07-24

<!-- Generated from 05_CLI-Specification.docx by scripts/docx-to-md.py -- do not edit by hand. -->
*Generated from `05_CLI-Specification.docx`. The Word document is canonical; regenerate with `python3 scripts/docx-to-md.py docs/05_CLI-Specification.docx`.*

## 1. Зорилго

TATAR-Kuber-ийн command-line интерфэйсийн эцсийн тодорхойлолт. Хэрэглэгчийн харилцах гадаргуу тогтвортой, ойлгомжтой, CI/CD-д тохиромжтой байх ёстой. Гол философи: scan нь зөвхөн цуглуулна, report нь тайлагнана — хоёр нь тусдаа.

## 2. Командын тойм

| **Команд** | **Үүрэг** |
|---|---|
| tatar-kuber scan | Cluster эсвэл manifest-ийг шалгаж raw + scan-result.json цуглуулна |
| tatar-kuber report | Цуглуулсан үр дүнгээс тайлан (json/sarif/html) үүсгэнэ |
| tatar-kuber update | Scanner binary татах, SHA256 checksum баталгаажуулах, tools.lock.yaml-д түгжих. --dry-run ба --check флагтай. cosign баталгаажуулалт хараахан хэрэгжээгүй (stub) бөгөөд tools.lock.yaml-д "unverified" гэж тэмдэглэгдэнэ. |
| tatar-kuber version | TATAR болон scanner-уудын хувилбарыг харуулна |
| tatar-kuber gate | scan-result.json-ыг .tatar-kuber.yaml бодлоготой тулгаж CI-д pass/fail (exit code) |
| tatar-kuber doctor | Scanner binary суусан эсэх, хувилбар, дэмждэг горимыг шалгана |
| tatar-kuber verify-lab | expected-findings.json-той тулгаж regression шалгана |

## 3. tatar-kuber scan

### 3.1 Хэрэглээ

```bash
# Mode A — Local configuration scan
tatar-kuber scan -f ./k8s/
tatar-kuber scan -f ./chart/            # Helm

# Mode B — Remote cluster assessment
tatar-kuber scan --kubeconfig ~/.kube/config
tatar-kuber scan --context production
tatar-kuber scan --context prod -n payments -n api   # namespace хязгаарлах
```

### 3.2 Флагууд

| **Флаг** | **Товч** | **Утга** | **Тайлбар** |
|---|---|---|---|
| --file | -f | path | Local manifest/Helm/Terraform зам (Mode A) |
| --kubeconfig |   | path | Kubeconfig файл (Mode B) |
| --context |   | name | Kubeconfig доторх context (Mode B). Тэмдэглэл: Trivy-д context нь positional аргумент, Kubescape-д --kube-contexts (олон тоо) — adapter тус бүр өөрөө зохицуулна. |
| --namespace | -n | name | Тодорхой namespace-аар хязгаарлах (давтагдана) |
| --scanners |   | list | Ажиллуулах scanner (default: бүгд). ж: --scanners trivy,kubescape |
| --timeout |   | duration | Scanner бүрийн timeout (default 5m) |
| --output-dir | -o | path | Үр дүнгийн хавтас (default: одоогийн хавтас). \<out\>/scan-result.json үүснэ. |
| --raw-dir |   | path | Урьдчилан цуглуулсан scanner raw JSON-ы хавтас (offline ingest, Mode A/B-гүй). \<dir\>/{trivy,kubescape,checkov,popeye}.json + сонголттой versions.json, inventory.json |
| --no-raw |   | — | Live scan-д scanner-уудын түүхий гаралтыг \<out\>/raw/ дотор ХАДГАЛАХГҮЙ. Default нь хадгална (аудитын нотолгоо; --raw-dir хүлээж авдаг яг тэр бүтэц) |
| --lang |   | en\\|mn | Тайлангийн хэл (default en). canonical registry-ээс curated title/remediation-ыг сонгосон хэлээр авна |
| --registry |   | path | canonical-controls.yaml зам. Хоосон бол binary-д шигтгэсэн registry (ихэнх тохиолдолд зөв) |
| --no-rollup |   | — | Pod хэмжээний finding-ийг эзэмшигч controller руу ЗӨӨХГҮЙ. Default нь зөөнө: нэг pod template-ийн зөрчил Popeye-д pod, Trivy/Kubescape-д workload болж давхар тоологдохыг зогсооно. Зөөлтийн тоо metadata.rollup ба тайланд ил гарна |

**Гаралт:** scan нь зөвхөн цуглуулна — ~/.tatar-kuber/scan-result.json ба ~/.tatar-kuber/raw/\<scanner\>.json үүсгэнэ. Хүний уншиж болох тайлан гаргахгүй (энэ нь report-ийн ажил).

## 4. tatar-kuber report

```bash
tatar-kuber report                       # default: сүүлийн scan-result.json
tatar-kuber report -o json               # machine-readable
tatar-kuber report -o sarif > out.sarif  # CI integration
tatar-kuber report -o html --open        # dashboard, browser нээнэ
tatar-kuber report --input ./scan-result.json --fail-on HIGH
tatar-kuber report --input ./scan-result.json --lang mn --out mn.html
```

| **Флаг** | **Утга** | **Тайлбар** |
|---|---|---|
| --output / -o | json \\| sarif \\| html | Гаралтын формат (default: html) |
| --open | — | HTML-г browser-т нээх |
| --input | path | Тодорхой scan-result.json заах |
| --fail-on | severity | Тухайн severity-с дээш finding байвал exit code 1 |
| --include-blind-shot | — | Blind-shot finding-ийг тайланд тодотгож харуулах (default: харуулна) |

### 4.1 Гаралтын формат

- **JSON:** Unified Schema бүрэн. Machine-readable, дараагийн систем рүү дамжуулах.
- **SARIF:** Заавал. GitHub Security, GitLab, Azure DevOps-т шууд залгагдана. Тогтвортой rule ID (§schema 7.1) ашиглаж дедуп эвдэхгүй.
- **HTML:** Хүн уншихад зориулсан dashboard: Critical/High/Medium/Low тоо, Blind Shot тоо, Risk Score, band, finding жагсаалт, remediation.

## 5. tatar-kuber update

Scanner binary-уудыг татаж, checksum/signature-ийг баталгаажуулж, tools.lock.yaml-д тэмдэглэнэ. Security tool өөрөө баталгаажуулаагүй binary ажиллуулж болохгүй — download → verify → execute.

```bash
tatar-kuber update                # бүх scanner-ыг lock хувилбар руу
tatar-kuber update --scanner trivy
tatar-kuber update --check        # татахгүй, зөвхөн шинэ хувилбар шалгах

# Дотоод дараалал:
download → verify checksum (SHA256) → verify signature (cosign) → install → lock
```

## 6. tatar-kuber version

```bash
$ tatar-kuber version
TATAR-Kuber    1.0.0   (build a3f19c, 2026-07-24)
  trivy       0.53.0  [verified]
  kubescape   3.0.8   [verified]
  checkov     3.2.0   [verified]
  popeye      0.21.5  [verified]
```

## 7. Exit code-ууд

| **Код** | **Утга** |
|---|---|
| 0 | Амжилттай. --fail-on босго давсан finding алга. |
| 1 | --fail-on босгоос дээш finding илэрсэн (CI-д ашиглах). |
| 2 | Гүйцэтгэлийн алдаа (scanner ажиллуулах, connection г.м). |
| 3 | Тохиргоо/аргументын алдаа. |
| 4 | Хэсэгчилсэн амжилт (зарим scanner унасан, degraded). |

## 8. Тохиргоо ба хавтасны бүтэц

```text
~/.tatar-kuber/
  config.yaml            # хэрэглэгчийн тохиргоо
  scan-result.json       # сүүлийн scan (Unified Schema)
  tools.lock.yaml        # scanner хувилбар + checksum (pin)
  blindshot-rules.json   # blind-shot дүрмүүд (хувилбартай)
  raw/
    trivy.json
    kubescape.json
    checkov.json
    popeye.json
  tools/                 # татаж авсан scanner binary-ууд
  logs/
    scan-2026-07-24.log
  audit/
    audit.log            # scan time, cluster, scanner ver, result hash
```

### 8.1 config.yaml жишээ

```yaml
default_output: html
timeout: 5m
scanners: [trivy, kubescape, checkov, popeye]
fail_on: HIGH
encryption:
  enabled: true          # local data шифрлэх сонголт
context_labels:          # asset context илрүүлэх (§scoring)
  production: ["prod", "production"]
  development: ["dev", "test", "staging"]
```

## 9. Лог ба аудит

Scan бүр дараах үе шатыг лог болгож бичнэ: START SCAN → RUN \<scanner\> → NORMALIZE → DEDUP → REPORT GENERATED. Аудитын лог нь scan хугацаа, cluster нэр, scanner хувилбар, result hash-ийг өөрчлөгдөшгүй байдлаар хадгална. Temp файлууд аюулгүй үүсч, ажиллагаа дуусахад цэвэрлэгдэнэ.

## Хувилбарын тэмдэглэл — v1.1 / v1.2 / v1.3 / v1.4 / v1.5 / v1.6

- \`update\` команд нь ЭХЛЭЭД v1-д ХЭРЭГЖЭЭГҮЙ байсан: exit 2 буцааж, scanner-уудыг гараар суулгаад \`doctor\`-оор шалгахыг зөвлөдөг байв. ОДОО хэрэгжсэн — download → SHA256 checksum → tools.lock.yaml, --dry-run ба --check флагтай. cosign нь stub хэвээр бөгөөд хэзээ ч "баталгаажсан" гэж хэлэхгүй.
- Шинэ флаг --no-raw: live scan нь default-аар түүхий scanner гаралтыг \<out\>/raw/-д нотолгоо болгон хадгална (--raw-dir хүлээж авдаг яг тэр бүтэц тул дахин боловсруулж, аудит хийж болно).
- \`gate\`-ийн --fail-on / --min-score нь ЗӨВХӨН хэрэглэгч тодорхой өгсөн үед .tatar-kuber.yaml-ыг дарна. Өмнө нь default утга (--min-score 0) бодлогын файлын утгыг үргэлж дарж, min_score утгагүй болж байв. Танигдахгүй fail_on-д анхааруулга хэвлэнэ.
- Баримтад байгаагүй командууд бүртгэгдэв: gate, doctor, verify-lab. --scanners ба --timeout нь v1-д хэрэгжээгүй (adapter тус бүр өөрийн зөвлөмж timeout-той: Trivy 6m, Kubescape 4m, Checkov 3m, Popeye 90s).
- scan нь stderr-т scanner бүрийн мөрийг (төлөв, finding тоо, зураглалгүй rule) хэвлэнэ; scanner ажилласан ч 0 finding normalize хийгдвэл анхааруулга гарна.

(v1.2) Шинэ флаг --no-rollup: Pod -\> controller зөөлтийг болиулна (default нь зөөнө).

(v1.2) \`gate\` нь гурван шинэ анхааруулга хэвлэнэ: хугацаа дууссан suppression, canonical registry-д БАЙХГҮЙ control руу заасан suppression, мөн ямар ч олдворт ТОХИРООГҮЙ suppression (хуучирсан дүрэм — "хүлээн зөвшөөрсөн эрсдэл"-ийн бүртгэл бодит бус болсныг харуулна).

(v1.2) scan нь rollup хийгдсэн үед stderr-т зөөлтийн тоог мэдэгдэнэ.

- ШИНЭ КОМАНД (v1.3): tatar-kuber diff --old a.json --new b.json \[-o text\|json\] \[--lang mn\|en\] \[--fail-on-new critical\|high\|medium\|low\] \[--all\]. Хоёр scan-ыг тогтвортой finding ID (StableID(control, resource, namespace))-гаар тулгаж шинэ / зассан / дордсон / сайжирсан / хэвээр гэж ангилна; severity тус бүрийн ба cluster онооны зөрүүг гаргана.
- Exit code: 0 — OK; 1 — --fail-on-new босго давсан (шинэ finding тэр severity-с дээш); 2 — файл унших/parse алдаа; 3 — --old эсвэл --new дутуу.
- diff нь metadata.scanner_runs-ыг МӨН тулгана. Өмнө finding өгч байсан scanner одоо 0 өгвөл, эсвэл ok төлвөөс гарвал "ХАМРАХ ХҮРЭЭ БУУРСАН" гэж тэмдэглэнэ — тоо буурахыг "зассан" гэж уншихаас сэргийлнэ (v1.0.0-ийн алдааны хэв маяг).
- Итгэх боломжгүй харьцуулалтыг анхааруулгаар хэлнэ: өөр cluster, өөр горим (Mode A vs B), нэг тал нь --no-rollup (resource өөрчлөгддөг тул ID бүр солигдоно), схем/хувилбарын зөрүү.
- Тест: 17 пакет (internal/diff — 6 тест; internal/cli-д diff-ийн E2E: rollup-тай ба rollup-гүй хоёр бодит scan, exit code бүр).
- diff-ийн тулгах түлхүүр: ердийн үед finding.ID. ГЭХДЭЭ нэг талд ID хоосон finding байвал (гараар засагдсан эсвэл хуучин хувилбарын файл) ХОЁР талыг canonical түлхүүрээр (control\|resource\|namespace) тулгана — эс бөгөөс ID-гүй бүх finding нэг түлхүүрт нийлж, ижил асуудал "зассан + шинэ" гэж хоёр удаа тоологдоно.
- metadata.scanner_runs нэг талд огт байхгүй бол scanner бүрийг "унасан" гэж зарлахгүй (худал сэрэмжлүүлэг болно). Оронд нь "хамрах хүрээг харьцуулах боломжгүй" гэсэн нэг анхааруулга өгч, тоог 0 гэхийн оронд "—" гэж харуулна: 0 нь "олдсонгүй", "—" нь "мэдэгдэхгүй".
- Анхааруулга бүр {code, mn, en} бүтэцтэй: CLI нь --lang-ийн дагуу сонгоно, JSON хэрэглэгч code-оор машинаар боловсруулна. Код: missing_ids, no_scanner_runs_old, no_scanner_runs_new, cluster_mismatch, mode_mismatch, rollup_mismatch, schema_mismatch, version_mismatch, scanner_absent, scanner_zero, scanner_status.
- ШИНЭ ФЛАГ (v1.4): report --lang en\|mn. Хэл нь SCAN-Ы БИШ, ГАРАЛТЫН шинж чанар болов. Өмнө нь зөвхөн scan --lang байсан тул монгол тайлан авахын тулд бүх scan-ыг дахин ажиллуулах шаардлагатай байв (cluster руу дахин хандах, 4 tool дахин ажиллуулах). Одоо нэг scan-result.json-оос хоёр хэл дээрх тайлан гарна.
- Хэрэгжүүлэлт: report нь canonical registry-г (шигтгэсэн, эсвэл --registry) ачаалж orchestrator.ApplyLang-аар title/remediation-ыг сэлгэнэ. scan-result.json файл ХӨНДӨГДӨХГҮЙ — зөвхөн санах ойн хуулбар өөрчлөгдөнө, тиймээс metadata.result_hash хүчинтэй хэвээр (verify ажиллана).
- --lang нь json, sarif, html гурван форматад бүгдэд үйлчилнэ (finding.title/remediation түвшинд сэлгэгддэг тул). --lang өгөөгүй бол scan-д сонгосон хэл хэвээр — буцаад нийцтэй.
- Registry-д байхгүй хэл зааж өгвөл ЧИМЭЭГҮЙ англи руу унахгүй: exit 3, ямар хэл байгааг хэлнэ. ХЯЗГААР: canonical registry-д зурагдаагүй finding-ийн гарчиг scanner-ийн эх текстээрээ үлдэнэ (орчуулах эх сурвалж байхгүй) — тэдгээрийн тоог stderr-т анхааруулна.
- ЗАСВАР (v1.4): HTML тайлангийн \<html lang="..."\> нь "mn" гэж хатуу бичээстэй байсан — англи тайлан өөрийгөө монгол гэж зарладаг байв (дэлгэц уншигч, орчуулагч, индексжүүлэлт бүгд үүнийг уншдаг). Одоо тайлангийн бодит хэлийг дагана.
- Тест: internal/cli-д E2E (нэг scan -\> en/mn хоёр тайлан, гарчиг үнэхээр өөр эсэх, эх файл хөндөгдөөгүй эсэх, --lang de бол exit 3); internal/report/html-д \<html lang\> шалгалт; internal/canonical-д Languages/HasLang ба БҮХ control mn орчуулгатай эсэх. Real cluster workflow нь en/mn хоёуланг нь гаргаж, lang атрибутыг шалгана.
- ЗАСВАР (v1.5): scan --raw-dir нь scan_mode="offline" гэж бичдэг болов. Өмнө нь mode хувьсагч ЗӨВХӨН -f байгаа эсэхээр шийдэгдэж (эс бөгөөс "remote"), --raw-dir салаа түүнийг дамжуулдаг байсан тул офлайн ingest бүр өөрийгөө амьд кластерын scan гэж зарладаг байв. Энэ нь README-гийн "cluster хэрэггүй түргэн эхлэл" зам буюу хамгийн олон хүн туршдаг зам дээр байсан.
- (v1.5) Үүний хоёр дахь хор: diff нь metadata.scan_mode-ыг тулгаж горим зөрвөл анхааруулдаг. Амьд scan ба офлайн ingest хоёул "remote" байсан тул энэ хамгаалалт тэдний хооронд хэзээ ч хөөрөх боломжгүй байв. Одоо хөөрнө.
- ШИНЭ ТЕСТ (v1.5): TestVersionsAgree. goreleaser нь ldflags-аар ЗӨВХӨН internal/cli.Version-ыг оруулдаг; orchestrator.Version нь const тул гараар шинэчилнэ. Release-д const-ыг мартвал \`tatar-kuber version\` нь шинэ хувилбар хэлэх атлаа scan-result.json-ийн metadata.tatar_version ба SARIF-ийн driver.version хуучин хэвээр үлдэнэ. Тест хоёрын зөрүүг барина.
- (v1.5) Release шалгах жагсаалт: хувилбар 6 газар байдаг — internal/orchestrator/orchestrator.go (const, ldflags хүрэхгүй), internal/cli/root.go, README-гийн release badge, README-гийн ./scripts/build.sh жишээ (en+mn), docs/img/architecture.gen.py, examples/report/ (4 файл). Тестийн badge-ийн пакетын тоог мөн шалгана.
- ШИНЭ ФЛАГ (v1.6): gate --baseline \<scan-result.json\>. Baseline-д аль хэдийн байгаа олдворыг босгонд тооцохгүй, ЗӨВХӨН шинэ ба ДОРДСОНЫГ тооцно. Зорилго: байгаа кластерт gate нэвтрүүлэхэд эхний өдөр бүх олдворт унаж, баг gate-ээ унтраахаас сэргийлэх. Унтраасан gate бол gate биш.
- (v1.6) Дордсон олдвор ЗААВАЛ тооцогдоно: LOW нь CRITICAL болох нь шинэ эрсдэл, "хуучин асуудал" гэж чимээгүй өнгөрөх нь энэ хэрэгслийн эсэргүүцдэг зүйл. Хэрэгжүүлэлт нь diff.Compare-ийг ашиглана (ChangeNew + ChangeWorsened).
- (v1.6) min_score нь baseline-аас ХАМААРАХГҮЙ: filtered үр дүнгийн Summary хэвээр дамждаг тул оноо бүтэн кластерынхаараа шалгагдана. Оноо бол кластерын шинж чанар, зөрүүнийх биш.
- (v1.6) Итгэх боломжгүй baseline (cluster_mismatch, mode_mismatch, rollup_mismatch, schema_mismatch) үед baseline ХЭРЭГСЭХГҮЙ, бүх олдвор тооцогдоно — аюулгүй байдлын gate эргэлзээтэй үедээ хаалттай талдаа унана. Шалтгааныг stderr-т нэрлэнэ.
- (v1.6) Suppression-ий бүртгэл (хугацаа дууссан / юунд ч тохироогүй дүрэм) нь БҮТЭН олдворын жагсаалт дээр тооцогдсон хэвээр. Эс бөгөөс baseline-д байсан finding-ийг хаадаг дүрэм бүр "ямар ч олдворт тохироогүй" гэж худал анхааруулагдах байв.
- (v1.6) Тест: TestCLI_GateBaseline — baseline-гүй (exit 1), өөрчлөлтгүй baseline (exit 0), шинэ CRITICAL (exit 1), дордсон олдвор (exit 1), cluster зөрсөн baseline (exit 1, хэрэгсэхгүй), байхгүй файл (exit 2).
