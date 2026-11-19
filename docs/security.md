# TATAR-Kuber — security model

How the tool protects itself and what it does to the scanners it runs.

English · [Монгол](#монгол-хэл-дээр)

---

## Security

A security tool should hold itself to the standard it enforces:

- **SAST + vuln scanning in CI** — every push runs [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
  (known CVEs in dependencies **and** the Go standard library) and [`gosec`](https://github.com/securego/gosec)
  (static analysis), with gosec results uploaded to the GitHub **Code scanning** tab. See
  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
- **Patched toolchain** — release binaries are built with a current, patched Go stdlib
  (pinned via `toolchain` in `go.mod`), so the report renderer stays clear of `html/template` CVEs.
- **Minimal supply chain** — one direct dependency (`gopkg.in/yaml.v3`) plus the standard library.
- **Pinned release pipeline** — every third-party GitHub Action runs at a **commit SHA**, not a
  movable tag. A tag can be repointed by whoever owns the action, and `checksums.txt` and the
  SBOM are produced by those same steps — so a compromised one would ship a backdoored binary
  *with a matching checksum*. First-party actions are pinned too, and the repository setting
  that rejects any unpinned action is on. Workflows are read-only by default; write permission
  is granted only on the job that needs it. Container base images are pinned by digest.
  `.github/dependabot.yml` raises updates weekly as pull requests, so the pins stay reviewed
  rather than frozen.
- **Safe by construction** — read-only cluster access (`get`/`list`/`watch`, granted by the
  reviewable [`deploy/least-privilege-clusterrole.yaml`](../deploy/least-privilege-clusterrole.yaml)
  — Secrets are **not** in that role at all: RBAC has no "metadata only" for a Secret, and
  `get`/`list` return the whole `data:` field), no shell invocation (scanners run via `exec`
  with fixed args, no `sh -c`), and reports render through `html/template` auto-escaping.
- **Output is written owner-only** — `scan-result.json`, the raw scanner output and every report
  (`html`, `audit`, `sarif`, `json`, `pdf`) are created with mode `0600`. A report is a list of a
  cluster's weaknesses in readable form; treat it as confidential wherever it travels.
- **The scanners are third-party programs, and the report says which one ran.** Each
  `metadata.scanner_runs[]` entry records the binary's path, where it was found (`path` or
  `tools`) and its SHA-256. PATH is searched before `~/.tatar-kuber/tools`, so a scanner that
  `update` pinned can be shadowed by another copy; when that happens a warning is printed and
  stored in the run. Scanners inherit your environment **except** forge/CI credentials
  (`GITHUB_TOKEN`, `GH_TOKEN`, `ACTIONS_*` tokens, …); `TATAR_PASS_ENV=NAME,NAME` hands a named
  one over. `TATAR_STRICT_ENV=1` switches this to an allow-list (only `PATH`, `HOME`, `KUBECONFIG`,
  proxy/CA variables, `TRIVY_*`-style tool prefixes and what `TATAR_PASS_ENV` names); cloud
  credentials are then withheld too. A scanner binary in `~/.tatar-kuber/tools` is compared with
  the SHA-256 `update` recorded (`installed_sha256` in `tools.lock.yaml`); if it was changed
  afterwards the scanner is reported `unavailable` and not run. `scan` writes `raw/SHA256SUMS`
  (`sha256sum` format) and `scan --raw-dir` refuses a directory that no longer matches it.
  Checkov is started with `BC_SKIP_MAPPING=TRUE`: without it, it calls
  `api0.prismacloud.io` on every run. Trivy's secret and misconfiguration scans make no network
  call; its vulnerability scan downloads its database. Kubescape and Popeye were measured on a
  kind cluster with a DNS-logging resolver: Popeye talks only to the cluster's API server.
  Kubescape also contacts `github.com` and `release-assets.githubusercontent.com` (policy
  download) and `tuf-repo-cdn.sigstore.dev` (signature verification). TATAR-Kuber sets
  `KS_SKIP_UPDATE_CHECK=true`, which removes a further per-run request to
  `version-check.ks-services.co`, and passes `--keep-local`, so results are never submitted to a
  Kubescape account. Only destinations were observed, not request contents.
- **The gate checks the file it is given.** `gate` recomputes the result hash, the finding
  counts and the risk score from the findings and refuses (exit 2) a `scan-result.json` that
  disagrees with itself. This catches hand edits, truncated files and files from another
  scoring model; it is a consistency check, not a signature — someone who can recompute every
  field is not stopped. `--skip-integrity-check` turns it off and says so each time.
- **Inputs are bounded.** Scanner output, raw JSON and scan results are capped at 256 MiB, and
  policy / attestation / registry files at 16 MiB; a larger file is an error, never a
  truncated read. A kube context or namespace that starts with `-` is refused rather than
  passed to a scanner as a flag.

Found a vulnerability? See [`SECURITY.md`](../SECURITY.md) — GitHub's **Security → Report a vulnerability** (private disclosure).

---

## Монгол хэл дээр

### Аюулгүй байдал

Аюулгүй байдлын багаж өөрөө өөрийн шаарддаг стандартыг барих ёстой:

- **CI-д SAST + CVE скан** — push бүрд [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
  (хамаарал **болон** Go stdlib дахь мэдэгдэж буй CVE) + [`gosec`](https://github.com/securego/gosec)
  (статик шинжилгээ) ажиллана; gosec-ийн үр дүн GitHub **Code scanning** таб руу ордог.
  ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).
- **Patched toolchain** — release бинарууд зассан Go stdlib-ээр build хийгддэг (`go.mod`-ийн
  `toolchain`-аар бэхлэсэн) тул тайлан рендерлэгч `html/template` CVE-үүдээс цэвэр.
- **Минимал supply chain** — ганц шууд хамаарал (`gopkg.in/yaml.v3`) + stdlib.
- **Пиннэсэн release зам** — гуравдагч этгээдийн GitHub Action бүр **commit SHA**-гаар
  ажиллана, хөдөлгөөнт tag-аар биш. Tag-ийг action-ы эзэмшигч өөр commit руу зөөж чадна, бас
  `checksums.txt` ба SBOM-ыг ЯГ ТЭР алхмууд үүсгэдэг — тиймээс эвдэрсэн нэг нь backdoor-той
  binary-г *таарсан checksum-тай нь* нийтэлнэ. `.github/dependabot.yml` долоо хоног тутам
  шинэчлэлтийг PR болгон ирүүлдэг тул пин нь хөлдөхгүй, хянагдсан хэвээр үлдэнэ. Эхний
  талын action-ууд мөн пиннэгдсэн, пиннээгүй action-ийг татгалздаг repo тохиргоо асаалттай.
  Workflow default-аараа зөвхөн унших эрхтэй; бичих эрхийг зөвхөн хэрэгтэй job-д өгнө. Docker
  суурь image digest-ээр пиннэгдсэн.
- **Бүтцээрээ аюулгүй** — read-only cluster хандалт (`get`/`list`/`watch`; хянагдах
  [`deploy/least-privilege-clusterrole.yaml`](../deploy/least-privilege-clusterrole.yaml)-аар
  олгогдоно — Secret тэр эрхэнд **огт байхгүй**: RBAC дээр Secret-д "зөвхөн metadata" гэсэн
  эрх байдаггүй, `get`/`list` нь `data:` талбарыг бүхэлд нь буцаана), shell дуудлагагүй
  (scanner-ууд тогтмол аргументтэй `exec`-ээр, `sh -c` байхгүй), тайлан `html/template`
  auto-escape-аар рендерлэгддэг.
- **Гаралт зөвхөн эзэмшигчид уншигдахаар бичигдэнэ** — `scan-result.json`, scanner-ийн түүхий
  гаралт, мөн тайлан бүр (`html`, `audit`, `sarif`, `json`, `pdf`) `0600` эрхтэй үүснэ. Тайлан
  бол кластерын сул талуудын хүн уншихуйц жагсаалт — хаашаа ч явсан нууц мэдээлэл гэж хандана.
- **Scanner-ууд бол гуравдагч талын програм; тайлан аль нь ажилласныг хэлнэ.**
  `metadata.scanner_runs[]` бичлэг бүр binary-ийн зам, хаанаас олдсон (`path` эсвэл `tools`),
  SHA-256-г бүртгэнэ. PATH нь `~/.tatar-kuber/tools`-оос ӨМНӨ хайгддаг тул `update`-ийн пин
  хийсэн scanner-ийг өөр хуулбар далдалж чадна; ингэвэл анхааруулга хэвлэж, run-д хадгална.
  Scanner-ууд таны орчныг өвлөнө, **гэхдээ** forge/CI credential-аас бусад
  (`GITHUB_TOKEN`, `GH_TOKEN`, `ACTIONS_*` token, …); нэрлэсэн нэгийг `TATAR_PASS_ENV=NAME,NAME`-ээр
  өгч болно. `TATAR_STRICT_ENV=1` нь үүнийг allow-list болгоно (зөвхөн `PATH`, `HOME`, `KUBECONFIG`,
  proxy/CA хувьсагч, `TRIVY_*` төрлийн угтвар, `TATAR_PASS_ENV`-д нэрлэсэн); cloud credential мөн
  хаагдана. `~/.tatar-kuber/tools` доторх scanner binary-г `update`-ийн бүртгэсэн SHA-256-тай
  (`tools.lock.yaml`-ийн `installed_sha256`) тулгана; дараа нь өөрчлөгдсөн бол scanner
  `unavailable` болж ажиллахгүй. `scan` нь `raw/SHA256SUMS` (`sha256sum` формат) бичнэ,
  `scan --raw-dir` нь үүнтэй таарахгүй хавтсыг татгалзана. Checkov-г `BC_SKIP_MAPPING=TRUE`-тай эхлүүлнэ: үгүй бол run бүрд
  `api0.prismacloud.io` руу хандана. Trivy-ийн secret болон misconfiguration скан сүлжээнд
  хандахгүй; vulnerability скан нь өөрийн database-ийг татна. Kubescape, Popeye-ийг kind
  cluster дээр DNS-ийг бүртгэдэг resolver-ээр хэмжсэн: Popeye зөвхөн cluster-ийн API server-тэй
  харилцана. Kubescape нэмээд `github.com`, `release-assets.githubusercontent.com` (policy татах),
  `tuf-repo-cdn.sigstore.dev` (гарын үсэг шалгах) руу хандана. TATAR-Kuber нь
  `KS_SKIP_UPDATE_CHECK=true` тохируулж `version-check.ks-services.co` руу run бүрд хийдэг
  нэмэлт хүсэлтийг устгадаг, `--keep-local` дамжуулдаг тул үр дүн хэзээ ч Kubescape account руу
  илгээгдэхгүй. Зөвхөн очих хаягийг ажигласан, хүсэлтийн агуулгыг биш.
- **Gate нь өөрт нь өгсөн файлыг шалгана.** `gate` нь result hash, finding-ийн тоо,
  эрсдэлийн оноог findings-ээс дахин бодож, өөртэйгөө зөрсөн `scan-result.json`-оос татгалзана
  (exit 2). Гар засвар, таслагдсан файл, өөр оноолтын загвараар үүссэн файлыг барина; энэ бол
  гарын үсэг биш, зөвхөн тууштай байдлын шалгалт — бүх талбарыг дахин бодож чадах хүнийг
  зогсоохгүй. `--skip-integrity-check` үүнийг унтрааж, тухай бүрд мэдэгдэнэ.
- **Оролт хязгаарлагдмал.** Scanner-ийн гаралт, raw JSON, scan result 256 MiB, policy /
  attestation / registry файл 16 MiB-ээс хэтрэхгүй; илүү том файл бол алдаа — хэзээ ч таслаж
  уншихгүй. `-`-ээр эхэлсэн kube context, namespace-ийг scanner-т flag болгон дамжуулахгүй,
  татгалзана.

Эмзэг байдал олсон уу? [`SECURITY.md`](../SECURITY.md) — GitHub-ын **Security → Report a vulnerability** (хаалттай мэдээлэл).
