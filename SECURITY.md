# Security policy

TATAR-Kuber reads cluster state and runs third-party scanners on your behalf, so a flaw in
it can matter more than its size suggests. Reports are welcome and are read.

## Reporting a vulnerability

Please do **not** open a public issue with the details.

1. Use GitHub's private channel: **Security → Report a vulnerability** on this repository.
2. If that option is not shown, open an issue titled `security contact request` that says
   only that you have a report — no details — and a private channel will be arranged.

Useful to include: the version (`tatar-kuber version`), what you did, what you expected, what
happened, and — if you can — a minimal input that shows it (a manifest, a `scan-result.json`,
a `tools.lock.yaml`).

This is a one-maintainer open-source project. Reports are acknowledged on a best-effort basis
and there is no guaranteed response time; a fix is released as a patch version and noted in
the release notes.

## Supported versions

Only the latest release receives fixes.

## What is in scope

Behaviour of this repository's code, in particular:

- `update` — downloading, checksum verification, archive extraction, installation;
- running scanners — argument handling, the environment they receive, output limits;
- `gate`, `policy`, `attest` — anything that lets a finding or an expired exception pass when
  it should not, including a `scan-result.json` the gate accepts although it was edited;
- report renderers — escaping, anything that makes a report execute or leak content;
- the release and CI configuration in `.github/` and `.goreleaser.yaml`.

## What is not

- Vulnerabilities in Trivy, Kubescape, Checkov or Popeye themselves — report those upstream.
  (If this tool handles their output in an unsafe way, that **is** in scope.)
- Findings a scanner reports about *your* cluster.
- Missing hardening that is already documented as not done — see the **Security** section of
  the README and `BLOCKED.md` (for example, cosign signature verification of scanners is not
  implemented yet, and `tools.lock.yaml` says so).

## Design notes useful to a reviewer

- Scanners are started without a shell and with fixed arguments; user-supplied values that
  start with `-` are refused.
- Downloads are verified against a pinned SHA-256 before anything is extracted or installed;
  a scanner with no pin for the platform is refused before any network request.
- `scan-result.json` is created owner-only (`0600`). Treat reports and the raw scanner output
  as confidential.

---

## Аюулгүй байдлын бодлого (товч)

Эмзэг байдал олсон бол нийтийн issue-д дэлгэрэнгүйг бичихгүй. GitHub-ийн **Security → Report
a vulnerability** ашиглана уу. Тэр сонголт харагдахгүй бол `security contact request` гарчигтай,
дэлгэрэнгүйгүй issue нээнэ үү — хаалттай суваг тохируулна. Энэ нь ганц хүний хөтөлдөг нээлттэй
эхийн төсөл тул хариу өгөх хугацааг амлахгүй; зөвхөн хамгийн сүүлийн хувилбар засвар авна.
