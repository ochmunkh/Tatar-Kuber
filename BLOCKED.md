# Blocked

Work that was started but cannot be finished here, with what it is waiting on.

## `tatar-kuber update` — three of four scanners are pinned

**Resolved 2026-09-30; pins widened to four platforms 2026-10-18.** The command
installs. `tools.lock.yaml` at the repo root ships pins for trivy, kubescape and
popeye — twelve checksums in all, one per scanner per platform
(linux/darwin x amd64/arm64).

Every value was **read out of the checksum file the project itself publishes on
the release**. None was computed from a local download. That distinction is the
whole point: a hash taken from a file you already have proves only that it did
not change on its way to you, which is not what a pin is for. `tools.lock.yaml`
records the same rule in its own header, and the two files must keep saying it.

The first round (2026-09-30) also downloaded the linux/amd64 artefact and
checked the computed hash against the published one, end to end: `tatar-kuber
update --scanner popeye` pulled 21 MB from GitHub, the SHA256 matched, the
binary installed and ran, and `tools.lock.yaml` recorded `installed: "0.22.1"`
separately from the pin. That was a verification of the mechanism, not the
source of any value in the file.

The catalogue's URL shapes were stale and were refreshed at the same time:
kubescape v4 renamed **every** asset (the v3 `kubescape-ubuntu-latest` names do
not exist on any v4 release) and checkov moved the version out of its filenames.
Both would have 404'd.

### kubescape's rules move without a version — now watched

kubescape does not embed its rules: it downloads the policy library at scan
time. So pinning the binary pins nothing about the meanings, and the rule set
can change **with no version bump at all**. The pin moved 4.0.15 -> 4.0.17 on
2026-11-10 without running the binary here (its library fetch verifies through
Sigstore's TUF root, which this environment cannot reach) — which matters less
than it sounds, precisely because the version does not carry the rules.

What does matter is now checked daily. `scripts/check-kubescape-rules.py` reads
the published control library, and compares every mapped `C-id` against the
meaning recorded in `TestKubescapeMappingsMatchUpstreamMeaning`. The Go test
still proves the registry agrees with what a human wrote down — it never touches
the network, and that rule is worth keeping — while the daily job proves that
what the human wrote down still agrees with upstream.

It found two on its first run: `C-0210` had grown "in your pod definitions", and
`C-0262` had gone from "Anonymous access enabled" to "Anonymous user has
RoleBinding". Both keep their meaning, so no mapping changed; the recorded names
were brought level. Nobody would have noticed either one.

### Still blocked: checkov has nothing to verify against

`bridgecrewio/checkov` publishes **no checksum file, no signature and no build
attestation** for its GitHub release archives. Release 3.3.20 ships four `.zip`
assets and nothing else; the release notes carry no digest; GitHub's
attestations endpoint returns 404 for the artefact.

So checkov is deliberately left unpinned and `update` refuses to install it —
the designed-for fail-closed state, not an oversight. Recording the SHA256 of a
zip downloaded here would say "this is what arrived on one machine on one day"
in the same shape as three pins that mean considerably more.

`internal/update/defaultlock_test.go` asserts the set of unpinned scanners is
exactly `{checkov}`, in both directions: dropping a pin fails, and **pinning
checkov also fails**, because that pin needs a human to record where the
checksum came from.

Ways out, for whoever picks this up:

* install checkov from PyPI, where every file has a recorded hash and
  `pip install --require-hashes` can enforce it. It is a wheel rather than a
  self-contained binary, so the adapter would need to know that.
* ask bridgecrewio to publish checksums for the release archives.
* accept trust-on-first-use for this one scanner, deliberately, and say so in
  `tools.lock.yaml`.

### Still blocked: cosign verification is a stub

`update.NoSignatureVerifier` checks nothing and answers `false`, and every
surface says so — the console prints a warning on each run and
`tools.lock.yaml` records `cosign: "unverified"`. The `SignatureVerifier`
interface is the seam a real implementation drops into; `Apply`, the lock file
and the CLI already handle both answers.

What is missing is a decision, not code: the trust root. Either sigstore
keyless verification against each project's published workflow identity, or a
pinned public key per scanner. Note kubescape already ships
`checksums.sha256.sig` and `checksums.sha256.pem` next to its release, so it is
the one that could be verified first.

### Pins are per-platform — and all four are now pinned

A release publishes a **different artefact per platform**, so one checksum pins
exactly one of them. Until 2026-10-18 this file carried a single value per
scanner: correct on linux/amd64, and a mismatch everywhere else — which `update`
reported as a corrupt download rather than as an unpinned platform. The lock
file is now keyed by platform and carries all four for each of the three
pinnable scanners.

`update` still refuses, by design, any scanner with no pin for the platform it
is running on. Windows is that case for all four: the catalogue has no Windows
assets, and `update` says so plainly instead of failing obscurely.

### Pinned versions drift

**Watched since 2026-10-30** (`.github/workflows/scanner-drift.yml`), **pins moved
2026-11-10.** The job compares each pin against upstream daily and keeps one
issue open. A check that cannot reach the API fails rather than reporting
"current".

Moving a pin is not a version edit, and trivy proved why. Its misconfiguration
rules are **embedded in the binary**, so a release can change the rule IDs
themselves: 0.76.1 emits `KSV-0001` where 0.74.0 emitted `AVD-KSV0001`, and
leaves `AVDID` empty entirely. Before the pin moved, trivy 0.76.1 was downloaded
(checksum verified against the published file), run against the Lab's `broken/`
manifests, and every rule ID it produced was resolved through the registry by
hand: 17 of 21 map, each to the control its title describes, and the four that
do not (`KSV-0020/0021` UID/GID bounds, `KSV-0044/0046` RBAC wildcards) are
reported as `unmapped_rules` rather than lost. The shape change is absorbed by
`NormalizeRuleID` — the fix that came out of the v1.0.0 incident, doing exactly
the job it was written for.

Two things this exercise exposed, both still open:

**The pin is not what CI exercises.** `real-cluster.yml` and `static-scan.yml`
install the scanners with each project's own `install.sh` or `pip`, which fetch
**latest** — not the pinned release. So the daily runs prove the mappings
survive against whatever shipped today, while `tools.lock.yaml` governs only
what a *user* gets from `tatar-kuber update`. Those are two different versions
and nothing says so. Making CI install from the lock would close the gap, at the
cost of no longer learning about upstream breakage the day it lands; running
both is the honest answer and is not written.

**"Behind upstream" is permanently true for fast-moving projects.** *(Fixed the
same day.)* Within the half hour it took to verify and move the pins on
2026-11-10, trivy released 0.76.2, kubescape 4.0.20 and checkov 3.4.3. A pin is
a *reviewed* version, not the newest one, so an issue raised on plain inequality
would never close — the same failure as a Security tab with twenty alerts nobody
reads any more, on a check built here to avoid exactly that.

The check now raises only where being behind means something: a **minor or major**
gap, which is the class of release that can move rule IDs (trivy 0.74 → 0.76
did), or a pin older than **90 days**, because patches accumulate and a pin
nobody has revisited in a season has stopped being a decision. A patch published
this morning is printed as information and raises nothing.

## `verify-lab` counts, it does not attribute

**Partly mitigated 2026-11-10.** The Lab corpus now runs inside the engine's CI
(`ci.yml`, job `lab`), so a change here that breaks the corpus turns this
repository red instead of leaving the net hanging on the wrong side.

What is still missing is inside `verify-lab` itself. It compares the set of
controls and the per-severity counts, so it cannot see one scanner's
contribution disappearing when another scanner happens to cover the same
control — the exact v1.0.0 failure, where Trivy contributed nothing and the
totals stayed healthy.

As a stopgap the CI job asserts that every scanner ran and contributed at least
one finding. That is a floor, not an expectation: the real fix is for
`expected-findings.json` to carry a per-scanner contribution and for
`verify-lab` to check it, which is a change to the Lab's expected-file format
and belongs in that repository.

Until then the floor lives in `.github/workflows/ci.yml`. It deliberately does
not record exact per-scanner numbers — that would be a second copy of
`expected-findings.json`, and the two would drift.
