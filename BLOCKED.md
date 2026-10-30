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

The pins name specific releases (trivy 0.74.0, kubescape 4.0.15, popeye 0.22.1,
checkov 3.3.20 as of 2026-10-18). Upstream moves; nothing in CI notices yet, so
the pins go stale silently. A daily job that compares each pin against the
project's latest release and opens an issue is the obvious fix and is not
written.

Checked by hand on 2026-10-30, twelve days after the pins were written: trivy
0.74.0 -> 0.76.1, kubescape 4.0.15 -> 4.0.17, checkov 3.3.20 -> 3.4.0. Only
popeye was still current. Three of four drifted inside two weeks and nothing
said so.
