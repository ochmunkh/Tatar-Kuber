# Blocked

Work that was started but cannot be finished here, with what it is waiting on.

## `tatar-kuber update` — three of four scanners are pinned

**Resolved 2026-09-30.** The command installs. `tools.lock.yaml` at the repo
root ships pins for trivy, kubescape and popeye, each obtained the only way a
pin is worth anything:

1. the latest stable release was read from the project's GitHub releases API
2. the linux/amd64 artefact was downloaded
3. its SHA256 was computed locally
4. that value was compared against the checksum file the project itself
   publishes on the same release

All three matched. Step 4 is the one that counts — a checksum computed from a
download you already have proves only that the file did not change in transit.

Verified end to end against the live release: `tatar-kuber update --scanner
popeye` downloaded 21 MB from GitHub, the SHA256 matched the pin, the binary
installed and runs, and `tools.lock.yaml` recorded `installed: "0.22.1"`
separately from the pin.

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

### Pins are per-platform

The shipped pins are for **linux/amd64**. `update` on another platform resolves
a different asset, whose checksum is not in the file, and refuses until someone
pins it the same way.
