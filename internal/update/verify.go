package update

import (
	"context"
	"fmt"
)

// SignatureVerifier — the cosign step of the specification's sequence
// (Doc #5 §5):
//
//	download -> verify checksum (SHA256) -> verify signature (cosign) -> install -> lock
//
// It is an interface so that a real implementation drops in without any caller
// changing shape: Apply hands every artefact it has already checksummed to the
// verifier and records the answer, whatever the answer is.
type SignatureVerifier interface {
	// Name — how this verifier is identified on screen. It is NOT what goes
	// into tools.lock.yaml; the lock records the outcome, not the tool.
	Name() string

	// Verify reports whether artefact (a path to the downloaded file) carries
	// a valid signature for plan.
	//
	// verified=false with err=nil means "not checked" — the artefact may be
	// perfectly well signed, nobody looked. An err means the check itself
	// failed and the caller must treat the artefact as unusable.
	Verify(ctx context.Context, plan Plan, artefact string) (verified bool, err error)
}

// NoSignatureVerifier — the default verifier, and it verifies NOTHING.
//
// TODO(v2): replace with a real cosign verifier (sigstore keyless verification
// against each project's published identity, or a pinned public key per
// scanner). The only thing that changes is which SignatureVerifier Options
// carries; Apply, the lock file and the CLI already handle both answers.
//
// It answers false — never true — so that neither the console output nor
// tools.lock.yaml can claim a signature was checked when none was. A stub that
// returned true would be worse than no stub at all: it would turn the whole
// verification step into a lie the lock file then preserves.
type NoSignatureVerifier struct{}

// Name — "none", because that is what is doing the verifying.
func (NoSignatureVerifier) Name() string { return "none" }

// Verify — always (false, nil): not checked.
func (NoSignatureVerifier) Verify(context.Context, Plan, string) (bool, error) { return false, nil }

// cosignStatus — the lock file value for a verifier's answer.
func cosignStatus(verified bool) string {
	if verified {
		return CosignVerified
	}
	return CosignUnverified
}

// ChecksumError — the downloaded artefact is not the artefact that was pinned.
//
// This is a hard failure by design: it is the one moment where an unverified
// binary could reach the disk, and the whole point of the step is that it
// never does.
type ChecksumError struct {
	Scanner string
	Want    string
	Got     string
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf("%s: SHA256 mismatch — pinned %s, downloaded %s", e.Scanner, e.Want, e.Got)
}

// UnpinnedError — nothing pins this scanner's checksum, so there is nothing to
// verify against. Refused before the network is touched: trust-on-first-use is
// exactly what a security tool must not do.
type UnpinnedError struct {
	Scanner  string
	Version  string
	Platform Platform
	LockPath string
}

func (e *UnpinnedError) Error() string {
	return fmt.Sprintf("%s: no pinned sha256 for %s %s — refusing to download a binary that cannot be verified (pin it in %s)",
		e.Scanner, e.Version, e.Platform, e.LockPath)
}

// UnknownScannerError — --scanner named something the catalogue does not know.
// A usage error, not a runtime one.
type UnknownScannerError struct {
	Name  string
	Known []string
}

func (e *UnknownScannerError) Error() string {
	return fmt.Sprintf("unknown scanner %q", e.Name)
}

// UnsupportedPlatformError — the release publishes no asset for this os/arch.
type UnsupportedPlatformError struct {
	Scanner   string
	Platform  Platform
	Available []string
}

func (e *UnsupportedPlatformError) Error() string {
	return fmt.Sprintf("%s: no release asset for %s", e.Scanner, e.Platform)
}
