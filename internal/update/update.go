// Package update implements `tatar-kuber update`: it fetches the pinned
// scanner binaries and verifies them before any of them reaches the disk.
//
// The order of the steps is the specification's (Doc #5 §5), not an
// implementation detail:
//
//	download -> verify checksum (SHA256) -> verify signature (cosign) -> install -> lock
//
// Three properties carry the security of this package:
//
//   - A scanner with no pinned checksum is REFUSED before the network is
//     touched. There is no trust-on-first-use path: the pin comes from
//     tools.lock.yaml, where a human put it after comparing it with what the
//     upstream project published.
//   - Nothing is installed until EVERY requested scanner has been downloaded,
//     checksum-verified AND unpacked. A mismatch, or an unreadable archive,
//     therefore installs nothing at all rather than "everything except the bad
//     one". The final step is a rename per scanner; that is not a transaction,
//     but by then everything that realistically fails has already happened.
//   - The cosign step is a stub (see verify.go) and says so everywhere it is
//     visible: on screen and in tools.lock.yaml. It never reports "verified".
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxArtefact — refuse an artefact larger than this. Trivy's tarball is the
// biggest of the four by a wide margin and is well under 200 MiB; the cap is
// here so that a wrong or hostile URL cannot fill the disk.
const maxArtefact = 512 << 20

// Options — one `update` invocation.
type Options struct {
	Home     string   // ~/.tatar-kuber (tools.lock.yaml and tools/ live here)
	Scanners []string // empty = every scanner in the catalogue
	Platform Platform // zero value = CurrentPlatform()
	Client   *http.Client
	Verifier SignatureVerifier // nil = NoSignatureVerifier (verifies nothing)
}

func (o Options) platform() Platform {
	if o.Platform.zero() {
		return CurrentPlatform()
	}
	return o.Platform
}

func (o Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

func (o Options) verifier() SignatureVerifier {
	if o.Verifier != nil {
		return o.Verifier
	}
	return NoSignatureVerifier{}
}

// Plan — what update WOULD do for one scanner. Resolve builds these without
// touching the network, which is what makes --dry-run and --check honest.
type Plan struct {
	Scanner  string
	Version  string
	URL      string
	SHA256   string // pinned expected checksum; "" when nothing pins it
	Archive  Archive
	Platform Platform

	// Installed — the version tools.lock.yaml records as being in place, or ""
	// when the scanner has never been installed through update. --check reads
	// this; it is not a claim that the binary is still on disk.
	Installed string
}

// Pinned — is there a checksum to verify the download against?
func (p Plan) Pinned() bool { return p.SHA256 != "" }

// Result — what Apply did for one scanner.
type Result struct {
	Plan       Plan
	BinPath    string // the installed scanner binary
	SigChecked bool   // a signature was checked AND accepted (false while cosign is a stub)
}

// Resolve — the plan for each requested scanner. Reads tools.lock.yaml and
// nothing else; makes no request.
func Resolve(opts Options) ([]Plan, error) {
	names := opts.Scanners
	if len(names) == 0 {
		names = Scanners()
	}
	lock, err := LoadLock(LockPath(opts.Home))
	if err != nil {
		return nil, err
	}
	plat := opts.platform()

	plans := make([]Plan, 0, len(names))
	for _, name := range names {
		t, ok := lookup(name)
		if !ok {
			return nil, &UnknownScannerError{Name: name, Known: Scanners()}
		}
		entry, locked := lock.Tools[name]

		// The lock pins the version; the catalogue's is only the fallback for a
		// scanner that has never been locked.
		version := t.Version
		if locked && entry.Version != "" {
			version = entry.Version
		}
		a, ok := t.Assets[plat.String()]
		if !ok {
			return nil, &UnsupportedPlatformError{Scanner: name, Platform: plat, Available: t.platforms()}
		}

		// A checksum only pins the artefact it was taken from, so it is used
		// only when the lock's version is the version being installed.
		sum := ""
		if locked && entry.Version == version {
			sum = entry.SHA256
		}
		plans = append(plans, Plan{
			Scanner:   name,
			Version:   version,
			URL:       expand(a.URL, version),
			SHA256:    sum,
			Archive:   a.Archive,
			Platform:  plat,
			Installed: entry.Installed,
		})
	}
	return plans, nil
}

// Apply — download, verify and install every requested scanner, then rewrite
// tools.lock.yaml.
//
// The specification's sequence runs per artefact down to the signature step;
// install is then deferred until every artefact has passed, which is what makes
// a checksum mismatch install nothing at all.
func Apply(ctx context.Context, opts Options) ([]Result, error) {
	plans, err := Resolve(opts)
	if err != nil {
		return nil, err
	}
	// Refuse before the network: an unverifiable download is not worth making.
	for _, p := range plans {
		if !p.Pinned() {
			return nil, &UnpinnedError{
				Scanner: p.Scanner, Version: p.Version, Platform: p.Platform,
				LockPath: LockPath(opts.Home),
			}
		}
	}

	if err := os.MkdirAll(opts.Home, 0o700); err != nil {
		return nil, err
	}
	// Staging lives under Home so that the install below is a rename within one
	// filesystem, and is removed however this function returns (Doc #5 §9:
	// temp files are cleaned up when the run ends).
	stage, err := os.MkdirTemp(opts.Home, ".update-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	type staged struct {
		plan       Plan
		artefact   string
		sigChecked bool
	}
	ready := make([]staged, 0, len(plans))

	for _, p := range plans {
		artefact := filepath.Join(stage, p.Scanner+".artefact")
		sum, err := fetch(ctx, opts.client(), p.URL, artefact)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Scanner, err)
		}
		// Hex case is not part of a checksum: release pages publish both, and
		// rejecting an upper-case pin as a MISMATCH would read as a
		// supply-chain alarm rather than the formatting difference it is.
		if !strings.EqualFold(sum, p.SHA256) {
			return nil, &ChecksumError{Scanner: p.Scanner, Want: p.SHA256, Got: sum}
		}
		checked, err := opts.verifier().Verify(ctx, p, artefact)
		if err != nil {
			return nil, fmt.Errorf("%s: signature verification: %w", p.Scanner, err)
		}
		ready = append(ready, staged{plan: p, artefact: artefact, sigChecked: checked})
	}

	// Everything verified — only now does anything leave the staging directory.
	tools := ToolsDir(opts.Home)
	if err := os.MkdirAll(tools, 0o755); err != nil {
		return nil, err
	}
	// Re-read rather than reuse Resolve's copy: the lock is rewritten whole, so
	// the entries for scanners this run did not touch have to be carried over.
	lock, err := LoadLock(LockPath(opts.Home))
	if err != nil {
		return nil, err
	}
	// Unpack every artefact BEFORE replacing any installed scanner. Installing
	// inside this loop meant a failure unpacking the third scanner left the
	// first two already replaced — a half-updated toolchain, reported only as
	// an error. Now a failure here leaves every installed scanner untouched.
	type unpacked struct {
		staged
		dir string // <tools>/<scanner>.new
		rel string // the binary, relative to dir
	}
	all := make([]unpacked, 0, len(ready))
	defer func() {
		// Whatever happens, no .new directory outlives this call. On the happy
		// path commitStaged has already renamed them away and this is a no-op.
		for _, u := range all {
			_ = os.RemoveAll(u.dir)
		}
	}()
	for _, s := range ready {
		dir, rel, err := unpackStaged(s.artefact, s.plan.Archive, s.plan.Scanner, tools)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.plan.Scanner, err)
		}
		all = append(all, unpacked{staged: s, dir: dir, rel: rel})
	}

	// Commit. This is the only step that touches an installed scanner, and it
	// is now just a RemoveAll + Rename per tool. It is not a transaction — a
	// failure part way still leaves earlier scanners replaced — but everything
	// that can realistically fail (network, checksum, archive) has already
	// happened by this point.
	results := make([]Result, 0, len(all))
	for _, u := range all {
		bin, err := commitStaged(u.dir, filepath.Join(tools, u.plan.Scanner), u.rel)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u.plan.Scanner, err)
		}
		lock.Tools[u.plan.Scanner] = LockEntry{
			Version: u.plan.Version,
			SHA256:  u.plan.SHA256,
			Cosign:  cosignStatus(u.sigChecked),
			// Only Apply ever writes this, which is what makes --check able to
			// tell "pinned in the lock" from "actually installed".
			Installed: u.plan.Version,
		}
		results = append(results, Result{Plan: u.plan, BinPath: bin, SigChecked: u.sigChecked})
	}
	if err := SaveLock(LockPath(opts.Home), lock); err != nil {
		return nil, err
	}
	return results, nil
}

// HTTPError — the release URL did not serve the artefact.
type HTTPError struct {
	URL    string
	Status string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("download %s: %s", e.URL, e.Status) }

// fetch — stream the artefact to dst, hashing as it goes, and return the hex
// SHA256. Hashing the stream rather than re-reading the file means the bytes
// that were written are the bytes that were hashed.
func fetch(ctx context.Context, client *http.Client, url, dst string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", &HTTPError{URL: url, Status: resp.Status}
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- dst is a file we just created a temp dir for
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxArtefact+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxArtefact {
		return "", errors.New("artefact is larger than the 512 MiB limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
