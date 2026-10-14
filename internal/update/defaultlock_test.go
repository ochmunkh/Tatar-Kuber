package update

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot — the repository root, found from this file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(self))) // internal/update -> internal -> root
}

// defaultLockPath — tools.lock.yaml as shipped at the repo root.
func defaultLockPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(repoRoot(t), "tools.lock.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the shipped tools.lock.yaml is missing: %v", err)
	}
	return p
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// UNPINNED — scanners the shipped lock deliberately does NOT pin, with why.
//
// checkov publishes no checksum file, no signature and no build attestation for
// its GitHub release archives, so there is nothing to check a computed hash
// against. Recording one anyway would be a pin nobody reviewed, which is the
// thing tools.lock.yaml exists to prevent — so it is left empty and `update`
// refuses to install it.
//
// This is asserted as an exact set, in both directions. Pinning checkov should
// break this test: that pin needs a human to say where the checksum came from,
// and to delete the explanation in tools.lock.yaml that says there isn't one.
var unpinnedByDesign = map[string]string{
	"checkov": "upstream publishes no checksums for its release archives",
}

// Every scanner in the catalogue appears in the shipped lock, every pin is a
// well-formed SHA256, and the only scanner without one is the documented
// exception.
func TestDefaultLock_EveryPinIsWellFormed(t *testing.T) {
	lock, err := LoadLock(defaultLockPath(t))
	if err != nil {
		t.Fatalf("LoadLock on the shipped tools.lock.yaml: %v", err)
	}
	if len(lock.Tools) == 0 {
		t.Fatal("the shipped tools.lock.yaml pins nothing")
	}

	var missing, unpinned []string
	for _, name := range Scanners() {
		e, ok := lock.Tools[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if strings.TrimSpace(e.Version) == "" {
			t.Errorf("%s: version is empty", name)
		}
		if e.Cosign != CosignUnverified {
			t.Errorf("%s: cosign = %q, want %q — signature checking is not implemented, "+
				"so the shipped lock must never claim otherwise", name, e.Cosign, CosignUnverified)
		}
		sum := strings.TrimSpace(e.SHA256)
		if sum == "" {
			unpinned = append(unpinned, name)
			continue
		}
		if !sha256Hex.MatchString(sum) {
			t.Errorf("%s: sha256 = %q, want 64 lower-case hex characters", name, sum)
		}
		// Installed is written by Apply on the machine that runs it. The
		// shipped file is a starting point, so it must not claim an install.
		if e.Installed != "" {
			t.Errorf("%s: installed = %q — the shipped lock records pins, not installs",
				name, e.Installed)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("catalogue scanners absent from the shipped lock: %s", strings.Join(missing, ", "))
	}

	sort.Strings(unpinned)
	want := make([]string, 0, len(unpinnedByDesign))
	for n := range unpinnedByDesign {
		want = append(want, n)
	}
	sort.Strings(want)
	if strings.Join(unpinned, ",") != strings.Join(want, ",") {
		t.Errorf("unpinned scanners = %v, documented exceptions = %v.\n"+
			"  A NEW unpinned scanner means a pin was dropped.\n"+
			"  A scanner LEAVING this list means it gained a pin — say in tools.lock.yaml "+
			"where that checksum was checked against, and update unpinnedByDesign here.",
			unpinned, want)
	}
}

// The shipped lock is what Resolve reads when it is the home directory's lock,
// and a pinned scanner must come out of Resolve ready to install.
func TestDefaultLock_ResolvesToAnInstallablePlan(t *testing.T) {
	home := t.TempDir()
	src, err := os.ReadFile(defaultLockPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(LockPath(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(LockPath(home), src, 0o600); err != nil {
		t.Fatal(err)
	}

	plans, err := Resolve(Options{Home: home, Platform: Platform{OS: "linux", Arch: "amd64"}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, p := range plans {
		_, exempt := unpinnedByDesign[p.Scanner]
		if p.Pinned() == exempt {
			t.Errorf("%s: Pinned()=%v but exempt=%v", p.Scanner, p.Pinned(), exempt)
		}
		if p.URL == "" || strings.Contains(p.URL, "{v}") {
			t.Errorf("%s: URL is unresolved: %q", p.Scanner, p.URL)
		}
		if !strings.Contains(p.URL, p.Version) {
			t.Errorf("%s: URL %q does not carry version %q — the catalogue's asset name "+
				"is probably stale for this release", p.Scanner, p.URL, p.Version)
		}
		// Nothing here touches the network: Resolve is pure.
	}
}
