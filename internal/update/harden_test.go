package update

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The lock's version is substituted into a download URL. These tests pin the
// guards that keep a hand-edited or hostile tools.lock.yaml from steering it.

func TestResolve_RejectsUnsafeLockVersion(t *testing.T) {
	for _, v := range []string{
		"1.0/../../evil",        // path traversal
		"1.0?x=1",               // query
		"1.0#frag",              // fragment
		"1.0 2.0",               // whitespace
		"..",                    // dots only
		"-1.0",                  // leading flag-like char
		"1.0\n2.0",              // newline
		"",                      // not reached: empty falls back to the catalogue
		strings.Repeat("a", 70), // too long
	} {
		if v == "" {
			continue
		}
		home := t.TempDir()
		lock := Lock{Tools: map[string]LockEntry{"trivy": {Version: v}}}
		if err := SaveLock(LockPath(home), lock); err != nil {
			// A version SaveLock cannot even write is refused earlier still.
			continue
		}
		_, err := Resolve(Options{Home: home, Scanners: []string{"trivy"}, Platform: Platform{OS: "linux", Arch: "amd64"}})
		var ive *InvalidVersionError
		if !errors.As(err, &ive) {
			t.Errorf("version %q: want InvalidVersionError, got %v", v, err)
		}
	}
}

func TestValidVersion(t *testing.T) {
	for _, ok := range []string{"0.76.1", "4.0.17", "v1.2.3", "1.2.3-rc.1", "1.2.3+build.5", "2026_11"} {
		if !validVersion(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "/", "a/b", "a b", "a?b", "-x", ".1", "a\x00b"} {
		if validVersion(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestSaveLock_LeavesNoTempFileAndRoundTrips(t *testing.T) {
	home := t.TempDir()
	path := LockPath(home)
	lock := Lock{Tools: map[string]LockEntry{"trivy": {Version: "0.76.1", Cosign: CosignUnverified}}}
	for i := 0; i < 3; i++ { // overwriting must be as clean as creating
		if err := SaveLock(path, lock); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != filepath.Base(path) {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("lock directory should hold only the lock, got %v", names)
	}
	got, err := LoadLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tools["trivy"].Version != "0.76.1" {
		t.Fatalf("round trip lost the pin: %+v", got.Tools["trivy"])
	}
	if fi, _ := os.Stat(path); fi != nil && fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("lock must stay private, mode %v", fi.Mode().Perm())
	}
}

func TestCommitStaged_KeepsWorkingInstallWhenSwapFails(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "trivy")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dest, "trivy")
	if err := os.WriteFile(keep, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The staged directory does not exist, so the second rename must fail.
	if _, err := commitStaged(filepath.Join(base, "missing-stage"), dest, "trivy"); err == nil {
		t.Fatal("commit of a missing stage must fail")
	}
	b, err := os.ReadFile(keep)
	if err != nil || string(b) != "old" {
		t.Fatalf("the working install must survive a failed swap: %v %q", err, b)
	}
	if _, err := os.Stat(dest + ".old"); err == nil {
		t.Fatal("the .old copy must not be left behind")
	}
}

func TestCommitStaged_ReplacesAndCleansUp(t *testing.T) {
	base := t.TempDir()
	dest := filepath.Join(base, "trivy")
	stage := filepath.Join(base, "stage")
	for _, d := range []string{dest, stage} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dest, "trivy"), []byte("old"), 0o700)
	_ = os.WriteFile(filepath.Join(stage, "trivy"), []byte("new"), 0o700)
	bin, err := commitStaged(stage, dest, "trivy")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "new" {
		t.Fatalf("new install not in place: %q", b)
	}
	if _, err := os.Stat(dest + ".old"); err == nil {
		t.Fatal(".old must be removed after a successful swap")
	}
}
