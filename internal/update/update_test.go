package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ── The update command's whole job is to refuse ──────────────────────────────
//
// Every test here runs against a net/http/httptest server: no test reaches the
// network, so the suite stays offline and deterministic. What is actually
// asserted is the failure side — a mismatching checksum, an HTTP error and a
// scanner nobody pinned must all leave the tools directory exactly as they
// found it. A downloader that installs is easy; one that refuses to is the
// product.

const testPlatform = "test/arch"

var plat = Platform{OS: "test", Arch: "arch"}

// ── artefact builders ────────────────────────────────────────────────────────

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// tarGzWith — a release tarball carrying the binary next to other files, which
// is how trivy and popeye ship: the binary has to be found, not assumed.
func tarGzWith(t *testing.T, member string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, mode int64, data []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("LICENSE", 0o644, []byte("Apache-2.0"))
	write(member, 0o755, body)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zipWith — a PyInstaller-shaped bundle: the executable sits below a directory,
// which is how checkov ships.
func zipWith(t *testing.T, member string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ── mock release server ──────────────────────────────────────────────────────

type releases struct {
	mu   sync.Mutex
	hits []string
}

func (r *releases) served() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.hits...)
}

// serveAssets — one artefact per URL path. A path that is not in the map is a
// 500, which is how the HTTP-error case is produced.
func serveAssets(t *testing.T, assets map[string][]byte) (*httptest.Server, *releases) {
	t.Helper()
	rec := &releases{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.hits = append(rec.hits, r.URL.Path)
		rec.mu.Unlock()
		body, ok := assets[r.URL.Path]
		if !ok {
			http.Error(w, "no such release asset", http.StatusInternalServerError)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("serving %s: %v", r.URL.Path, err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// useCatalogue — point the built-in catalogue at the mock server for one test.
func useCatalogue(t *testing.T, tools ...tool) {
	t.Helper()
	saved := catalogue
	catalogue = tools
	t.Cleanup(func() { catalogue = saved })
}

func mockTool(name, version, url string, kind Archive) tool {
	return tool{
		Name:    name,
		Version: version,
		Assets:  map[string]asset{testPlatform: {URL: url, Archive: kind}},
	}
}

func opts(home string, srv *httptest.Server, scanners ...string) Options {
	return Options{Home: home, Scanners: scanners, Platform: plat, Client: srv.Client()}
}

// installedBinaries — every regular file under <home>/tools, so a test can say
// "nothing was installed" about the whole directory rather than one path.
func installedBinaries(t *testing.T, home string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(ToolsDir(home), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(ToolsDir(home), path)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return out
}

// ── the happy path ───────────────────────────────────────────────────────────

func TestApply_DownloadVerifyInstallLock(t *testing.T) {
	binary := []byte("#!/bin/sh\necho trivy 9.9.9\n")
	artefact := tarGzWith(t, "trivy", binary)
	srv, rec := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": artefact})
	useCatalogue(t, mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))

	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: sum(artefact), Cosign: CosignUnverified},
	}}); err != nil {
		t.Fatal(err)
	}

	results, err := Apply(context.Background(), opts(home, srv))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results=%d, want 1", len(results))
	}
	got, err := os.ReadFile(results[0].BinPath)
	if err != nil {
		t.Fatalf("installed binary: %v", err)
	}
	if !bytes.Equal(got, binary) {
		t.Errorf("installed binary content = %q", got)
	}
	fi, err := os.Stat(results[0].BinPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("installed binary is not executable: %v", fi.Mode())
	}
	// The rest of the tarball comes along: the licence next to the binary is
	// part of what was shipped.
	if _, err := os.Stat(filepath.Join(filepath.Dir(results[0].BinPath), "LICENSE")); err != nil {
		t.Errorf("LICENSE not unpacked: %v", err)
	}
	if len(rec.served()) != 1 {
		t.Errorf("requests = %v, want exactly one", rec.served())
	}

	// The lock records the install, and records that nobody checked a signature.
	lock, err := LoadLock(LockPath(home))
	if err != nil {
		t.Fatal(err)
	}
	e := lock.Tools["trivy"]
	if e.Version != "1.2.3" || e.SHA256 != sum(artefact) {
		t.Errorf("lock entry = %+v", e)
	}
	if e.Cosign != CosignUnverified {
		t.Errorf("lock cosign = %q, want %q — the stub verifier must never claim a signature was checked",
			e.Cosign, CosignUnverified)
	}
	if results[0].SigChecked {
		t.Error("SigChecked = true with the no-op verifier")
	}
}

// A raw asset (kubescape) and a zip bundle (checkov) install too, and the
// binary is found wherever the project happens to put it.
func TestApply_RawAndZipAssets(t *testing.T) {
	raw := []byte("kubescape-binary")
	bundle := zipWith(t, "dist/checkov/checkov", []byte("checkov-binary"))
	srv, _ := serveAssets(t, map[string][]byte{
		"/kubescape-1.0.0":   raw,
		"/checkov-2.0.0.zip": bundle,
	})
	useCatalogue(t,
		mockTool("kubescape", "1.0.0", srv.URL+"/kubescape-{v}", ArchiveRaw),
		mockTool("checkov", "2.0.0", srv.URL+"/checkov-{v}.zip", ArchiveZip),
	)

	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"kubescape": {Version: "1.0.0", SHA256: sum(raw)},
		"checkov":   {Version: "2.0.0", SHA256: sum(bundle)},
	}}); err != nil {
		t.Fatal(err)
	}

	results, err := Apply(context.Background(), opts(home, srv))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
	for _, r := range results {
		if filepath.Base(r.BinPath) != r.Plan.Scanner {
			t.Errorf("%s: installed binary is %s", r.Plan.Scanner, r.BinPath)
		}
		if _, err := os.Stat(r.BinPath); err != nil {
			t.Errorf("%s: %v", r.Plan.Scanner, err)
		}
	}
}

// ── the refusals ─────────────────────────────────────────────────────────────

// A checksum mismatch is the case the whole step exists for: it must fail, and
// it must leave nothing behind.
func TestApply_ChecksumMismatchInstallsNothing(t *testing.T) {
	artefact := tarGzWith(t, "trivy", []byte("the binary that was actually served"))
	srv, _ := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": artefact})
	useCatalogue(t, mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))

	home := t.TempDir()
	pinned := sum([]byte("a different artefact entirely"))
	before := Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: pinned, Cosign: CosignUnverified},
	}}
	if err := SaveLock(LockPath(home), before); err != nil {
		t.Fatal(err)
	}
	lockBefore, err := os.ReadFile(LockPath(home))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Apply(context.Background(), opts(home, srv))
	var mismatch *ChecksumError
	if !errors.As(err, &mismatch) {
		t.Fatalf("Apply error = %v, want *ChecksumError", err)
	}
	if mismatch.Want != pinned || mismatch.Got != sum(artefact) {
		t.Errorf("ChecksumError = %+v", mismatch)
	}
	if got := installedBinaries(t, home); len(got) != 0 {
		t.Errorf("a mismatching artefact installed %v — it must install NOTHING", got)
	}
	lockAfter, err := os.ReadFile(LockPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lockBefore, lockAfter) {
		t.Error("tools.lock.yaml was rewritten although nothing was installed")
	}
}

// One bad scanner poisons the whole run: a half-updated toolchain is not a
// state this command may leave behind.
func TestApply_OneMismatchInstallsNoneOfThem(t *testing.T) {
	good := tarGzWith(t, "trivy", []byte("trivy"))
	bad := tarGzWith(t, "popeye", []byte("popeye"))
	srv, _ := serveAssets(t, map[string][]byte{
		"/trivy-1.0.0.tar.gz":  good,
		"/popeye-2.0.0.tar.gz": bad,
	})
	useCatalogue(t,
		mockTool("trivy", "1.0.0", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz),
		mockTool("popeye", "2.0.0", srv.URL+"/popeye-{v}.tar.gz", ArchiveTarGz),
	)

	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy":  {Version: "1.0.0", SHA256: sum(good)},
		"popeye": {Version: "2.0.0", SHA256: sum([]byte("not what is served"))},
	}}); err != nil {
		t.Fatal(err)
	}

	if _, err := Apply(context.Background(), opts(home, srv)); err == nil {
		t.Fatal("Apply succeeded with a mismatching popeye")
	}
	if got := installedBinaries(t, home); len(got) != 0 {
		t.Errorf("installed %v — the verified trivy must not land either", got)
	}
}

// An HTTP failure is a failure: no partial file, no lock entry.
func TestApply_HTTPErrorInstallsNothing(t *testing.T) {
	srv, _ := serveAssets(t, map[string][]byte{}) // every path is a 500
	useCatalogue(t, mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))

	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: sum([]byte("anything"))},
	}}); err != nil {
		t.Fatal(err)
	}

	_, err := Apply(context.Background(), opts(home, srv))
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("Apply error = %v, want *HTTPError", err)
	}
	if got := installedBinaries(t, home); len(got) != 0 {
		t.Errorf("installed %v after an HTTP error", got)
	}
}

// Nothing pinned means nothing downloaded — the refusal comes before the
// request, because trust-on-first-use is the thing being refused.
func TestApply_UnpinnedIsRefusedBeforeAnyRequest(t *testing.T) {
	srv, rec := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": []byte("never fetched")})
	useCatalogue(t, mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))

	home := t.TempDir() // no tools.lock.yaml at all
	_, err := Apply(context.Background(), opts(home, srv))
	var unpinned *UnpinnedError
	if !errors.As(err, &unpinned) {
		t.Fatalf("Apply error = %v, want *UnpinnedError", err)
	}
	if got := rec.served(); len(got) != 0 {
		t.Errorf("requests = %v — an unverifiable download must not be made at all", got)
	}
	if got := installedBinaries(t, home); len(got) != 0 {
		t.Errorf("installed %v", got)
	}
}

// The lock is the pin: it decides the version, and the catalogue's default is
// only what a scanner that has never been locked falls back to.
func TestResolve_TheLockDecidesTheVersion(t *testing.T) {
	useCatalogue(t, mockTool("trivy", "2.0.0", "https://example.invalid/trivy-{v}.tar.gz", ArchiveTarGz))
	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.0.0", SHA256: "deadbeef"},
	}}); err != nil {
		t.Fatal(err)
	}
	plans, err := Resolve(Options{Home: home, Platform: plat})
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].Version != "1.0.0" || plans[0].URL != "https://example.invalid/trivy-1.0.0.tar.gz" {
		t.Errorf("plan = %+v, want the lock's 1.0.0", plans[0])
	}
	if !plans[0].Pinned() {
		t.Error("the lock pins 1.0.0 and 1.0.0 is what would be installed — want pinned")
	}
}

// A checksum that is not attached to the version being installed pins nothing.
// A hand-edited lock that kept a sha256 but dropped the version it belonged to
// must come out as "not pinned", not as "pinned to whatever is current".
func TestResolve_AChecksumWithoutItsVersionPinsNothing(t *testing.T) {
	useCatalogue(t, mockTool("trivy", "2.0.0", "https://example.invalid/trivy-{v}.tar.gz", ArchiveTarGz))
	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {SHA256: "deadbeef"},
	}}); err != nil {
		t.Fatal(err)
	}
	plans, err := Resolve(Options{Home: home, Platform: plat})
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].Version != "2.0.0" {
		t.Errorf("version = %q, want the catalogue default", plans[0].Version)
	}
	if plans[0].Pinned() {
		t.Errorf("SHA256 = %q — a checksum with no version must not pin the catalogue default",
			plans[0].SHA256)
	}
}

// ── --dry-run ────────────────────────────────────────────────────────────────

// Resolve is what --dry-run prints. It must make no request and write no file,
// which is also why it can be called before the flags are even looked at.
func TestResolve_TouchesNeitherNetworkNorDisk(t *testing.T) {
	srv, rec := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": []byte("never fetched")})
	useCatalogue(t,
		mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz),
		mockTool("popeye", "0.9.0", srv.URL+"/popeye-{v}.tar.gz", ArchiveTarGz),
	)
	home := t.TempDir()

	plans, err := Resolve(opts(home, srv))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("plans=%d, want 2", len(plans))
	}
	// Everything --dry-run has to print is on the plan.
	if plans[0].Scanner != "trivy" || plans[0].Version != "1.2.3" ||
		plans[0].URL != srv.URL+"/trivy-1.2.3.tar.gz" {
		t.Errorf("plan = %+v", plans[0])
	}
	if plans[0].Pinned() {
		t.Errorf("SHA256 = %q with no lock file — want empty (\"not pinned\")", plans[0].SHA256)
	}
	if got := rec.served(); len(got) != 0 {
		t.Errorf("requests = %v, want none", got)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("Resolve wrote %d entries into the home directory, want 0", len(entries))
	}
}

func TestResolve_UnknownScannerIsAUsageError(t *testing.T) {
	useCatalogue(t, mockTool("trivy", "1.2.3", "https://example.invalid/{v}", ArchiveRaw))
	_, err := Resolve(Options{Home: t.TempDir(), Scanners: []string{"nmap"}, Platform: plat})
	var unknown *UnknownScannerError
	if !errors.As(err, &unknown) {
		t.Fatalf("error = %v, want *UnknownScannerError", err)
	}
	if unknown.Name != "nmap" || len(unknown.Known) != 1 {
		t.Errorf("error = %+v", unknown)
	}
}

func TestResolve_UnsupportedPlatform(t *testing.T) {
	useCatalogue(t, mockTool("trivy", "1.2.3", "https://example.invalid/{v}", ArchiveRaw))
	_, err := Resolve(Options{Home: t.TempDir(), Platform: Platform{OS: "plan9", Arch: "mips"}})
	var unsupported *UnsupportedPlatformError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error = %v, want *UnsupportedPlatformError", err)
	}
}

// ── lock file ────────────────────────────────────────────────────────────────

func TestLock_RoundTripsAndIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tools.lock.yaml")
	in := Lock{Tools: map[string]LockEntry{
		"popeye": {Version: "0.21.5", SHA256: "bbbb", Cosign: CosignUnverified},
		"trivy":  {Version: "0.53.0", SHA256: "aaaa", Cosign: CosignUnverified},
	}}
	if err := SaveLock(path, in); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := LoadLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Tools) != 2 || out.Tools["trivy"] != in.Tools["trivy"] {
		t.Fatalf("round trip = %+v", out.Tools)
	}
	// Rewriting an unchanged lock must produce an unchanged file, or every run
	// shows up as a change.
	if err := SaveLock(path, out); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("SaveLock is not deterministic:\n%s\n---\n%s", first, second)
	}
	if !bytes.Contains(first, []byte(CosignUnverified)) {
		t.Error("the lock file does not say the signature was unverified")
	}
	if bytes.Contains(first, []byte(`cosign:  "`+CosignVerified+`"`)) {
		t.Error("the lock file claims a signature was verified")
	}
}

func TestLoadLock_MissingFileIsEmptyNotAnError(t *testing.T) {
	l, err := LoadLock(filepath.Join(t.TempDir(), "tools.lock.yaml"))
	if err != nil {
		t.Fatalf("LoadLock: %v", err)
	}
	if len(l.Tools) != 0 {
		t.Errorf("Tools = %+v, want empty", l.Tools)
	}
}

// ── unpacking ────────────────────────────────────────────────────────────────

// An archive member that points outside the install directory is refused
// rather than written (zip slip / "../" tar entries).
func TestInstall_RefusesAnEscapingMember(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../escaped")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("nope")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	artefact := filepath.Join(dir, "evil.zip")
	if err := os.WriteFile(artefact, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(dir, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := install(artefact, ArchiveZip, "checkov", tools); err == nil {
		t.Fatal("install accepted a member escaping the install directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped")); !os.IsNotExist(err) {
		t.Error("the escaping member was written outside the install directory")
	}
}

// An artefact without the scanner binary in it is a failed install, not a
// silent success that leaves `doctor` reporting the tool as missing.
func TestInstall_FailsWhenTheBinaryIsNotInTheArtefact(t *testing.T) {
	dir := t.TempDir()
	artefact := filepath.Join(dir, "trivy.tar.gz")
	if err := os.WriteFile(artefact, tarGzWith(t, "README.md", []byte("hello")), 0o600); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(dir, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := install(artefact, ArchiveTarGz, "trivy", tools); err == nil {
		t.Fatal("install succeeded without a trivy binary in the artefact")
	}
}

// ── the cosign stub ──────────────────────────────────────────────────────────

func TestNoSignatureVerifier_NeverReportsVerified(t *testing.T) {
	ok, err := NoSignatureVerifier{}.Verify(context.Background(), Plan{Scanner: "trivy"}, "/dev/null")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("the no-op verifier reported a verified signature")
	}
	if got := cosignStatus(ok); got != CosignUnverified {
		t.Errorf("cosignStatus = %q, want %q", got, CosignUnverified)
	}
}

// The interface is the seam a real cosign verifier drops into: Apply records
// whatever it answers, without any caller changing shape.
type acceptingVerifier struct{ calls int }

func (a *acceptingVerifier) Name() string { return "test" }
func (a *acceptingVerifier) Verify(context.Context, Plan, string) (bool, error) {
	a.calls++
	return true, nil
}

func TestApply_RecordsAVerifierThatDoesCheck(t *testing.T) {
	artefact := tarGzWith(t, "trivy", []byte("trivy"))
	srv, _ := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": artefact})
	useCatalogue(t, mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))

	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: sum(artefact)},
	}}); err != nil {
		t.Fatal(err)
	}
	v := &acceptingVerifier{}
	o := opts(home, srv)
	o.Verifier = v

	results, err := Apply(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if v.calls != 1 {
		t.Errorf("verifier called %d times, want 1", v.calls)
	}
	if !results[0].SigChecked {
		t.Error("SigChecked = false although the verifier accepted the artefact")
	}
	lock, err := LoadLock(LockPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if lock.Tools["trivy"].Cosign != CosignVerified {
		t.Errorf("lock cosign = %q, want %q", lock.Tools["trivy"].Cosign, CosignVerified)
	}
}

// Updating one scanner must not drop the pins of the others: the lock is
// rewritten whole, so everything it already held has to be carried over.
func TestApply_KeepsLockEntriesItDidNotTouch(t *testing.T) {
	artefact := tarGzWith(t, "trivy", []byte("trivy"))
	srv, _ := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": artefact})
	useCatalogue(t,
		mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz),
		mockTool("popeye", "0.9.0", srv.URL+"/popeye-{v}.tar.gz", ArchiveTarGz),
	)

	home := t.TempDir()
	popeye := LockEntry{Version: "0.9.0", SHA256: "cafe", Cosign: CosignUnverified}
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy":  {Version: "1.2.3", SHA256: sum(artefact), Cosign: CosignUnverified},
		"popeye": popeye,
	}}); err != nil {
		t.Fatal(err)
	}

	if _, err := Apply(context.Background(), opts(home, srv, "trivy")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	lock, err := LoadLock(LockPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if lock.Tools["popeye"] != popeye {
		t.Errorf("popeye entry = %+v, want %+v — an untouched pin was lost", lock.Tools["popeye"], popeye)
	}
}

// A scanner whose archive unpacks fine must not be left replaced when a LATER
// scanner's archive turns out to be unusable.
//
// The checksum tests above only prove the DOWNLOAD phase is all-or-nothing.
// Installing inside the same loop that unpacked meant an artefact that passed
// its checksum and then failed to unpack — a truncated or restructured release
// — left the earlier scanners already swapped in: a half-updated toolchain,
// reported to the operator as a plain error.
func TestApply_AnUnusableArchiveLeavesTheOthersUntouched(t *testing.T) {
	// trivy is already installed at 1.0.0 by a previous, successful run.
	old := tarGzWith(t, "trivy", []byte("trivy 1.0.0"))
	srvOld, _ := serveAssets(t, map[string][]byte{"/trivy-1.0.0.tar.gz": old})
	useCatalogue(t, mockTool("trivy", "1.0.0", srvOld.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))
	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.0.0", SHA256: sum(old)},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), opts(home, srvOld)); err != nil {
		t.Fatalf("seeding the first install: %v", err)
	}

	// Now update trivy to 2.0.0 and install popeye alongside it — but popeye's
	// artefact checksums correctly and does NOT contain a popeye binary.
	newTrivy := tarGzWith(t, "trivy", []byte("trivy 2.0.0"))
	noBinary := tarGzWith(t, "NOTICE", []byte("no popeye in here"))
	srv, _ := serveAssets(t, map[string][]byte{
		"/trivy-2.0.0.tar.gz":  newTrivy,
		"/popeye-2.0.0.tar.gz": noBinary,
	})
	useCatalogue(t,
		mockTool("trivy", "2.0.0", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz),
		mockTool("popeye", "2.0.0", srv.URL+"/popeye-{v}.tar.gz", ArchiveTarGz),
	)
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy":  {Version: "2.0.0", SHA256: sum(newTrivy), Installed: "1.0.0"},
		"popeye": {Version: "2.0.0", SHA256: sum(noBinary)},
	}}); err != nil {
		t.Fatal(err)
	}

	if _, err := Apply(context.Background(), opts(home, srv)); err == nil {
		t.Fatal("Apply succeeded although popeye's artefact has no binary in it")
	}

	// trivy must still be the 1.0.0 that was working before this run.
	bin := filepath.Join(ToolsDir(home), "trivy", "trivy")
	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("the already-installed trivy is gone: %v", err)
	}
	if string(got) != "trivy 1.0.0" {
		t.Errorf("installed trivy = %q, want the untouched %q", got, "trivy 1.0.0")
	}
	// ...and no staging directory is left lying about.
	if _, err := os.Stat(filepath.Join(ToolsDir(home), "trivy.new")); !os.IsNotExist(err) {
		t.Errorf("trivy.new survived the failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ToolsDir(home), "popeye.new")); !os.IsNotExist(err) {
		t.Errorf("popeye.new survived the failure: %v", err)
	}
}

// A version pinned in tools.lock.yaml is a REQUEST, not a record of an install.
// Reading Plan.Installed off the same `version:` field made `update --check`
// report a scanner as installed and up to date when nothing had ever been
// downloaded — the worst possible answer, because it is the one an operator
// acts on by doing nothing.
func TestResolve_APinIsNotAnInstall(t *testing.T) {
	useCatalogue(t, mockTool("trivy", "1.2.3", "https://example.invalid/trivy-{v}.tar.gz", ArchiveTarGz))
	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: sum([]byte("x"))}, // pinned, never installed
	}}); err != nil {
		t.Fatal(err)
	}
	plans, err := Resolve(Options{Home: home, Platform: plat})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans=%d", len(plans))
	}
	if plans[0].Version != "1.2.3" {
		t.Errorf("Version = %q, want the pin 1.2.3", plans[0].Version)
	}
	if plans[0].Installed != "" {
		t.Errorf("Installed = %q, want empty — nothing was ever installed, only pinned",
			plans[0].Installed)
	}
}

// After Apply, `installed` is written and --check can tell the two apart.
func TestApply_RecordsWhatItInstalledSeparatelyFromThePin(t *testing.T) {
	artefact := tarGzWith(t, "trivy", []byte("trivy"))
	srv, _ := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": artefact})
	useCatalogue(t, mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))
	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: sum(artefact)},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), opts(home, srv)); err != nil {
		t.Fatal(err)
	}
	lock, err := LoadLock(LockPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if lock.Tools["trivy"].Installed != "1.2.3" {
		t.Errorf("lock installed = %q, want 1.2.3", lock.Tools["trivy"].Installed)
	}
	plans, err := Resolve(Options{Home: home, Platform: plat})
	if err != nil {
		t.Fatal(err)
	}
	if plans[0].Installed != "1.2.3" {
		t.Errorf("Installed = %q after a real install, want 1.2.3", plans[0].Installed)
	}
}

// Hex case is not part of a checksum. Release pages publish both, and rejecting
// an upper-case pin as a MISMATCH reads as a supply-chain alarm rather than the
// formatting difference it is.
func TestApply_AnUpperCasePinIsNotAMismatch(t *testing.T) {
	artefact := tarGzWith(t, "trivy", []byte("trivy"))
	srv, _ := serveAssets(t, map[string][]byte{"/trivy-1.2.3.tar.gz": artefact})
	useCatalogue(t, mockTool("trivy", "1.2.3", srv.URL+"/trivy-{v}.tar.gz", ArchiveTarGz))
	home := t.TempDir()
	if err := SaveLock(LockPath(home), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: strings.ToUpper(sum(artefact))},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), opts(home, srv)); err != nil {
		t.Fatalf("Apply rejected a correct but upper-case checksum: %v", err)
	}
	// A genuinely wrong checksum is still a mismatch, whatever its case.
	home2 := t.TempDir()
	if err := SaveLock(LockPath(home2), Lock{Tools: map[string]LockEntry{
		"trivy": {Version: "1.2.3", SHA256: strings.ToUpper(sum([]byte("something else")))},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), opts(home2, srv)); err == nil {
		t.Fatal("a wrong upper-case checksum was accepted")
	}
}
