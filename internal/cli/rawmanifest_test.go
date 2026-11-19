package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

func rawSet(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "raw")
	err := saveRaw(dir, []scanner.RawResult{
		{Scanner: "trivy", Version: "0.76.1", Data: []byte(`{"Results":[]}`)},
		{Scanner: "popeye", Data: []byte(`{"popeye":{}}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRawManifest_WrittenAndAccepted(t *testing.T) {
	dir := rawSet(t)
	b, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil || !strings.Contains(string(b), "  trivy.json\n") || !strings.Contains(string(b), "  versions.json\n") {
		t.Fatalf("manifest missing entries: %q err=%v", b, err)
	}
	if _, _, err := loadRawDir(dir); err != nil {
		t.Fatalf("an untouched raw dir must load: %v", err)
	}
}

func TestRawManifest_RejectsEditedFile(t *testing.T) {
	dir := rawSet(t)
	_ = os.WriteFile(filepath.Join(dir, "trivy.json"), []byte(`{"Results":[{"edited":true}]}`), 0o600)
	if _, _, err := loadRawDir(dir); err == nil || !strings.Contains(err.Error(), "modified after the scan") {
		t.Fatalf("an edited raw file must be refused, got %v", err)
	}
}

func TestRawManifest_RejectsRemovedAndAddedFiles(t *testing.T) {
	dir := rawSet(t)
	_ = os.WriteFile(filepath.Join(dir, "checkov.json"), []byte(`{}`), 0o600)
	if _, _, err := loadRawDir(dir); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("a file added after the scan must be refused, got %v", err)
	}
	dir = rawSet(t)
	_ = os.Truncate(filepath.Join(dir, "popeye.json"), 0)
	if _, _, err := loadRawDir(dir); err == nil {
		t.Fatal("a truncated file must be refused")
	}
}

func TestRawManifest_RejectsPathInManifest(t *testing.T) {
	dir := rawSet(t)
	line := strings.Repeat("a", 64) + "  ../../etc/passwd\n"
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(line), 0o600)
	if err := verifyRawManifest(dir); err == nil || !strings.Contains(err.Error(), "plain file name") {
		t.Fatalf("a manifest naming a path must be refused, got %v", err)
	}
}

func TestRawManifest_HandCollectedDirWithoutManifestStillLoads(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "trivy.json"), []byte(`{"Results":[]}`), 0o600)
	if _, _, err := loadRawDir(dir); err != nil {
		t.Fatalf("no manifest = hand-collected, must load: %v", err)
	}
}

func TestChromiumSandboxOnlyWhereNeeded(t *testing.T) {
	old := needsNoSandbox
	defer func() { needsNoSandbox = old }()
	c := chromium("chromium", "/x")
	needsNoSandbox = func() bool { return false }
	for _, a := range c.Args("/h.html", "/o.pdf") {
		if a == "--no-sandbox" {
			t.Fatal("--no-sandbox must not be passed when the sandbox can run")
		}
	}
	needsNoSandbox = func() bool { return true }
	found := false
	for _, a := range c.Args("/h.html", "/o.pdf") {
		found = found || a == "--no-sandbox"
	}
	if !found {
		t.Fatal("--no-sandbox is required as root/in a container")
	}
}
