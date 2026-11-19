package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/scanner"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/toolexec"
)

// A scanner run must say which executable it was. A stand-in file named after
// the adapter is put on PATH, so Describe resolves it for real on every OS and
// the test does not depend on any tool being installed.
func TestCollect_RecordsWhichBinaryRan(t *testing.T) {
	const tool = "tatar-fake-scanner"
	dir := t.TempDir()
	file := tool
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte("stand-in"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	reg := testRegistry(t)
	p := New(reg, &fakeAdapter{name: tool, ctrl: "TATAR-TEST-001", res: "deployment/a"})
	_, runs := p.Collect(context.Background(), scanner.Target{Mode: scanner.ModeRemote})
	if len(runs) != 1 {
		t.Fatalf("runs=%d", len(runs))
	}
	r := runs[0]
	if r.BinaryPath == "" || len(r.BinarySHA256) != 64 || (r.BinarySource != "path" && r.BinarySource != "tools") {
		t.Fatalf("the run must record path, origin and SHA-256 of the binary: %+v", r)
	}
}

// An adapter whose tool is not a resolvable binary (the fakes in this package)
// simply has nothing to record -- no empty fields invented.
func TestCollect_NoBinaryNoRecord(t *testing.T) {
	reg := testRegistry(t)
	p := New(reg, &fakeAdapter{name: "no-such-tool-xyz", ctrl: "TATAR-TEST-001", res: "deployment/a"})
	_, runs := p.Collect(context.Background(), scanner.Target{Mode: scanner.ModeRemote})
	r := runs[0]
	if r.BinaryPath != "" || r.BinarySHA256 != "" || r.BinarySource != "" || r.Warning != "" {
		t.Fatalf("nothing resolved, nothing recorded: %+v", r)
	}
}

// A scanner in the tools directory whose binary no longer matches the digest
// `update` recorded must not be executed: the run is reported unavailable.
func TestCollect_RefusesToolsBinaryThatChangedAfterInstall(t *testing.T) {
	const tool = "tatar-fake-scanner2"
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	dir := filepath.Join(toolexec.ToolsDir(), tool)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := tool
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(filepath.Dir(toolexec.ToolsDir()), "tools.lock.yaml")
	body := "tools:\n  " + tool + ":\n    installed_sha256: \"" + strings.Repeat("0", 64) + "\"\n"
	if err := os.WriteFile(lock, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	fa := &fakeAdapter{name: tool, ctrl: "TATAR-TEST-001", res: "deployment/a"}
	p := New(testRegistry(t), fa)
	_, runs := p.Collect(context.Background(), scanner.Target{Mode: scanner.ModeRemote})
	r := runs[0]
	if r.Status != "unavailable" || !strings.Contains(r.Error, "does not match") {
		t.Fatalf("a changed binary must be refused: %+v", r)
	}
	if r.BinarySHA256 == "" || r.Warning == "" {
		t.Fatalf("the refusal must still say which binary it was: %+v", r)
	}
}
