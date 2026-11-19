package toolexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ── environment handed to a scanner ──────────────────────────────────────────

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func TestChildEnv_DropsForgeCredentialsKeepsTheRest(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin", "HOME=/h", "KUBECONFIG=/k",
		"GITHUB_TOKEN=ghp_x", "gh_token=lower", "ACTIONS_RUNTIME_TOKEN=r",
		"AWS_ACCESS_KEY_ID=keep-for-eks", "GOOGLE_APPLICATION_CREDENTIALS=/g.json",
	}
	got := envMap(childEnv(environ, []string{"BC_SKIP_MAPPING=TRUE"}))
	for _, gone := range []string{"GITHUB_TOKEN", "gh_token", "ACTIONS_RUNTIME_TOKEN"} {
		if _, ok := got[gone]; ok {
			t.Errorf("%s must not reach the scanner", gone)
		}
	}
	for _, kept := range []string{"PATH", "HOME", "KUBECONFIG", "AWS_ACCESS_KEY_ID", "GOOGLE_APPLICATION_CREDENTIALS", "BC_SKIP_MAPPING"} {
		if _, ok := got[kept]; !ok {
			t.Errorf("%s must still reach the scanner", kept)
		}
	}
}

func TestChildEnv_PassEnvEscapeHatch(t *testing.T) {
	environ := []string{"GITHUB_TOKEN=ghp_x", "GH_TOKEN=y", ForwardEnvVar + "=GITHUB_TOKEN"}
	got := envMap(childEnv(environ, nil))
	if got["GITHUB_TOKEN"] != "ghp_x" {
		t.Error("a variable named in TATAR_PASS_ENV must be passed")
	}
	if _, ok := got["GH_TOKEN"]; ok {
		t.Error("only the named variable is released")
	}
}

func TestChildEnv_ExtraWinsOverInherited(t *testing.T) {
	got := envMap(childEnv([]string{"KUBECONFIG=/old"}, []string{"KUBECONFIG=/new"}))
	if got["KUBECONFIG"] != "/new" {
		t.Errorf("extra must override, got %q", got["KUBECONFIG"])
	}
}

// ── bounded output ───────────────────────────────────────────────────────────

func TestRun_RefusesOutputOverTheCap(t *testing.T) {
	if _, ok := Resolve("go"); !ok {
		t.Skip("go binary not available")
	}
	old := maxStdout
	maxStdout = 5
	defer func() { maxStdout = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := Run(ctx, "go", []string{"version"})
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("want ErrOutputTooLarge, got %v", err)
	}
}

func TestCapBuffer_StderrTruncatesInsteadOfFailing(t *testing.T) {
	c := &capBuffer{max: 4, drop: true}
	if n, err := c.Write([]byte("abcdefgh")); err != nil || n != 8 {
		t.Fatalf("a dropping buffer must report success, got %d %v", n, err)
	}
	if c.buf.Len() != 0 {
		t.Fatalf("excess must be discarded, kept %d", c.buf.Len())
	}
	h := &capBuffer{max: 4}
	if _, err := h.Write([]byte("abcdefgh")); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("a strict buffer must fail, got %v", err)
	}
}

// ── user-supplied arguments ──────────────────────────────────────────────────

func TestValidateValue(t *testing.T) {
	for _, ok := range []string{"", "prod", "arn:aws:eks:eu-west-1:1:cluster/x", "gke_proj_zone_name", "kube-system"} {
		if err := ValidateValue("v", ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"--insecure-skip-tls-verify", "-n", "a\nb", "a\x00b", "a\x7fb"} {
		if err := ValidateValue("v", bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// ── a version line is not free text ──────────────────────────────────────────

func TestPlainVersionLine(t *testing.T) {
	if got := plainVersionLine("Version: 0.76.1"); got != "Version: 0.76.1" {
		t.Errorf("plain line altered: %q", got)
	}
	for _, bad := range []string{`{"results":{"failed_checks":[]}}`, "<script>alert(1)</script>", strings.Repeat("a", 200)} {
		if got := plainVersionLine(bad); got != "unparsed" {
			t.Errorf("%q must not be copied into the report, got %q", bad, got)
		}
	}
}

// ── which binary ran ─────────────────────────────────────────────────────────

func writeTool(t *testing.T, dir, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("not really a program"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDescribe_PathCopyShadowingThePinnedOneIsReported(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pinned := writeTool(t, filepath.Join(ToolsDir(), "faketool"), "faketool")
	pathDir := t.TempDir()
	onPath := writeTool(t, pathDir, "faketool")
	t.Setenv("PATH", pathDir)

	b, ok := Describe("faketool")
	if !ok {
		t.Fatal("faketool not resolved")
	}
	if b.Source != SourcePath || b.Path != onPath {
		t.Fatalf("PATH copy expected first, got %+v", b)
	}
	if !b.Shadowed || !strings.Contains(b.Warning, "pinned copy") {
		t.Fatalf("shadowing the pinned copy must be reported: %+v", b)
	}
	if len(b.SHA256) != 64 {
		t.Fatalf("binary hash missing: %q", b.SHA256)
	}
	_ = pinned
}

func TestDescribe_ToolsDirCopyIsNotShadowed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	writeTool(t, filepath.Join(ToolsDir(), "faketool"), "faketool")
	t.Setenv("PATH", t.TempDir()) // nothing on PATH

	b, ok := Describe("faketool")
	if !ok || b.Source != SourceTools || b.Shadowed || b.Warning != "" {
		t.Fatalf("a tools-dir binary is the pinned one: %+v ok=%v", b, ok)
	}
}

func TestDescribe_OnlyOnPathIsNotAWarning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	pathDir := t.TempDir()
	writeTool(t, pathDir, "faketool")
	t.Setenv("PATH", pathDir)

	b, ok := Describe("faketool")
	if !ok || b.Source != SourcePath || b.Shadowed || b.Warning != "" {
		t.Fatalf("a PATH-only binary shadows nothing: %+v ok=%v", b, ok)
	}
}

// ── F2: the binary in the tools directory must still be the one `update` installed

func writeLock(t *testing.T, name, sha string) {
	t.Helper()
	lock := filepath.Join(filepath.Dir(ToolsDir()), "tools.lock.yaml")
	body := "tools:\n  " + name + ":\n    version: \"1.0.0\"\n    installed_sha256: \"" + sha + "\"\n"
	if err := os.MkdirAll(filepath.Dir(lock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDescribe_ToolsBinaryMatchingTheLockIsFine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	p := writeTool(t, filepath.Join(ToolsDir(), "faketool"), "faketool")
	writeLock(t, "faketool", fileSHA256(p))

	b, ok := Describe("faketool")
	if !ok || b.Mismatch || b.Warning != "" || b.PinnedSHA256 != b.SHA256 {
		t.Fatalf("a binary that still matches the lock must pass: %+v", b)
	}
}

func TestDescribe_ToolsBinaryChangedAfterInstallIsFlagged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	p := writeTool(t, filepath.Join(ToolsDir(), "faketool"), "faketool")
	writeLock(t, "faketool", fileSHA256(p))
	if err := os.WriteFile(p, []byte("swapped after update verified it"), 0o755); err != nil {
		t.Fatal(err)
	}

	b, ok := Describe("faketool")
	if !ok || !b.Mismatch || !strings.Contains(b.Warning, "tatar-kuber update") {
		t.Fatalf("a modified tools binary must be flagged: %+v", b)
	}
}

func TestDescribe_NoPinInLockMeansNoMismatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	writeTool(t, filepath.Join(ToolsDir(), "faketool"), "faketool")
	// no lock at all (hand-placed binary, older install): behaviour unchanged
	if b, ok := Describe("faketool"); !ok || b.Mismatch || b.PinnedSHA256 != "" {
		t.Fatalf("no recorded digest -> nothing to compare: %+v", b)
	}
	// a lock that does not mention this tool
	writeLock(t, "othertool", strings.Repeat("a", 64))
	if b, _ := Describe("faketool"); b.Mismatch {
		t.Fatalf("another tool's pin must not apply: %+v", b)
	}
}

func TestChildEnv_StrictModeIsAnAllowList(t *testing.T) {
	environ := []string{
		StrictEnvVar + "=1", "PATH=/usr/bin", "HOME=/h", "KUBECONFIG=/k", "HTTPS_PROXY=http://p", "TRIVY_CACHE_DIR=/c",
		"AWS_SECRET_ACCESS_KEY=s", "GITHUB_TOKEN=t", "DATABASE_URL=postgres://x", "MY_API_KEY=k",
	}
	got := envMap(childEnv(environ, []string{"EXTRA=1"}))
	for _, want := range []string{"PATH", "HOME", "KUBECONFIG", "HTTPS_PROXY", "TRIVY_CACHE_DIR", "EXTRA"} {
		if _, ok := got[want]; !ok {
			t.Errorf("strict mode must keep %s", want)
		}
	}
	for _, gone := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "DATABASE_URL", "MY_API_KEY"} {
		if _, ok := got[gone]; ok {
			t.Errorf("strict mode must drop %s", gone)
		}
	}
}

func TestChildEnv_StrictModeStillHonoursPassEnv(t *testing.T) {
	environ := []string{StrictEnvVar + "=1", "PATH=/p", ForwardEnvVar + "=AWS_PROFILE", "AWS_PROFILE=dev", "AWS_SECRET_ACCESS_KEY=s"}
	got := envMap(childEnv(environ, nil))
	if got["AWS_PROFILE"] != "dev" {
		t.Error("TATAR_PASS_ENV must release a named variable in strict mode")
	}
	if _, ok := got["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Error("unnamed cloud credential must stay out in strict mode")
	}
}
