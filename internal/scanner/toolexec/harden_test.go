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
	environ := []string{"GITHUB_TOKEN=ghp_x", "GH_TOKEN=y", PassEnvVar + "=GITHUB_TOKEN"}
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
