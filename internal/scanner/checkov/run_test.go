package checkov

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// The test binary doubles as a fake "checkov": when it is started under that
// name it records the environment and arguments it was given, prints an empty
// report and exits. No Python, no network, same on every OS.
func TestMain(m *testing.M) {
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "checkov" {
		if dump := os.Getenv("FAKE_CHECKOV_DUMP"); dump != "" {
			_ = os.WriteFile(dump, []byte(strings.Join(append(os.Environ(), "ARGS="+strings.Join(os.Args[1:], " ")), "\n")), 0o600)
		}
		fmt.Println(`{"results":{"failed_checks":[]}}`)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func installFake(t *testing.T) (dump string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir()) // nothing real can be found
	name := "checkov"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := filepath.Join(home, ".tatar-kuber", "tools", "checkov")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = self.Close() }()
	dst, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, self); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	dump = filepath.Join(t.TempDir(), "dump.txt")
	t.Setenv("FAKE_CHECKOV_DUMP", dump)
	return dump
}

func scanFake(t *testing.T, target scanner.Target) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := New(nil).Scan(ctx, target); err != nil {
		t.Fatal(err)
	}
}

// Checkov calls api0.prismacloud.io on every run unless told not to, which
// breaks the offline promise. The adapter must always tell it not to.
func TestScan_StartsCheckovWithoutThePrismaCall(t *testing.T) {
	dump := installFake(t)
	scanFake(t, scanner.Target{Mode: scanner.ModeLocal, Path: t.TempDir()})
	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("the fake checkov never ran: %v", err)
	}
	if !strings.Contains(string(b), "BC_SKIP_MAPPING=TRUE") {
		t.Fatalf("checkov must be started with BC_SKIP_MAPPING=TRUE, environment was:\n%s", b)
	}
}

// Forge credentials in the caller's environment stay with the caller.
func TestScan_DoesNotHandForgeTokensToCheckov(t *testing.T) {
	dump := installFake(t)
	t.Setenv("GITHUB_TOKEN", "ghp_must_not_be_seen")
	t.Setenv("KEEP_ME", "visible")
	scanFake(t, scanner.Target{Mode: scanner.ModeLocal, Path: t.TempDir()})
	b, _ := os.ReadFile(dump)
	if strings.Contains(string(b), "ghp_must_not_be_seen") {
		t.Fatal("GITHUB_TOKEN reached the scanner")
	}
	if !strings.Contains(string(b), "KEEP_ME=visible") {
		t.Fatal("ordinary variables must still be inherited")
	}
}

func TestScan_RefusesAPathThatLooksLikeAFlag(t *testing.T) {
	dump := installFake(t)
	_, err := New(nil).Scan(context.Background(), scanner.Target{Mode: scanner.ModeLocal, Path: "--config-file=/tmp/x"})
	if err == nil {
		t.Fatal("a path starting with '-' must be refused")
	}
	if _, statErr := os.Stat(dump); statErr == nil {
		t.Fatal("the scanner must not even have been started")
	}
}
