package toolexec

import (
	"context"
	"regexp"
	"testing"
	"time"
)

// `go` binary тест орчинд заавал байдаг тул түүгээр Resolve/Run/Version-ыг шалгана.
func TestResolveAndRun_Go(t *testing.T) {
	if _, ok := Resolve("go"); !ok {
		t.Skip("go binary олдсонгүй — тестийн орчин ер бусын")
	}
	ok, err := Available("go")
	if err != nil || !ok {
		t.Fatalf("Available(go)=%v,%v want true,nil", ok, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Run(ctx, "go", []string{"version"})
	if err != nil {
		t.Fatalf("Run(go version): %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit=%d, want 0", res.ExitCode)
	}
	if len(res.Stdout) == 0 {
		t.Error("stdout хоосон")
	}
}

func TestVersion_ParsesSemver(t *testing.T) {
	if _, ok := Resolve("go"); !ok {
		t.Skip("go binary алга")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	v, err := Version(ctx, "go", "version")
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+`).MatchString(v) {
		t.Errorf("version=%q, semver хэлбэр биш", v)
	}
}

func TestAvailable_Missing(t *testing.T) {
	ok, err := Available("tatar-kuber-definitely-not-a-real-binary-xyz")
	if err != nil {
		t.Fatalf("алдаа гарах ёсгүй: %v", err)
	}
	if ok {
		t.Error("байхгүй binary-г байгаа гэж заасан")
	}
}
