package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── `update` дээрх CLI давхарга ──────────────────────────────────────────────
//
// internal/update-ийн тестүүд нь httptest server дээр татах/баталгаажуулах
// замыг бүрэн шалгадаг. ЭНД шалгах зүйл нь тэр биш: dispatcher-т холбогдсон
// эсэх, exit code-ийн гэрээ, мөн --dry-run/--check ҮНЭХЭЭР юу ч бичдэггүй
// эсэх. Нэг ч тест сүлжээнд хүрэхгүй — --dry-run ба --check нь request хийдэггүй.
//
// `--scanner trivy`: catalogue-д байгаа дөрвөн scanner бүгд ижил платформ
// дэмждэггүй (checkov нь darwin/arm64-д binary нийтэлдэггүй) тул тест
// ажиллуулагч машинаас хамаарахгүй байхын тулд дөрвөн платформ дэмждэг нэгийг
// сонгов.

// captureStdout — команд юу хэвлэснийг буцаана.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()

	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// --dry-run нь татах ЁСТОЙ зүйлээ хэвлээд зогсоно: файл үүсгэхгүй.
func TestCLI_UpdateDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	var code int
	out := captureStdout(t, func() {
		code = cmdUpdate([]string{"--scanner", "trivy", "--dry-run", "--home", home})
	})
	if code != 0 {
		t.Fatalf("update --dry-run exit=%d, want 0", code)
	}
	for _, want := range []string{"trivy", "https://", "NOT PINNED"} {
		if !strings.Contains(out, want) {
			t.Errorf("--dry-run гаралтад %q алга:\n%s", want, out)
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("--dry-run нь %d бичлэг үүсгэв, 0 байх ёстой", len(entries))
	}
}

// --check мөн адил: зөвхөн уншиж хэвлэнэ.
func TestCLI_UpdateCheckWritesNothing(t *testing.T) {
	home := t.TempDir()
	var code int
	out := captureStdout(t, func() {
		code = cmdUpdate([]string{"--scanner", "trivy", "--check", "--home", home})
	})
	if code != 0 {
		t.Fatalf("update --check exit=%d, want 0", code)
	}
	if !strings.Contains(out, "trivy") {
		t.Errorf("--check гаралтад trivy алга:\n%s", out)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("--check нь %d бичлэг үүсгэв, 0 байх ёстой", len(entries))
	}
}

// Танигдаагүй scanner нь ХЭРЭГЛЭЭНИЙ алдаа (3), ажиллагааны алдаа (2) биш —
// README-гийн exit code хүснэгтийн дагуу.
func TestCLI_UpdateUnknownScannerIsUsageError(t *testing.T) {
	if code := cmdUpdate([]string{"--scanner", "nmap", "--dry-run", "--home", t.TempDir()}); code != 3 {
		t.Errorf("update --scanner nmap exit=%d, want 3", code)
	}
}

// `tatar-kuber update` нь dispatcher-т холбогдсон байх ёстой: v1-д энэ нь
// "хэрэгжээгүй" гэж exit 2 буцаадаг байсан.
func TestCLI_UpdateIsWiredIntoTheDispatcher(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig; setLang(nil) }()

	home := t.TempDir()
	os.Args = []string{"tatar-kuber", "update", "--scanner", "trivy", "--dry-run", "--home", home}
	var code int
	captureStdout(t, func() { code = Execute() })
	if code != 0 {
		t.Errorf("Execute(update --dry-run) = %d, want 0 (v1-д 2 буцаадаг байв)", code)
	}
}

// Home-ийн дараалал нь resolveRegistry-тэй ижил: флаг > орчны хувьсагч > default.
func TestResolveHomePrecedence(t *testing.T) {
	t.Setenv("TATAR_HOME", "/from/env")

	if got, err := resolveHome("/from/flag"); err != nil || got != "/from/flag" {
		t.Errorf("resolveHome(флаг) = %q, %v", got, err)
	}
	if got, err := resolveHome(""); err != nil || got != "/from/env" {
		t.Errorf("resolveHome($TATAR_HOME) = %q, %v", got, err)
	}

	t.Setenv("TATAR_HOME", "")
	got, err := resolveHome("")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != ".tatar-kuber" {
		t.Errorf("resolveHome(default) = %q, want <home>/.tatar-kuber", got)
	}
}
