package toolexec

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// `tatar-kuber update` нь архивыг <tools>/<name>/ ДОТОР задалдаг бөгөөд
// binary нь тэндээ сууна. Resolve нь <tools>/<name>-ийг ФАЙЛ гэж хайдаг
// байсан тул суусан scanner-ийг олдоггүй байв: `update` "суулгалаа" гэж
// хэлээд `doctor` "суугаагүй" гэж хэлнэ, хоёулаа ногоон.
//
// CI нь scanner-уудаа install.sh-ээр PATH руу суулгадаг байсан тул энэ зам
// огт шалгагддаггүй байв. Энэ тест яг тэр байрлалыг гараар босгож шалгана.
func TestResolve_FindsWhatUpdateInstalled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows

	layout := filepath.Join(home, ".tatar-kuber", "tools", "trivy")
	if err := os.MkdirAll(layout, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(layout, binName("trivy"))
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, ok := Resolve("trivy")
	if !ok {
		t.Fatalf("update-ийн суулгасан байрлалыг Resolve олсонгүй: %s", bin)
	}
	if got != bin {
		t.Errorf("Resolve = %q, want %q", got, bin)
	}
}

// Архив нь binary-г гүнд савласан байж болно (kubescape-ийн v3 багцууд).
func TestResolve_FindsANestedBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	deep := filepath.Join(home, ".tatar-kuber", "tools", "popeye", "dist", "linux")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(deep, binName("popeye"))
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, ok := Resolve("popeye"); !ok || got != bin {
		t.Fatalf("Resolve = (%q, %v), want (%q, true)", got, ok, bin)
	}
}

// Суугаагүй scanner нь алдаа биш — зүгээр л олдохгүй.
func TestResolve_MissingIsNotFound(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if _, ok := Resolve("tatar-no-such-scanner"); ok {
		t.Fatal("байхгүй хэрэгсэл олдлоо гэв")
	}
}

// binName — Windows дээр .exe дагавар.
func binName(n string) string {
	if runtime.GOOS == "windows" {
		return n + ".exe"
	}
	return n
}
