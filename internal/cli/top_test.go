package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// `top` нь шинэ оноо зохиодоггүй — файл дотор байгаа зүйлийг тоолно. Тиймээс
// энд шалгах зүйл нь тооллого ЗӨВ, эрэмбэ ДЕТЕРМИНИСТИК эсэх.

func writeScan(t *testing.T, fs []finding.Finding) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scan-result.json")
	b, err := json.Marshal(finding.ScanResult{Findings: fs})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func f(control, resource, ns string, sev finding.Severity) finding.Finding {
	return finding.Finding{CanonicalControl: control, Resource: resource, Namespace: ns, Severity: sev}
}

// Жин нь тооноос давамгайлна: нэг CRITICAL (5) бүхий ачаалал нь хоёр LOW (4)
// бүхийгээс дээш гарах ёстой — эс бөгөөс "хамгийн олон" нь "хамгийн муу"-г
// дарж, эрэмбэ төөрөлдөнө.
func TestTop_RanksResourcesBySeverityWeightNotCount(t *testing.T) {
	in := writeScan(t, []finding.Finding{
		f("TATAR-A", "deployment/noisy", "prod", finding.SeverityLow),
		f("TATAR-B", "deployment/noisy", "prod", finding.SeverityLow),
		f("TATAR-C", "deployment/grave", "prod", finding.SeverityCritical),
	})
	out := captureStdout(t, func() {
		if code := cmdTop([]string{"--input", in}); code != 0 {
			t.Fatalf("exit=%d, want 0", code)
		}
	})
	grave, noisy := strings.Index(out, "deployment/grave"), strings.Index(out, "deployment/noisy")
	if grave < 0 || noisy < 0 {
		t.Fatalf("хоёр resource хоёулаа гарах ёстой:\n%s", out)
	}
	if grave > noisy {
		t.Errorf("CRITICAL-тай ачаалал хоёр LOW-ийн доор гарч байна (жин 5 vs 4):\n%s", out)
	}
}

// Control-ийн хүснэгт нь ОЛДВОР биш, ялгаатай RESOURCE-ийг тоолно: нэг
// template-ийн алдаа хэдэн ачаалалд тархсаныг л энэ хүснэгт хариулдаг.
func TestTop_ControlsCountDistinctResources(t *testing.T) {
	in := writeScan(t, []finding.Finding{
		f("TATAR-SPREAD", "deployment/a", "prod", finding.SeverityMedium),
		f("TATAR-SPREAD", "deployment/b", "prod", finding.SeverityMedium),
		f("TATAR-SPREAD", "deployment/c", "prod", finding.SeverityMedium),
		f("TATAR-DEEP", "deployment/a", "prod", finding.SeverityCritical),
	})
	out := captureStdout(t, func() { cmdTop([]string{"--input", in}) })
	spread, deep := strings.Index(out, "TATAR-SPREAD"), strings.Index(out, "TATAR-DEEP")
	if spread < 0 || deep < 0 {
		t.Fatalf("хоёр control хоёулаа гарах ёстой:\n%s", out)
	}
	// SPREAD нь 3 resource, DEEP нь 1 — severity нь доогуур ч SPREAD түрүүлнэ.
	if spread > deep {
		t.Errorf("3 resource-д тархсан control нь 1 resource-тайгаас доош байна:\n%s", out)
	}
}

// Олдворгүй scan бол алдаа биш.
func TestTop_EmptyScanIsNotAnError(t *testing.T) {
	in := writeScan(t, nil)
	out := captureStdout(t, func() {
		if code := cmdTop([]string{"--input", in}); code != 0 {
			t.Fatalf("exit=%d, want 0", code)
		}
	})
	if strings.TrimSpace(out) == "" {
		t.Error("хоосон scan дээр юу ч хэвлээгүй — хэрэглэгч команд ажилласан эсэхийг мэдэхгүй")
	}
}

func TestTop_MissingInputIsExit2(t *testing.T) {
	if code := cmdTop([]string{"--input", filepath.Join(t.TempDir(), "nope.json")}); code != 2 {
		t.Errorf("байхгүй файл дээр exit=%d, want 2", code)
	}
}

// --limit нь хэвлэх мөрийг хязгаарлаж, хэдэн мөр үлдснийг ХЭЛНЭ. Чимээгүй
// таслах нь жагсаалт дууссан мэт уншигдана.
func TestTop_LimitSaysHowManyWereHidden(t *testing.T) {
	var fs []finding.Finding
	for _, n := range []string{"a", "b", "c", "d"} {
		fs = append(fs, f("TATAR-X", "deployment/"+n, "prod", finding.SeverityHigh))
	}
	in := writeScan(t, fs)
	out := captureStdout(t, func() { cmdTop([]string{"--input", in, "--limit", "2"}) })
	if !strings.Contains(out, "2") || !strings.Contains(strings.ToLower(out), "more") {
		t.Errorf("нуусан мөрийн тоог хэлээгүй:\n%s", out)
	}
}
