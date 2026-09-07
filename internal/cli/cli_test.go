package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// E2E: examples/demo raw -> scan -> report(sarif/html) -> gate. CLI давхарга
// өмнө нь огт тестгүй байсан (flag семантик, exit code, файл бичилт).
func TestCLI_ScanReportGate_E2E(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "e2e", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	resPath := filepath.Join(out, "scan-result.json")
	data, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	var res finding.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if res.Summary.TotalFindings == 0 || len(res.Metadata.ScannerRuns) != 4 {
		t.Fatalf("findings=%d runs=%d", res.Summary.TotalFindings, len(res.Metadata.ScannerRuns))
	}
	for _, r := range res.Metadata.ScannerRuns {
		if r.Status != "ingested" || r.Findings == 0 {
			t.Errorf("scanner_run %+v: ingested + findings>0 байх ёстой", r)
		}
	}

	for _, f := range []string{"sarif", "html", "json"} {
		p := filepath.Join(out, "r."+f)
		if code := cmdReport([]string{"--input", resPath, "-o", f, "--out", p}); code != 0 {
			t.Errorf("report %s exit=%d", f, code)
		}
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("report %s хоосон/алга", f)
		}
	}

	// Demo-д HIGH finding бий → default gate унана (exit 1); fail-on critical бол
	// CRITICAL байгаа эсэхээс хамаарна; policy файлгүй бол default high.
	if code := cmdGate([]string{"--input", resPath, "--policy", filepath.Join(out, "none.yaml")}); code != 1 {
		t.Errorf("gate default(high) exit=%d, want 1 (demo-д HIGH бий)", code)
	}
}

// Флаг ЗӨВХӨН өгсөн үед policy файлыг дарна: --min-score default (0) нь файлын
// min_score-ыг устгаж болохгүй (v1.0.0 regression).
func TestCLI_GateFlagsDoNotClobberPolicyFile(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "-o", out}); code != 0 {
		t.Fatal("scan")
	}
	resPath := filepath.Join(out, "scan-result.json")
	pol := filepath.Join(out, ".tatar-kuber.yaml")
	// fail_on critical-аас дээш л унана; min_score 100 → score хэзээ ч 100 биш тул унах ЁСТОЙ.
	if err := os.WriteFile(pol, []byte("fail_on: critical\nmin_score: 100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdGate([]string{"--input", resPath, "--policy", pol}); code != 1 {
		t.Errorf("min_score=100 файлаас уншигдаж gate унах ёстой, exit=%d", code)
	}
	// Тодорхой --min-score 0 өгвөл файлыг дарна → зөвхөн fail_on critical үлдэнэ.
	code := cmdGate([]string{"--input", resPath, "--policy", pol, "--min-score", "0"})
	var res finding.ScanResult
	b, _ := os.ReadFile(resPath)
	_ = json.Unmarshal(b, &res)
	want := 0
	if res.Summary.Counts[finding.SeverityCritical] > 0 {
		want = 1
	}
	if code != want {
		t.Errorf("--min-score 0 explicit: exit=%d want %d", code, want)
	}
}

func TestCLI_ScanRequiresInput(t *testing.T) {
	if code := cmdScan([]string{"-o", t.TempDir()}); code != 3 {
		t.Errorf("оролтгүй scan exit=%d, want 3", code)
	}
}
