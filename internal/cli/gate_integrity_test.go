package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// The gate must refuse a scan-result.json that disagrees with itself. Each case
// edits a real result the way someone trying to get a build through would, and
// a green (exit 0) answer to any of them is the failure being guarded.

func freshResult(t *testing.T) (dir, path string, res finding.ScanResult) {
	t.Helper()
	dir = t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "ig", "-o", dir}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	path = filepath.Join(dir, "scan-result.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	return dir, path, res
}

func writeJSON(t *testing.T, dir, name string, r finding.ScanResult) string {
	t.Helper()
	d, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, d, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGate_UntouchedResultPassesTheIntegrityCheck(t *testing.T) {
	dir, path, _ := freshResult(t)
	// demo has HIGH findings, so the verdict is "failed" (1) -- the point is that
	// it is a verdict at all, not the refusal (2).
	if code := cmdGate([]string{"--input", path, "--policy", filepath.Join(dir, "none.yaml")}); code != 1 {
		t.Fatalf("exit=%d, want 1 (a normal failing verdict, not an integrity refusal)", code)
	}
}

func TestGate_RefusesAnEditedResult(t *testing.T) {
	dir, _, res := freshResult(t)
	none := filepath.Join(dir, "none.yaml")

	cases := map[string]func(r *finding.ScanResult){
		"score lowered": func(r *finding.ScanResult) { r.Summary.RiskScore = 100 },
		"findings emptied, summary left": func(r *finding.ScanResult) {
			r.Findings = nil
		},
		"one finding dropped": func(r *finding.ScanResult) { r.Findings = r.Findings[1:] },
		"severity downgraded": func(r *finding.ScanResult) {
			r.Findings = append([]finding.Finding(nil), r.Findings...)
			for i := range r.Findings {
				if r.Findings[i].Severity == finding.SeverityHigh || r.Findings[i].Severity == finding.SeverityCritical {
					r.Findings[i].Severity = finding.SeverityInfo
				}
			}
		},
		"hash replaced": func(r *finding.ScanResult) { r.Metadata.ResultHash = "sha256:0000" },
	}
	for name, edit := range cases {
		r := res
		r.Findings = append([]finding.Finding(nil), res.Findings...)
		edit(&r)
		p := writeJSON(t, dir, "edited.json", r)
		if code := cmdGate([]string{"--input", p, "--policy", none, "--fail-on", "critical", "--min-score", "1"}); code != 2 {
			t.Errorf("%s: exit=%d, want 2 (refused)", name, code)
		}
	}
}

func TestGate_SkipIntegrityCheckIsExplicit(t *testing.T) {
	dir, _, res := freshResult(t)
	none := filepath.Join(dir, "none.yaml")
	r := res
	r.Findings = nil // an edited file: only passes if the check is skipped on purpose
	p := writeJSON(t, dir, "edited.json", r)
	if code := cmdGate([]string{"--input", p, "--policy", none}); code != 2 {
		t.Fatalf("without the flag: exit=%d, want 2", code)
	}
	if code := cmdGate([]string{"--input", p, "--policy", none, "--skip-integrity-check"}); code == 2 {
		t.Fatalf("with --skip-integrity-check the file must be judged, not refused (exit=%d)", code)
	}
}
