package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// FuzzLoadAndEvaluate — a policy file is user-supplied YAML. Loading it and
// evaluating a scan against it must never panic, whatever it contains.
func FuzzLoadAndEvaluate(f *testing.F) {
	f.Add([]byte("fail_on: high\n"))
	f.Add([]byte("fail_on: LoW\nsuppress:\n  - control: TATAR-CON-001\n    expires: 2099-01-01\n"))
	f.Add([]byte("suppress: [{expires: \"not a date\"}]\n"))
	f.Add([]byte("{{{{"))
	f.Add([]byte("a: &a [*a]\n"))
	dir := f.TempDir()
	res := finding.ScanResult{Findings: []finding.Finding{{CanonicalControl: "TATAR-CON-001", Resource: "deployment/a", Severity: finding.SeverityHigh}}}
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(dir, "p.yaml")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		pol, err := Load(p)
		if err != nil {
			return
		}
		_ = pol.ValidFailOn()
		_ = pol.Evaluate(res, time.Unix(0, 0))
	})
}
