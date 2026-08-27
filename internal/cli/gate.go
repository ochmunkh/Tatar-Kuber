package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/policy"
)

// cmdGate — CI/CD gatekeeper: scan-result.json-ыг .tatar-kuber.yaml бодлоготой
// тулгаж, severity босго / cluster score-оор pass/fail шийдэж exit code буцаана.
//
//	exit 0 — PASSED, exit 1 — FAILED, exit 2/3 — алдаа.
func cmdGate(args []string) int {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	input := fs.String("input", "scan-result.json", "scan-result.json зам")
	policyPath := fs.String("policy", ".tatar-kuber.yaml", "бодлогын файл")
	failOn := fs.String("fail-on", "", "severity босго (файлыг дарна): critical|high|medium|low")
	minScore := fs.Int("min-score", -1, "cluster score доод хязгаар (файлыг дарна)")
	_ = fs.Parse(args)

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	var res finding.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		fmt.Fprintln(os.Stderr, "алдаа: scan-result.json parse:", err)
		return 2
	}

	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	if *failOn != "" {
		pol.FailOn = *failOn
	}
	if *minScore >= 0 {
		pol.MinScore = *minScore
	}

	r := pol.Evaluate(res, time.Now())

	fmt.Printf("TATAR-Kuber gate — fail_on=%s  score=%d", r.FailOn, r.Score)
	if r.MinScore > 0 {
		fmt.Printf("  min_score=%d", r.MinScore)
	}
	fmt.Printf("  (suppressed=%d)\n\n", len(r.Suppressed))

	for _, s := range r.InvalidRules {
		fmt.Fprintf(os.Stderr, "анхаар: suppression '%s' expires формат буруу (%s) — YYYY-MM-DD байх ёстой\n", s.Control, s.Expires)
	}
	for _, s := range r.ExpiredRules {
		fmt.Fprintf(os.Stderr, "анхаар: suppression '%s' хугацаа дууссан (%s) — дахин идэвхжсэнгүй\n", s.Control, s.Expires)
	}

	if len(r.Violations) > 0 {
		fmt.Printf("Босго давсан %d олдвор:\n", len(r.Violations))
		for _, f := range r.Violations {
			ns := ""
			if f.Namespace != "" {
				ns = f.Namespace + "/"
			}
			fmt.Printf("  [%s] %s  %s%s  (%s)\n", f.Severity, f.CanonicalControl, ns, f.Resource, f.Title)
		}
		fmt.Println()
	}

	if r.Passed {
		fmt.Println("✓ GATE PASSED")
		return 0
	}
	fmt.Println("✗ GATE FAILED —", joinReasons(r.Reasons))
	return 1
}

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}
