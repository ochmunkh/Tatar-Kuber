package policy

import (
	"testing"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// A suppression is a promise to look again by a date. The gate must never turn a
// date it cannot read into "never".

func scanWith(controls ...string) finding.ScanResult {
	var fs []finding.Finding
	for _, c := range controls {
		fs = append(fs, finding.Finding{ID: c, CanonicalControl: c, Severity: finding.SeverityHigh, Resource: "deployment/api"})
	}
	return finding.ScanResult{Findings: fs}
}

func TestEvaluate_MalformedExpiresDoesNotSuppress(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	for _, bad := range []string{"2026-13-45", "tomorrow", "19/11/2026", "2026-1-1x", "2099"} {
		p := Policy{FailOn: "high", Suppress: []Suppression{{Control: "TATAR-A", Reason: "r", Expires: bad}}}
		r := p.Evaluate(scanWith("TATAR-A"), now)
		if r.Passed {
			t.Errorf("expires=%q: an unreadable expiry must not suppress, but the gate passed", bad)
		}
		if len(r.Violations) != 1 {
			t.Errorf("expires=%q: the finding must stay a violation, got %d", bad, len(r.Violations))
		}
		if len(r.InvalidRules) != 1 {
			t.Errorf("expires=%q: the bad rule must be listed, got %d", bad, len(r.InvalidRules))
		}
		if len(r.Suppressed) != 0 {
			t.Errorf("expires=%q: nothing may be suppressed", bad)
		}
	}
}

func TestEvaluate_ValidFutureExpiresStillSuppresses(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	p := Policy{FailOn: "high", Suppress: []Suppression{{Control: "TATAR-A", Reason: "r", Expires: "2026-12-31"}}}
	r := p.Evaluate(scanWith("TATAR-A"), now)
	if !r.Passed || len(r.Suppressed) != 1 || len(r.InvalidRules) != 0 {
		t.Fatalf("a valid unexpired suppression must still apply: %+v", r)
	}
}

func TestEvaluate_ExpiredStillDoesNotSuppress(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	p := Policy{FailOn: "high", Suppress: []Suppression{{Control: "TATAR-A", Reason: "r", Expires: "2026-11-01"}}}
	r := p.Evaluate(scanWith("TATAR-A"), now)
	if r.Passed || len(r.ExpiredRules) != 1 {
		t.Fatalf("an expired suppression must not apply: %+v", r)
	}
}

func TestEvaluate_NoExpiresIsStillAllowed(t *testing.T) {
	// Documented behaviour, unchanged: expires is optional. (A suppression that
	// never expires is a policy choice, and the gate says so in `unused`/audit.)
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	p := Policy{FailOn: "high", Suppress: []Suppression{{Control: "TATAR-A", Reason: "r"}}}
	r := p.Evaluate(scanWith("TATAR-A"), now)
	if !r.Passed || len(r.Suppressed) != 1 {
		t.Fatalf("an expiry-less suppression keeps working: %+v", r)
	}
}
