package policy

import (
	"testing"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func result(fs ...finding.Finding) finding.ScanResult {
	return finding.ScanResult{Summary: finding.Summary{RiskScore: 72, TotalFindings: len(fs)}, Findings: fs}
}

var now = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

func TestEvaluate_FailOnHigh(t *testing.T) {
	res := result(
		finding.Finding{CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Severity: finding.SeverityCritical},
		finding.Finding{CanonicalControl: "TATAR-NET-002", Resource: "svc/x", Severity: finding.SeverityMedium},
	)
	r := Default().Evaluate(res, now) // fail_on=high
	if r.Passed {
		t.Error("CRITICAL байхад pass болсон")
	}
	if len(r.Violations) != 1 || r.Violations[0].Severity != finding.SeverityCritical {
		t.Errorf("violations=%+v, want зөвхөн CRITICAL", r.Violations)
	}
}

func TestEvaluate_MediumBelowThresholdPasses(t *testing.T) {
	res := result(finding.Finding{CanonicalControl: "TATAR-NET-002", Resource: "svc/x", Severity: finding.SeverityMedium})
	r := Default().Evaluate(res, now)
	if !r.Passed {
		t.Errorf("зөвхөн MEDIUM байхад унасан: %+v", r.Reasons)
	}
}

func TestEvaluate_Suppression(t *testing.T) {
	res := result(finding.Finding{CanonicalControl: "TATAR-CON-001", Resource: "deployment/legacy", Namespace: "default", Severity: finding.SeverityCritical})
	pol := Policy{FailOn: "high", Suppress: []Suppression{
		{Control: "TATAR-CON-001", Resource: "deployment/legacy", Namespace: "default", Reason: "accepted, JIRA-1"},
	}}
	r := pol.Evaluate(res, now)
	if !r.Passed {
		t.Error("suppress хийсэн олдвор gate-ийг унагаасан")
	}
	if len(r.Suppressed) != 1 || len(r.Violations) != 0 {
		t.Errorf("suppressed=%d violations=%d, want 1/0", len(r.Suppressed), len(r.Violations))
	}
}

func TestEvaluate_ExpiredSuppressionReactivates(t *testing.T) {
	res := result(finding.Finding{CanonicalControl: "TATAR-CON-001", Resource: "deployment/legacy", Severity: finding.SeverityCritical})
	pol := Policy{FailOn: "high", Suppress: []Suppression{
		{Control: "TATAR-CON-001", Resource: "deployment/legacy", Reason: "temp", Expires: "2026-01-01"}, // өнгөрсөн
	}}
	r := pol.Evaluate(res, now)
	if r.Passed {
		t.Error("хугацаа дууссан suppress-ийг gate хүчинтэйд тооцсон")
	}
	if len(r.ExpiredRules) != 1 {
		t.Errorf("expired=%d, want 1", len(r.ExpiredRules))
	}
	if len(r.Violations) != 1 {
		t.Errorf("violations=%d, want 1 (дахин идэвхжсэн)", len(r.Violations))
	}
}

func TestEvaluate_MinScore(t *testing.T) {
	res := result() // score 72, олдворгүй
	pol := Policy{FailOn: "critical", MinScore: 80}
	r := pol.Evaluate(res, now)
	if r.Passed || !r.ScoreViolated {
		t.Errorf("score 72 < 80 байхад pass=%v scoreViolated=%v", r.Passed, r.ScoreViolated)
	}
}

func TestEvaluate_CleanPasses(t *testing.T) {
	res := result(finding.Finding{CanonicalControl: "TATAR-X", Resource: "r", Severity: finding.SeverityLow})
	r := Default().Evaluate(res, now)
	if !r.Passed {
		t.Errorf("цэвэр (зөвхөн LOW) unasan: %+v", r.Reasons)
	}
}

// Ямар ч finding-д тохироогүй suppression ил гарах ёстой: хуучирсан дүрэм нь
// "хүлээн зөвшөөрсөн эрсдэл"-ийн бүртгэлийг бодит бус болгож, дараа өөр
// finding-ийг санамсаргүй хааж мэднэ.
func TestEvaluate_ReportsUnusedSuppression(t *testing.T) {
	res := finding.ScanResult{Findings: []finding.Finding{
		{CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Severity: finding.SeverityHigh},
	}}
	p := Policy{FailOn: "high", Suppress: []Suppression{
		{Control: "TATAR-CON-001", Resource: "deployment/api", Reason: "accepted"}, // тохирно
		{Control: "TATAR-CON-001", Resource: "deployment/gone", Reason: "stale"},   // тохирохгүй
		{Control: "TATAR-NET-001", Reason: "stale too"},                            // тохирохгүй
	}}
	r := p.Evaluate(res, time.Now())
	if len(r.Suppressed) != 1 {
		t.Errorf("Suppressed=%d, want 1", len(r.Suppressed))
	}
	if len(r.UnusedRules) != 2 {
		t.Fatalf("UnusedRules=%d, want 2: %+v", len(r.UnusedRules), r.UnusedRules)
	}
	if !r.Passed {
		t.Errorf("suppress хийгдсэн тул gate давах ёстой: %v", r.Reasons)
	}
}
