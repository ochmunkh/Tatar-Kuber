package policy

import (
	"os"
	"path/filepath"
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

// fail_on нь ҮСГИЙН ТОМ/ЖИЖИГТ ҮЛ ХАМААРНА — README болон action.yml-д
// баримтжуулсан зан. Бодлогын ФАЙЛААР дамжуулан шалгана (зөвхөн Policy{}
// литерал биш): `fail_on: Low` танигдахгүй байсан тул чимээгүйгээр `high`
// болж, LOW ба MEDIUM олдвор gate-ийг унагахаа больдог байв — босгыг
// СУЛРУУЛАХ тал руух чимээгүй хувирал. Энэ тест яг тэр регрессийг бариулна.
func TestLoad_FailOnIsCaseInsensitiveAndGates(t *testing.T) {
	// Босго давуулах ёстой олдворууд: хамгийн өндөр нь MEDIUM.
	res := result(
		finding.Finding{CanonicalControl: "TATAR-NET-002", Resource: "svc/x", Severity: finding.SeverityMedium},
		finding.Finding{CanonicalControl: "TATAR-X-001", Resource: "deployment/api", Severity: finding.SeverityLow},
	)

	for _, raw := range []string{"low", "Low", "LOW", "LoW", "lOW"} {
		path := filepath.Join(t.TempDir(), ".tatar-kuber.yaml")
		if err := os.WriteFile(path, []byte("fail_on: "+raw+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(path)
		if err != nil {
			t.Fatalf("fail_on: %s — Load: %v", raw, err)
		}
		if !p.ValidFailOn() {
			t.Errorf("fail_on: %s — ValidFailOn()=false, CLI дэмий анхааруулна", raw)
		}
		if got, want := p.threshold(), finding.Rank(finding.SeverityLow); got != want {
			t.Errorf("fail_on: %s — threshold=%d, want %d (low)", raw, got, want)
		}
		r := p.Evaluate(res, now)
		if r.Passed {
			t.Errorf("fail_on: %s — MEDIUM+LOW байхад gate ДАВСАН: босго чимээгүй сулрав", raw)
		}
		if len(r.Violations) != 2 {
			t.Errorf("fail_on: %s — violations=%d, want 2", raw, len(r.Violations))
		}
	}
}

// Бусад түвшний том/жижиг бичиглэл ч мөн адил, мөн танигдахгүй утга нь
// ХАТУУ `high`-д унана (сулруулахгүй).
func TestValidFailOn_CaseVariantsAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
		want  finding.Severity // хүлээгдэх хүчинтэй босго
	}{
		{"critical", true, finding.SeverityCritical},
		{"Critical", true, finding.SeverityCritical},
		{"CRITICAL", true, finding.SeverityCritical},
		{"CrItIcAl", true, finding.SeverityCritical},
		{"high", true, finding.SeverityHigh},
		{"High", true, finding.SeverityHigh},
		{"HIGH", true, finding.SeverityHigh},
		{"medium", true, finding.SeverityMedium},
		{"Medium", true, finding.SeverityMedium},
		{"MEDIUM", true, finding.SeverityMedium},
		{"low", true, finding.SeverityLow},
		{"Low", true, finding.SeverityLow},
		{"LOW", true, finding.SeverityLow},
		// Баримтжуулсан олонлог нь critical|high|medium|low — INFO нь gate-ийн
		// босго БИШ, танигдахгүй утга нь хатуу high руу унана.
		{"info", false, finding.SeverityHigh},
		{"informational", false, finding.SeverityHigh},
		{"bogus", false, finding.SeverityHigh},
		{"", false, finding.SeverityHigh},
		{"hgih", false, finding.SeverityHigh},
	} {
		p := Policy{FailOn: tc.raw}
		if got := p.ValidFailOn(); got != tc.valid {
			t.Errorf("fail_on=%q: ValidFailOn()=%v, want %v", tc.raw, got, tc.valid)
		}
		if got, want := p.threshold(), finding.Rank(tc.want); got != want {
			t.Errorf("fail_on=%q: threshold=%d, want %d (%s)", tc.raw, got, want, tc.want)
		}
	}
}
