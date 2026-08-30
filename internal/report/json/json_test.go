package json

import (
	"bytes"
	stdjson "encoding/json"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func sample() finding.ScanResult {
	return finding.ScanResult{
		SchemaVersion: "1.0",
		Summary: finding.Summary{Counts: map[finding.Severity]int{finding.SeverityHigh: 1}, RiskScore: 80, RiskBand: "Good", TotalFindings: 1,
			RiskBreakdown: &finding.RiskBreakdown{TotalPenalty: 10.5, HighPenalty: 10.5, LowPoolCap: 10, Scale: 100, Formula: "100 / (1 + P/K)",
				TopContributors: []finding.TopContributor{{ID: "TK-abc123", CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Severity: finding.SeverityHigh, Contribution: 10.5, Share: 100}}}},
		Findings: []finding.Finding{{
			ID: "TK-abc123", CanonicalControl: "TATAR-CON-001", Resource: "deployment/api",
			Severity: finding.SeverityHigh, Title: "Privileged", FoundBy: []string{"trivy"},
			RiskContribution: 10.5, RiskFactors: &finding.RiskFactors{BaseWeight: 7, AssetContext: 1.0, Exposure: 1.5, Confidence: 1.0, Contribution: 10.5},
			Attack: []finding.AttackTechnique{{Technique: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"}},
		}},
	}
}

func TestRender_RoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, sample()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var back finding.ScanResult
	if err := stdjson.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Summary.TotalFindings != 1 || back.Findings[0].CanonicalControl != "TATAR-CON-001" {
		t.Errorf("round-trip алдаа: %+v", back.Summary)
	}
	// Explainable risk task-ий гаралт JSON-д хадгалагдсан эсэх
	if back.Summary.RiskBreakdown == nil || back.Summary.RiskBreakdown.TotalPenalty != 10.5 {
		t.Errorf("risk_breakdown round-trip алдаа: %+v", back.Summary.RiskBreakdown)
	}
	if len(back.Summary.RiskBreakdown.TopContributors) != 1 || back.Summary.RiskBreakdown.TopContributors[0].Share != 100 {
		t.Errorf("top_contributors round-trip алдаа: %+v", back.Summary.RiskBreakdown.TopContributors)
	}
	if back.Findings[0].RiskFactors == nil || back.Findings[0].RiskFactors.BaseWeight != 7 {
		t.Errorf("risk_factors round-trip алдаа: %+v", back.Findings[0].RiskFactors)
	}
	// JSON түлхүүрүүд snake_case-ээр гарсан эсэх
	if len(back.Findings[0].Attack) != 1 || back.Findings[0].Attack[0].Technique != "T1611" {
		t.Errorf("attack round-trip алдаа: %+v", back.Findings[0].Attack)
	}
	raw := b.String()
	for _, key := range []string{`"risk_breakdown"`, `"risk_factors"`, `"top_contributors"`, `"total_penalty"`, `"base_weight"`, `"attack"`, `"technique"`, `"tactic"`} {
		if !bytes.Contains([]byte(raw), []byte(key)) {
			t.Errorf("JSON-д %s түлхүүр алга", key)
		}
	}
}
