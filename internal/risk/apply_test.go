package risk

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestApplyScores(t *testing.T) {
	// CRITICAL, production, MEDIUM confidence -> 10 * 1.5 * 1.0 * 1.0 = 15
	f := finding.Finding{
		CanonicalControl: "TATAR-RBAC-001",
		Namespace:        "production",
		Severity:         finding.SeverityCritical,
		Confidence:       finding.ConfidenceMedium,
	}
	scored, score, band, bd := ApplyScores([]finding.Finding{f})
	if scored[0].RiskContribution != 15 {
		t.Errorf("risk_contribution=%v, want 15", scored[0].RiskContribution)
	}
	// Diminishing: total=15 -> 100/(1+0.15)=87 (Good)
	if score != 87 || band != "Good" {
		t.Errorf("score=%d (%s), want 87 (Good)", score, band)
	}
	// Explainable factors: 10 × 1.5 × 1.0 × 1.0 = 15
	rf := scored[0].RiskFactors
	if rf == nil {
		t.Fatal("risk_factors хоосон — explainable задаргаа алга")
	}
	if rf.BaseWeight != 10 || rf.AssetContext != 1.5 || rf.Exposure != 1.0 || rf.Confidence != 1.0 {
		t.Errorf("factors=%+v, want base10 asset1.5 exp1.0 conf1.0", rf)
	}
	// Breakdown: нэг HIGH-pool finding, LOW pool хоосон, топ 1
	if bd.TotalPenalty != 15 || bd.HighPenalty != 15 || bd.LowPenaltyRaw != 0 {
		t.Errorf("breakdown=%+v, want total15 high15 low0", bd)
	}
	if len(bd.TopContributors) != 1 || bd.TopContributors[0].Share != 100 {
		t.Errorf("top=%+v, want 1 contributor at 100%%", bd.TopContributors)
	}
}

func TestDetectAssetContext(t *testing.T) {
	cases := map[string]float64{
		"production": CtxProduction,
		"prod-eu":    CtxProduction,
		"dev":        CtxDevelopment,
		"staging":    CtxDevelopment,
		"payments":   CtxUnknown,
	}
	for ns, want := range cases {
		if got := DetectAssetContext(ns); got != want {
			t.Errorf("DetectAssetContext(%q)=%v, want %v", ns, got, want)
		}
	}
}
