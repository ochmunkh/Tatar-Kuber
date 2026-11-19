package cli

import (
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
	"github.com/ochmunkh/tatar-kuber/internal/risk"
)

// reseal recomputes every field a scan derives from its findings (digest,
// total, severity counts, score, band). Tests that build a scan-result.json by
// editing the findings of a real one use it so the file stays self-consistent --
// the gate refuses a file that is not (see integrity), and a test that hand-edits
// findings is exactly the kind of file it refuses.
func reseal(r *finding.ScanResult) {
	_, score, band, _ := risk.ApplyScores(r.Findings)
	r.Summary.RiskScore = score
	r.Summary.RiskBand = band
	r.Summary.TotalFindings = len(r.Findings)
	counts := map[finding.Severity]int{
		finding.SeverityCritical: 0, finding.SeverityHigh: 0, finding.SeverityMedium: 0,
		finding.SeverityLow: 0, finding.SeverityInfo: 0,
	}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	r.Summary.Counts = counts
	r.Metadata.ResultHash = orchestrator.ResultHash(r.Findings)
}
