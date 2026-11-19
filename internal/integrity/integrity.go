// Package integrity checks that a scan-result.json agrees with itself.
//
// scan and gate are separate steps, often separate CI jobs, with a file passed
// between them. The gate used to trust that file whole: min_score read the
// stored risk_score, and nothing compared the findings with the digest the scan
// had written next to them. A file edited in between -- a finding deleted, a
// score lowered -- passed.
//
// This is a CONSISTENCY check, not authentication. Someone who can rewrite the
// file and recompute every derived field is not stopped; signing the result is
// a separate piece of work. What it does catch is the cheap cases -- a hand
// edit, a truncated or merged file, a result from a different scoring model --
// and it turns them from a silent pass into a refusal.
package integrity

import (
	"fmt"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
	"github.com/ochmunkh/tatar-kuber/internal/risk"
)

// Issue codes (stable: the CLI maps them to messages).
const (
	CodeHash  = "result_hash"
	CodeTotal = "total_findings"
	CodeCount = "severity_counts"
	CodeScore = "risk_score"
	CodeBand  = "risk_band"
)

// Issue — one disagreement between the file and its own findings.
type Issue struct {
	Code   string
	Detail string
}

// Check recomputes everything that is derived from the findings and reports each
// field that disagrees with what the file claims. An empty result means the file
// is self-consistent.
func Check(res finding.ScanResult) []Issue {
	var out []Issue
	add := func(code, format string, a ...any) {
		out = append(out, Issue{Code: code, Detail: fmt.Sprintf(format, a...)})
	}

	if want := orchestrator.ResultHash(res.Findings); res.Metadata.ResultHash != want {
		add(CodeHash, "metadata.result_hash is %q but the findings hash to %q", res.Metadata.ResultHash, want)
	}

	if res.Summary.TotalFindings != len(res.Findings) {
		add(CodeTotal, "summary.total_findings is %d but the file holds %d findings", res.Summary.TotalFindings, len(res.Findings))
	}

	counts := map[finding.Severity]int{}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	for _, sev := range []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo,
	} {
		if res.Summary.Counts[sev] != counts[sev] {
			add(CodeCount, "summary.counts[%s] is %d but the findings contain %d", sev, res.Summary.Counts[sev], counts[sev])
		}
	}

	_, score, band, _ := risk.ApplyScores(res.Findings)
	if res.Summary.RiskScore != score {
		add(CodeScore, "summary.risk_score is %d but the findings score %d", res.Summary.RiskScore, score)
	}
	if res.Summary.RiskBand != band {
		add(CodeBand, "summary.risk_band is %q but the findings give %q", res.Summary.RiskBand, band)
	}
	return out
}
