package integrity

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// examples/report/scan-result.json is a real result written by an earlier
// release, so it also proves the check does not reject honest older files.
func load(t *testing.T) finding.ScanResult {
	t.Helper()
	b, err := os.ReadFile("../../examples/report/scan-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var r finding.ScanResult
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) < 3 {
		t.Fatalf("fixture too small to be useful: %d findings", len(r.Findings))
	}
	return r
}

func has(issues []Issue, code string) bool {
	for _, i := range issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func TestCheck_HonestResultIsConsistent(t *testing.T) {
	if issues := Check(load(t)); len(issues) != 0 {
		t.Fatalf("an untouched result must be consistent, got %+v", issues)
	}
}

func TestCheck_LoweredScoreIsCaught(t *testing.T) {
	r := load(t)
	r.Summary.RiskScore += 40
	if !has(Check(r), CodeScore) {
		t.Fatal("a rewritten risk_score must be reported")
	}
}

func TestCheck_ChangedBandIsCaught(t *testing.T) {
	r := load(t)
	r.Summary.RiskBand = "Low"
	if !has(Check(r), CodeBand) {
		t.Fatal("a rewritten risk_band must be reported")
	}
}

func TestCheck_DeletedFindingIsCaught(t *testing.T) {
	r := load(t)
	r.Findings = r.Findings[1:]
	issues := Check(r)
	if !has(issues, CodeHash) || !has(issues, CodeTotal) {
		t.Fatalf("a removed finding must break the hash and the total, got %+v", issues)
	}
}

func TestCheck_DowngradedSeverityIsCaught(t *testing.T) {
	r := load(t)
	for i := range r.Findings {
		if r.Findings[i].Severity == finding.SeverityCritical {
			r.Findings[i].Severity = finding.SeverityLow
			break
		}
	}
	issues := Check(r)
	if !has(issues, CodeHash) || !has(issues, CodeCount) {
		t.Fatalf("a downgraded severity must break the hash and the counts, got %+v", issues)
	}
}

func TestCheck_EditedCountsAreCaught(t *testing.T) {
	r := load(t)
	r.Summary.Counts[finding.SeverityCritical] = 0
	if !has(Check(r), CodeCount) {
		t.Fatal("rewritten severity counts must be reported")
	}
}

func TestCheck_EmptyResultIsAnIssueOnlyIfItClaimsOtherwise(t *testing.T) {
	r := finding.ScanResult{}
	r.Metadata.ResultHash = "sha256:nonsense"
	if !has(Check(r), CodeHash) {
		t.Fatal("a result with findings removed entirely but a stale hash must be reported")
	}
}
