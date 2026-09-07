package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestRender_SARIF(t *testing.T) {
	res := finding.ScanResult{
		Metadata: finding.Metadata{TatarVersion: "1.0.0"},
		Findings: []finding.Finding{
			{CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Namespace: "production", Severity: finding.SeverityHigh, Title: "Privileged", Remediation: "fix", FoundBy: []string{"trivy", "kubescape"}, Confidence: finding.ConfidenceHigh},
			{CanonicalControl: "TATAR-OPS-003", Resource: "service/orphan", Severity: finding.SeverityInfo, Title: "Orphan", FoundBy: []string{"popeye"}},
		},
	}
	var b bytes.Buffer
	if err := Render(&b, res); err != nil {
		t.Fatalf("Render: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if m["version"] != "2.1.0" {
		t.Errorf("version=%v, want 2.1.0", m["version"])
	}
	if !strings.Contains(b.String(), "TATAR-CON-001") {
		t.Error("ruleId TATAR-CON-001 алга")
	}
	if !strings.Contains(b.String(), `"level": "error"`) {
		t.Error("HIGH -> level error байх ёстой")
	}
	if !strings.Contains(b.String(), `"level": "note"`) {
		t.Error("INFO -> level note байх ёстой")
	}
}

func TestRuleSeverityIsMaxAndFingerprints(t *testing.T) {
	res := finding.ScanResult{Findings: []finding.Finding{
		{ID: "TK-aaaaaa", CanonicalControl: "TATAR-X-001", Severity: finding.SeverityLow, Title: "x", Resource: "deployment/a"},
		{ID: "TK-bbbbbb", CanonicalControl: "TATAR-X-001", Severity: finding.SeverityCritical, Title: "x", Resource: "deployment/b"},
	}}
	var buf bytes.Buffer
	if err := Render(&buf, res); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if got := log.Runs[0].Tool.Driver.Rules[0].Properties["security-severity"]; got != "9.5" {
		t.Errorf("rule security-severity=%v, want 9.5 (max of findings)", got)
	}
	if fp := log.Runs[0].Results[1].PartialFingerprints["tatarId/v1"]; fp != "TK-bbbbbb" {
		t.Errorf("partialFingerprints=%v", log.Runs[0].Results[1].PartialFingerprints)
	}
}
