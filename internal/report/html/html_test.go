package html

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func TestRender_HTML(t *testing.T) {
	res := finding.ScanResult{
		SchemaVersion: "1.0",
		Metadata:      finding.Metadata{ClusterName: "production", ScanMode: "remote", Lang: "mn", ResultHash: "sha256:abc", TatarVersion: "1.0.0", ScannerVersions: map[string]string{"trivy": "0.67.2", "kubescape": "3.1.4"}, Inventory: map[string]int{"Nodes": 5, "Pods": 142}},
		Summary: finding.Summary{Counts: map[finding.Severity]int{finding.SeverityHigh: 1}, RiskScore: 78, RiskBand: "Good", TotalFindings: 1,
			RiskBreakdown: &finding.RiskBreakdown{TotalPenalty: 12.6, HighPenalty: 12.6, LowPenaltyRaw: 0, LowPenaltyCapped: 0, LowPoolCap: 10, Scale: 100, Formula: "100 / (1 + P/K)",
				TopContributors: []finding.TopContributor{{ID: "f1", CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Severity: finding.SeverityHigh, Contribution: 12.6, Share: 100}}}},
		Findings: []finding.Finding{{ID: "f1", CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Namespace: "production", Severity: finding.SeverityHigh, Title: "Privileged container", RiskContribution: 12.6, RiskFactors: &finding.RiskFactors{BaseWeight: 7, AssetContext: 1.5, Exposure: 1.0, Confidence: 1.2, Contribution: 12.6}, Attack: []finding.AttackTechnique{{Technique: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"}}, References: []string{"CIS-5.2.5", "MITRE-T1611", "https://avd.aquasec.com/misconfig/ksv017"}, Evidence: []finding.Evidence{{Scanner: "kubescape", Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "зөвлөмж: false"}}, Remediation: "securityContext.privileged=false болгоно", FoundBy: []string{"trivy", "kubescape"}, Confidence: finding.ConfidenceHigh}},
	}
	var b bytes.Buffer
	if err := Render(&b, res); err != nil {
		t.Fatalf("Render: %v", err)
	}
	s := b.String()
	for _, want := range []string{
		"TATAR-Kuber Security Report", "78/100", "TATAR-CON-001", "Privileged container", "production",
		"securityContext.privileged=false",
		"spec.template.spec.containers[0].securityContext.privileged",
		// mn UI шошго (Lang: mn)
		"Гүйцэтгэх хураангуй", "Гол эрсдэлүүд", "Зөвлөмж", "Засвар", "Нотолгоо", "Кластерын нөөц",
		"CIS-5.2.5", "MITRE-T1611", // compliance badges
		"Scanner хувилбар", "0.67.2", // metadata footer (mn label)
		"Nodes", "142", // inventory section
		"Эх сурвалж", "Trivy Advisory", "https://avd.aquasec.com/misconfig/ksv017", // References гарчиг + labeled link
		"Онооны зурвас",     // band legend (mn)
		"Онооны задаргаа",   // explainable score panel (mn)
		"100/(1+P/100)",     // formula with scale
		"7 × 1.5 × 1 × 1.2", // factor breakdown of the top risk
		"(100%)",            // score share of the top contributor
		"T1611",             // MITRE ATT&CK technique badge
		"Escape to Host",    // technique name (badge tooltip)
		"class=\"atk\"",     // ATT&CK badge styling present
	} {
		if !strings.Contains(s, want) {
			t.Errorf("HTML-д %q алга", want)
		}
	}
}

// <html lang> нь тайлангийн БОДИТ хэлтэй таарах ёстой. v1.0.2 хүртэл "mn" гэж
// хатуу бичээстэй байсан тул англи тайлан өөрийгөө монгол гэж зарладаг байв —
// дэлгэц уншигч, орчуулагч, хайлтын индексжүүлэлт бүгд үүнийг уншдаг.
func TestRender_HTMLLangMatchesReportLang(t *testing.T) {
	for _, tc := range []struct{ meta, want string }{
		{"mn", "mn"}, {"en", "en"}, {"", "en"}, {"de", "en"},
	} {
		var b strings.Builder
		res := finding.ScanResult{SchemaVersion: "1.0"}
		res.Metadata.Lang = tc.meta
		if err := Render(&b, res); err != nil {
			t.Fatal(err)
		}
		if want := `<html lang="` + tc.want + `">`; !strings.Contains(b.String(), want) {
			t.Errorf("metadata.lang=%q: %s олдсонгүй", tc.meta, want)
		}
	}
}

func TestRender_HostileTitleIsInertAndCSPPresent(t *testing.T) {
	res := finding.ScanResult{
		SchemaVersion: "1.0",
		Findings: []finding.Finding{{ID: "f1", CanonicalControl: "TATAR-CON-001", Resource: "deployment/api", Severity: finding.SeverityHigh,
			Title: `<script>alert(1)</script><img src="file:///etc/passwd">`}},
	}
	var b bytes.Buffer
	if err := Render(&b, res); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if strings.Contains(s, "<script") || strings.Contains(s, `<img src="file:`) {
		t.Fatal("hostile title leaked into the page as markup")
	}
	if !strings.Contains(s, `Content-Security-Policy" content="default-src 'none'`) {
		t.Fatal("HTML report must carry a restrictive CSP")
	}
}
