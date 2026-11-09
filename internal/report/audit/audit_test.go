package audit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func sample() finding.ScanResult {
	res := finding.ScanResult{
		Findings: []finding.Finding{
			{CanonicalControl: "TATAR-CON-001", Resource: "deployment/a", Namespace: "prod",
				Severity: finding.SeverityHigh, Title: "Privileged container",
				Remediation: "Set privileged: false", FoundBy: []string{"trivy", "kubescape"},
				Confidence: finding.ConfidenceHigh, ConfidenceReason: finding.ConfidenceReasonCorroborated},
			{CanonicalControl: "TATAR-CON-001", Resource: "deployment/b", Namespace: "prod",
				Severity: finding.SeverityHigh, Title: "Privileged container",
				FoundBy: []string{"trivy"}},
			{CanonicalControl: "TATAR-OPS-001", Resource: "deployment/c",
				Severity: finding.SeverityLow, Title: "No liveness probe", FoundBy: []string{"popeye"}},
		},
		Summary: finding.Summary{
			Counts:        map[finding.Severity]int{finding.SeverityHigh: 2, finding.SeverityLow: 1},
			RiskScore:     41,
			RiskBand:      "High",
			TotalFindings: 3,
		},
	}
	res.Metadata.ClusterName = "prod-1"
	res.Metadata.ScanMode = "remote"
	res.Metadata.ResultHash = "sha256:abc"
	res.Metadata.ScannerRuns = []finding.ScannerRun{
		{Scanner: "trivy", Status: "ok", Version: "0.74.0", Findings: 2},
		{Scanner: "checkov", Status: "unavailable"},
	}
	return res
}

func render(t *testing.T, res finding.ScanResult, lang string) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, res, lang); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Аудитын тайлангийн ЦӨМ нь "юу ажиллаагүй" хэсэг. Суугаагүй scanner нь нийт
// тоонд уусах ёсгүй — нэрээрээ, төлөвтэйгөө гарна (§6).
func TestRender_NamesTheScannerThatContributedNothing(t *testing.T) {
	out := render(t, sample(), "en")
	if !strings.Contains(out, "checkov") {
		t.Fatal("ажиллаагүй scanner тайланд алга")
	}
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Errorf("'unavailable' нь ойлгомжтой бичвэр болоогүй:\n%s", excerpt(out, "checkov"))
	}
}

// Оноо бол шийдвэр биш, нийтлэгдсэн томьёо: тайлангаас дахин тооцох боломжтой
// байх ёстой, тиймээс томьёо өөрөө баримт дотор байна.
func TestRender_CarriesTheScoreFormula(t *testing.T) {
	res := sample()
	res.Summary.RiskBreakdown = &finding.RiskBreakdown{
		Formula: "100 / (1 + P/K)", TotalPenalty: 142.5,
	}
	out := render(t, res, "en")
	// html/template нь '+'-ийг &#43; болгон зайлуулдаг (UTF-7-ийн эсрэг), тиймээс
	// түүхий мөрөөр биш, хоёр талаас нь шалгана. Хөрвүүлэгч PDF дээр зөв
	// харуулдаг — энэ бол зөвхөн эх кодын дүрслэл.
	if !strings.Contains(out, "100 / (1 ") || !strings.Contains(out, "P/K)") {
		t.Fatalf("томьёо тайланд алга:\n%s", excerpt(out, "Formula"))
	}
	if !strings.Contains(out, "142.5") {
		t.Errorf("нийт penalty алга")
	}
}

// Хугацаа дууссан attestation нь чимээгүй хаягдах ёсгүй: тайланд дууссан гэж
// нэрлэгдэж, шалгагдаагүйд тооцогдоно.
func TestRender_ExpiredAttestationIsMarkedNotDropped(t *testing.T) {
	res := sample()
	res.Attestations = []finding.Attestation{{
		Control: "TATAR-NET-004", Decision: finding.AttestCompliant,
		Severity: finding.SeverityHigh, Status: finding.AttestExpired,
		Rationale: "reviewed", AttestedBy: "maintainer",
		AttestedAt: "2026-01-01", Expires: "2026-02-01",
	}}
	out := render(t, res, "en")
	if !strings.Contains(out, "TATAR-NET-004") {
		t.Fatal("attestation тайланд алга")
	}
	if !strings.Contains(out, "EXPIRED") {
		t.Errorf("хугацаа дууссан нь тэмдэглэгдсэнгүй:\n%s", excerpt(out, "TATAR-NET-004"))
	}
}

// Нэг хяналтын хоёр олдвор НЭГ бүлэг болно: тайлан нь "хэдэн мөр" биш, "хэдэн
// зөрчил" гэдгийг харуулах ёстой.
func TestRender_GroupsFindingsByControl(t *testing.T) {
	out := render(t, sample(), "en")
	if n := strings.Count(out, "TATAR-CON-001 —"); n != 1 {
		t.Fatalf("TATAR-CON-001 нь %d удаа толгой болов, 1 байх ёстой", n)
	}
	for _, r := range []string{"deployment/a", "deployment/b"} {
		if !strings.Contains(out, r) {
			t.Errorf("%s бүлэг дотор алга", r)
		}
	}
}

// Бүлэг дотор HIGH нь LOW-оос дээш; бүлгүүдийн хооронд ч мөн адил. Эрэмбэ
// детерминистик байх нь §3 — хоёр тайланг тулгах боломжтой байхын тулд.
func TestRender_OrdersBySeverity(t *testing.T) {
	out := render(t, sample(), "en")
	hi, lo := strings.Index(out, "TATAR-CON-001"), strings.Index(out, "TATAR-OPS-001")
	if hi < 0 || lo < 0 {
		t.Fatal("хоёр хяналт хоёулаа гарах ёстой")
	}
	if hi > lo {
		t.Error("LOW хяналт HIGH-аас дээш гарч байна")
	}
}

// Итгэлцлийн ЗЭРЭГ дангаараа тайлбаргүй: аудитор "HIGH" гэдгийг үйлчлүүлэгчийн
// өмнө хамгаалахын тулд ЯАГААД гэдгийг нь мэдэх ёстой.
func TestRender_ConfidenceCarriesItsReason(t *testing.T) {
	out := render(t, sample(), "en")
	if !strings.Contains(out, "two or more scanners agreed") {
		t.Fatalf("confidence_reason хүний хэлээр гарсангүй:\n%s", excerpt(out, "Confidence"))
	}
}

// Хэл нь тайлангийн шинж чанар: нэг scan-аас хоёр хэл.
func TestRender_Bilingual(t *testing.T) {
	en, mn := render(t, sample(), "en"), render(t, sample(), "mn")
	if !strings.Contains(en, "Audit Report") {
		t.Error("англи гарчиг алга")
	}
	if !strings.Contains(mn, "аудитын тайлан") {
		t.Error("монгол гарчиг алга")
	}
	if strings.Contains(mn, "What ran — and what did not") {
		t.Error("монгол тайланд англи хэсгийн гарчиг үлдлээ")
	}
}

// Хэл заагаагүй бол scan-д сонгосон хэлээрээ үлдэнэ (v1.0.3-ийн гэрээ).
func TestRender_FallsBackToTheScansLanguage(t *testing.T) {
	res := sample()
	res.Metadata.Lang = "mn"
	if !strings.Contains(render(t, res, ""), "аудитын тайлан") {
		t.Fatal("metadata.lang хэрэгсэгдсэнгүй")
	}
}

// Гадаад нөөц татдаг тайлан нь жилийн дараа өөр юм болж харагдана. Аудитын
// баримт өөрөө бие даасан байх ёстой.
func TestRender_IsSelfContained(t *testing.T) {
	out := render(t, sample(), "en")
	for _, bad := range []string{"<script", "src=\"http", "href=\"http", "@import", "<link"} {
		if strings.Contains(out, bad) {
			t.Errorf("тайлан гадаад нөөц/скрипт агуулж байна: %q", bad)
		}
	}
}

func excerpt(s, around string) string {
	i := strings.Index(s, around)
	if i < 0 {
		return s[:min(400, len(s))]
	}
	return s[max(0, i-200):min(i+300, len(s))]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
