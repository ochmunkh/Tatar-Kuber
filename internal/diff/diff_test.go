package diff

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func f(id, ctrl, res string, sev finding.Severity, risk float64) finding.Finding {
	return finding.Finding{
		ID: id, CanonicalControl: ctrl, Resource: res, Namespace: "production",
		Severity: sev, Title: ctrl + " on " + res, RiskContribution: risk,
		FoundBy: []string{"trivy"},
	}
}

func result(score int, fs ...finding.Finding) finding.ScanResult {
	r := finding.ScanResult{SchemaVersion: "1.0"}
	r.Summary.RiskScore = score
	r.Findings = fs
	return r
}

// Хамгийн гол шинж: ID тогтвортой тул severity өөрчлөгдөхөд "хуучин арилж шинэ
// гарлаа" гэж БИШ, "ижил асуудал дордов/сайжрав" гэж ангилагдана.
func TestCompare_Categories(t *testing.T) {
	old := result(50,
		f("aaa", "TATAR-CON-001", "deployment/api", finding.SeverityHigh, 20),
		f("bbb", "TATAR-OPS-002", "deployment/web", finding.SeverityLow, 2),
		f("ccc", "TATAR-RBAC-001", "clusterrole/admin", finding.SeverityCritical, 40),
		f("ddd", "TATAR-SEC-001", "deployment/db", finding.SeverityMedium, 8),
	)
	nw := result(62,
		f("aaa", "TATAR-CON-001", "deployment/api", finding.SeverityCritical, 40), // дордов
		f("bbb", "TATAR-OPS-002", "deployment/web", finding.SeverityLow, 2),       // хэвээр
		f("ddd", "TATAR-SEC-001", "deployment/db", finding.SeverityLow, 2),        // сайжрав
		f("eee", "TATAR-IMG-003", "deployment/api", finding.SeverityHigh, 20),     // шинэ
		// ccc алга болов -> зассан
	)
	r := Compare(old, nw)

	want := map[Change]int{ChangeNew: 1, ChangeWorsened: 1, ChangeFixed: 1, ChangeImproved: 1, ChangeUnchanged: 1}
	for c, n := range want {
		if r.Counts[c] != n {
			t.Errorf("%s: got %d, want %d", c, r.Counts[c], n)
		}
	}
	if len(r.Items) != 5 {
		t.Fatalf("items: got %d, want 5", len(r.Items))
	}
	// Эрэмбэ: шинэ нь эхэнд, дараа нь дордсон.
	if r.Items[0].Change != ChangeNew || r.Items[1].Change != ChangeWorsened {
		t.Errorf("эрэмбэ буруу: %s, %s", r.Items[0].Change, r.Items[1].Change)
	}
	if r.ScoreDelta != 12 {
		t.Errorf("score delta: got %d, want 12", r.ScoreDelta)
	}
	// Дордсон нь хуучин severity-гээ хадгална.
	for _, it := range r.Items {
		if it.ID == "aaa" {
			if it.OldSeverity != finding.SeverityHigh || it.Severity != finding.SeverityCritical {
				t.Errorf("aaa: %s -> %s", it.OldSeverity, it.Severity)
			}
			if it.RiskDelta != 20 {
				t.Errorf("aaa risk delta: got %v, want 20", it.RiskDelta)
			}
		}
		if it.ID == "ccc" && it.RiskDelta != -40 {
			t.Errorf("ccc risk delta: got %v, want -40", it.RiskDelta)
		}
	}
	if s := r.MaxNewSeverity(); s != finding.SeverityHigh {
		t.Errorf("MaxNewSeverity: got %s, want HIGH", s)
	}
}

func TestCompare_Identical(t *testing.T) {
	a := result(80, f("aaa", "TATAR-CON-001", "deployment/api", finding.SeverityHigh, 20))
	a.Metadata.ResultHash = "deadbeef"
	b := a
	r := Compare(a, b)
	if !r.SameResult {
		t.Error("ижил result_hash-ыг таниагүй")
	}
	if r.Counts[ChangeUnchanged] != 1 || len(r.Items) != 1 {
		t.Errorf("ижил scan: %v", r.Counts)
	}
	if s := r.MaxNewSeverity(); s != "" {
		t.Errorf("шинэ finding байхгүй атал %s", s)
	}
}

// Тоо буурсан нь сайн мэдээ биш байж болно: scanner унасан ч тоо буурна.
func TestCompare_ScannerRegression(t *testing.T) {
	old := result(40, f("aaa", "TATAR-CON-001", "deployment/api", finding.SeverityHigh, 20))
	old.Metadata.ScannerRuns = []finding.ScannerRun{
		{Scanner: "trivy", Status: "ok", Findings: 323},
		{Scanner: "kubescape", Status: "ok", Findings: 18},
		{Scanner: "popeye", Status: "ok", Findings: 12},
	}
	nw := result(95)
	nw.Metadata.ScannerRuns = []finding.ScannerRun{
		{Scanner: "trivy", Status: "error", Findings: 0, Error: "exit 1"},
		{Scanner: "kubescape", Status: "ok", Findings: 18},
		// popeye огт байхгүй
	}
	r := Compare(old, nw)

	reg := r.Regressions()
	if len(reg) != 2 {
		t.Fatalf("regression: got %d, want 2 (trivy, popeye)", len(reg))
	}
	names := map[string]bool{reg[0].Scanner: true, reg[1].Scanner: true}
	if !names["trivy"] || !names["popeye"] {
		t.Errorf("буруу scanner: %v", names)
	}
	if len(r.Warnings) < 2 {
		t.Errorf("сэрэмжлүүлэг дутуу: %v", r.Warnings)
	}
	// Оноо "сайжирсан" мэт харагдаж байгаа ч шалтгаан нь scanner унасан.
	if r.ScoreDelta <= 0 {
		t.Errorf("score delta: got %d", r.ScoreDelta)
	}
	if r.Counts[ChangeFixed] != 1 {
		t.Errorf("fixed: %v", r.Counts)
	}
}

// kubescape хэвээр ok, finding нь ижил — regression гэж тэмдэглэх ёсгүй.
func TestCompare_ScannerStable(t *testing.T) {
	old, nw := result(40), result(40)
	old.Metadata.ScannerRuns = []finding.ScannerRun{{Scanner: "checkov", Status: "ok", Findings: 28}}
	nw.Metadata.ScannerRuns = []finding.ScannerRun{{Scanner: "checkov", Status: "ok", Findings: 30}}
	r := Compare(old, nw)
	if len(r.Regressions()) != 0 {
		t.Errorf("буруу regression: %v", r.Regressions())
	}
	if len(r.Warnings) != 0 {
		t.Errorf("шаардлагагүй сэрэмжлүүлэг: %v", r.Warnings)
	}
}

// rollup зөрөх нь resource-ийг өөрчилдөг тул diff үнэмшилгүй — заавал хэлнэ.
func TestCompare_RollupMismatchWarns(t *testing.T) {
	old, nw := result(50), result(50)
	nw.Metadata.Rollup = &finding.RollupInfo{Moved: 3, Pods: []string{"api-598c4dc6b8-ldjqq"}}
	r := Compare(old, nw)
	found := false
	for _, w := range r.Warnings {
		if w.Code == "rollup_mismatch" {
			found = true
		}
	}
	if !found {
		t.Errorf("rollup зөрүүг анхааруулаагүй: %v", r.Warnings)
	}
}

func TestCompare_ModeAndClusterWarn(t *testing.T) {
	old, nw := result(50), result(50)
	old.Metadata.ClusterName, nw.Metadata.ClusterName = "prod", "staging"
	old.Metadata.ScanMode, nw.Metadata.ScanMode = "remote", "local"
	r := Compare(old, nw)
	if len(r.Warnings) != 2 {
		t.Errorf("сэрэмжлүүлэг: got %d (%v), want 2", len(r.Warnings), r.Warnings)
	}
}

// ID хоосон файлтай тулгахад ижил асуудал "зассан + шинэ" гэж ХОЁР удаа
// тоологдож, тоо гуйвж байсан. Одоо хоёр талыг canonical түлхүүрээр тулгана.
func TestCompare_MissingIDsFallBackToCanonicalKey(t *testing.T) {
	old := result(50,
		f("aaa", "TATAR-CON-001", "deployment/api", finding.SeverityHigh, 20),
		f("bbb", "TATAR-OPS-002", "deployment/web", finding.SeverityLow, 2),
	)
	nw := result(50,
		f("", "TATAR-CON-001", "deployment/api", finding.SeverityHigh, 20),
		f("", "TATAR-OPS-002", "deployment/web", finding.SeverityLow, 2),
	)
	r := Compare(old, nw)
	if r.Counts[ChangeUnchanged] != 2 || r.Counts[ChangeNew] != 0 || r.Counts[ChangeFixed] != 0 {
		t.Errorf("ID дутуу үед буруу тоолов: %v", r.Counts)
	}
	if len(r.Warnings) == 0 || r.Warnings[0].Code != "missing_ids" {
		t.Errorf("ID дутууг анхааруулаагүй: %v", r.Warnings)
	}
	// Бүх ID байгаа үед canonical түлхүүрт шилжих ёсгүй — энгийн замаар л явна.
	if r2 := Compare(old, old); len(r2.Warnings) != 0 {
		t.Errorf("шаардлагагүй сэрэмжлүүлэг: %v", r2.Warnings)
	}
}

// Нэг талд scanner_runs огт байхгүй бол scanner бүрийг "унасан" гэж зарлах нь
// ХУДАЛ сэрэмжлүүлэг. Зөрүүг харуулна, гэхдээ regressed гэж тэмдэглэхгүй.
func TestCompare_MissingScannerRunsIsNotRegression(t *testing.T) {
	old, nw := result(40), result(40)
	old.Metadata.ScannerRuns = []finding.ScannerRun{
		{Scanner: "trivy", Status: "ok", Findings: 5},
		{Scanner: "checkov", Status: "ok", Findings: 89},
	}
	// nw-д scanner_runs байхгүй
	r := Compare(old, nw)
	if len(r.Regressions()) != 0 {
		t.Errorf("худал regression: %v", r.Regressions())
	}
	if len(r.Scanners) != 2 {
		t.Errorf("scanner зөрүү харагдах ёстой: %d", len(r.Scanners))
	}
	if len(r.Warnings) != 1 || r.Warnings[0].Code != "no_scanner_runs_new" {
		t.Errorf("нэг тодорхой сэрэмжлүүлэг байх ёстой: %v", r.Warnings)
	}
}
