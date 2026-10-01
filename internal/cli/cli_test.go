package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// E2E: examples/demo raw -> scan -> report(sarif/html) -> gate. CLI давхарга
// өмнө нь огт тестгүй байсан (flag семантик, exit code, файл бичилт).
func TestCLI_ScanReportGate_E2E(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "e2e", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	resPath := filepath.Join(out, "scan-result.json")
	data, err := os.ReadFile(resPath)
	if err != nil {
		t.Fatal(err)
	}
	var res finding.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if res.Summary.TotalFindings == 0 || len(res.Metadata.ScannerRuns) != 4 {
		t.Fatalf("findings=%d runs=%d", res.Summary.TotalFindings, len(res.Metadata.ScannerRuns))
	}
	for _, r := range res.Metadata.ScannerRuns {
		if r.Status != "ingested" || r.Findings == 0 {
			t.Errorf("scanner_run %+v: ingested + findings>0 байх ёстой", r)
		}
	}

	for _, f := range []string{"sarif", "html", "json"} {
		p := filepath.Join(out, "r."+f)
		if code := cmdReport([]string{"--input", resPath, "-o", f, "--out", p}); code != 0 {
			t.Errorf("report %s exit=%d", f, code)
		}
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Errorf("report %s хоосон/алга", f)
		}
	}

	// Demo-д HIGH finding бий → default gate унана (exit 1); fail-on critical бол
	// CRITICAL байгаа эсэхээс хамаарна; policy файлгүй бол default high.
	if code := cmdGate([]string{"--input", resPath, "--policy", filepath.Join(out, "none.yaml")}); code != 1 {
		t.Errorf("gate default(high) exit=%d, want 1 (demo-д HIGH бий)", code)
	}
}

// Флаг ЗӨВХӨН өгсөн үед policy файлыг дарна: --min-score default (0) нь файлын
// min_score-ыг устгаж болохгүй (v1.0.0 regression).
func TestCLI_GateFlagsDoNotClobberPolicyFile(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "-o", out}); code != 0 {
		t.Fatal("scan")
	}
	resPath := filepath.Join(out, "scan-result.json")
	pol := filepath.Join(out, ".tatar-kuber.yaml")
	// fail_on critical-аас дээш л унана; min_score 100 → score хэзээ ч 100 биш тул унах ЁСТОЙ.
	if err := os.WriteFile(pol, []byte("fail_on: critical\nmin_score: 100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdGate([]string{"--input", resPath, "--policy", pol}); code != 1 {
		t.Errorf("min_score=100 файлаас уншигдаж gate унах ёстой, exit=%d", code)
	}
	// Тодорхой --min-score 0 өгвөл файлыг дарна → зөвхөн fail_on critical үлдэнэ.
	code := cmdGate([]string{"--input", resPath, "--policy", pol, "--min-score", "0"})
	var res finding.ScanResult
	b, _ := os.ReadFile(resPath)
	_ = json.Unmarshal(b, &res)
	want := 0
	if res.Summary.Counts[finding.SeverityCritical] > 0 {
		want = 1
	}
	if code != want {
		t.Errorf("--min-score 0 explicit: exit=%d want %d", code, want)
	}
}

func TestCLI_ScanRequiresInput(t *testing.T) {
	if code := cmdScan([]string{"-o", t.TempDir()}); code != 3 {
		t.Errorf("оролтгүй scan exit=%d, want 3", code)
	}
}

// `-o` нэг флаг хоёр өөр зүйл: scan-д ХАВТАС, report/diff-д ФОРМАТ. README-ийн
// hero блокт хоёр нь хажуу хажуу мөрөнд байсан тул `scan -o html` бичих нь
// хүлээгдэхүйц алдаа — гэтэл өмнө нь exit 0 буцааж, "html" нэртэй хавтас
// үүсгээд, scan-result.json-ыг хэрэглэгч хайхгүй газар бичдэг байв.
func TestCLI_ScanRejectsFormatAsOutDir(t *testing.T) {
	for _, v := range []string{"html", "json", "sarif", "text"} {
		if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "-o", v}); code != 3 {
			t.Errorf("scan -o %s: exit=%d, want 3", v, code)
		}
		if _, err := os.Stat(v); err == nil {
			t.Errorf("scan -o %s нь '%s' хавтас үүсгэсэн", v, v)
		}
	}
	// Зам хэлбэрээр өгвөл хүндэтгэнэ — false positive-ыг нарийн барьсан.
	dir := filepath.Join(t.TempDir(), "html")
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "-o", dir}); code != 0 {
		t.Errorf("scan -o <path>/html: exit=%d, want 0", code)
	}
	// --out-dir нь -o-ийн бүтэн нэр — хоёул ажиллана.
	long := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--out-dir", long}); code != 0 {
		t.Errorf("scan --out-dir: exit=%d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(long, "scan-result.json")); err != nil {
		t.Errorf("--out-dir нь scan-result.json бичсэнгүй: %v", err)
	}
}

// report --fail-on нь ЗӨВХӨН том үсгээр ажилладаг байв. Жижиг үсэг (бусад бүх
// газар — action.yml, .tatar-kuber.yaml.example, README — ингэж бичдэг) эсвэл
// бичиглэлийн алдаа нь Rank 0 болж, `>= 0` нь INFO хүртэл finding БҮРТЭЙ таарч,
// "high-аас дээшид унана" гэсэн босго "бүхэнд унана" болж ЭСРЭГЭЭРЭЭ хувирдаг
// байсан: gate унтардаггүй, харин чимээгүй байдлаар хуурамч эрсдэл зарладаг.
// Зөвхөн INFO-той fixture дээр шалгана — CRITICAL..LOW босго хэзээ ч давагдах
// ёсгүй, INFO босго давагдах ёстой (тест өөрөө ажиллаж байгаагийн баталгаа).
func TestCLI_ReportFailOnIsCaseInsensitive(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	var res finding.ScanResult
	b, err := os.ReadFile(filepath.Join(out, "scan-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	var infoOnly []finding.Finding
	for _, f := range res.Findings {
		if f.Severity == finding.SeverityInfo {
			infoOnly = append(infoOnly, f)
		}
	}
	if len(infoOnly) == 0 {
		t.Fatal("demo-д INFO finding алга — fixture үүсгэх боломжгүй")
	}
	res.Findings = infoOnly
	infoPath := filepath.Join(out, "info-only.json")
	d, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, d, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		failOn string
		want   int
	}{
		{"CRITICAL", 0}, {"critical", 0}, {"Critical", 0}, {"CrItIcAl", 0},
		{"HIGH", 0}, {"high", 0}, {"HiGh", 0},
		{"MEDIUM", 0}, {"medium", 0},
		{"LOW", 0}, {"low", 0},
		{"bogus", 0}, // танигдсангүй -> анхааруулна, харин эсрэгээрээ ажиллахгүй
		{"INFO", 1}, {"info", 1}, {"InFo", 1},
	} {
		code := cmdReport([]string{"--input", infoPath, "--format", "json",
			"--out", filepath.Join(out, "r.json"), "--fail-on", tc.failOn})
		if code != tc.want {
			t.Errorf("report --fail-on %q: exit=%d, want %d", tc.failOn, code, tc.want)
		}
	}
}

// Exit code бол gate-ийн ГЭРЭЭ: `set -e`-тэй pipeline-д "бодлого зөрчигдсөн" (1)
// ба "хэрэгсэл оролтоо уншиж чадсангүй" (2) хоёрыг ялгах чадвар нь gate-ийг
// report --fail-on-оос ялгаж байгаа гол зүйл. Энэ гэрээ өмнө нь ЗӨВХӨН экспортлоогүй
// Go тайлбарт байсан; одоо README + `--help` дээр хүснэгт болсон тул тэр хүснэгт
// хуучрахгүй байхыг тестээр барина.
//
// `doctor` энд байхгүй: түүний 1 нь "ямар ч scanner суугаагүй" гэсэн утга тул
// тестийг машин дээрх суулгацаас хамааралтай болгоно.
func TestCLI_ExitCodeContract(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	res := filepath.Join(out, "scan-result.json")

	bad := filepath.Join(out, "bad.json")
	if err := os.WriteFile(bad, []byte("{ not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(out, "missing.json")

	// БОДЛОГЫН файл нь ӨӨРӨӨ алдааны эх сурвалж: доорх gate case-ууд бүгд
	// эвдэрсэн/байхгүй ОРОЛТ-той хос тул оролтын алдаа нь эхэлж буцдаг ба
	// бодлогын мөр шалгагдахгүй үлдэнэ. Тиймээс САЙН оролт + эвдэрсэн бодлого
	// гэсэн case-ыг тусад нь шалгана (exit code хүснэгтийн `2` мөр).
	corruptPolicy := filepath.Join(out, "corrupt.tatar-kuber.yaml")
	if err := os.WriteFile(corruptPolicy, []byte("fail_on: [oops\n  bad: : :\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// exit 2 — ажиллагааны алдаа: уншигдахгүй / эвдэрсэн оролт.
	for _, tc := range []struct {
		name string
		code int
	}{
		{"report/эвдэрсэн", cmdReport([]string{"--input", bad, "--format", "json", "--out", filepath.Join(out, "x.json")})},
		{"report/байхгүй", cmdReport([]string{"--input", missing, "--format", "json"})},
		{"gate/эвдэрсэн", cmdGate([]string{"--input", bad, "--policy", missing})},
		{"gate/байхгүй", cmdGate([]string{"--input", missing, "--policy", missing})},
		{"gate/эвдэрсэн бодлого", cmdGate([]string{"--input", res, "--policy", corruptPolicy})},
		{"verify-lab/байхгүй", cmdVerifyLab([]string{"--input", missing, "--expected", missing})},
		{"verify-lab/эвдэрсэн expected", cmdVerifyLab([]string{"--input", res, "--expected", bad})},
	} {
		if tc.code != 2 {
			t.Errorf("%s: exit=%d, want 2", tc.name, tc.code)
		}
	}

	// exit 3 — хэрэглээний алдаа: формат / хэл / дутуу флаг.
	for _, tc := range []struct {
		name string
		code int
	}{
		{"report/формат", cmdReport([]string{"--input", res, "--format", "nope"})},
		{"report/хэл", cmdReport([]string{"--input", res, "--format", "json", "--lang", "de", "--out", filepath.Join(out, "de.json")})},
		{"diff/дутуу --old", cmdDiff([]string{"--new", res})},
		{"scan/оролтгүй", cmdScan([]string{"-o", out})},
	} {
		if tc.code != 3 {
			t.Errorf("%s: exit=%d, want 3", tc.name, tc.code)
		}
	}

	// exit 1 — бодлого/босго зөрчигдсөн. verify-lab FAIL: байхгүй control шаардана.
	exp := filepath.Join(out, "expected.json")
	if err := os.WriteFile(exp, []byte(`{"scenario":"none","controls":["TATAR-XXX-999"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdVerifyLab([]string{"--input", res, "--expected", exp}); code != 1 {
		t.Errorf("verify-lab FAIL: exit=%d, want 1", code)
	}
	// gate: demo-д HIGH бий тул default (high) бодлого унана.
	//
	// Мөн энэ нь exit code хүснэгтийн залруулгыг БАРИМТЖУУЛНА: бодлогын файл
	// БАЙХГҮЙ бол exit 2 БИШ — policy.Load нь os.IsNotExist үед Default()-ыг
	// зориуд буцаадаг тул gate нь built-in `fail_on: high`-аар ажиллаад
	// зөрчил дээрээ 1 буцаана (`.tatar-kuber.yaml` нь сонголт).
	if code := cmdGate([]string{"--input", res, "--policy", missing}); code != 1 {
		t.Errorf("gate FAILED (байхгүй бодлого -> default high): exit=%d, want 1", code)
	}
	// exit 0 — амжилттай.
	if code := cmdVerifyLab([]string{"--input", res,
		"--expected", writeExpectedPass(t, out)}); code != 0 {
		t.Errorf("verify-lab PASS: exit=%d, want 0", code)
	}
}

// writeExpectedPass — scan-д ҮНЭХЭЭР байгаа нэг control-ыг шаардсан expected
// spec (verify-lab-ийн PASS замыг шалгахад).
func writeExpectedPass(t *testing.T, dir string) string {
	t.Helper()
	var res finding.ScanResult
	b, err := os.ReadFile(filepath.Join(dir, "scan-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("finding алга")
	}
	p := filepath.Join(dir, "expected-pass.json")
	spec := fmt.Sprintf(`{"scenario":"demo","controls":[%q]}`, res.Findings[0].CanonicalControl)
	if err := os.WriteFile(p, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// E2E: rollup-тай ба rollup-гүй хоёр бодит scan-ыг diff хийнэ. --no-rollup нь
// pod-scoped finding-үүдийг үлдээдэг тул "шинэ" гэж гарах ба rollup зөрүүг
// анхааруулах ёстой. Мөн --fail-on-new exit code-ыг шалгана.
func TestCLI_Diff_E2E(t *testing.T) {
	out := t.TempDir()
	a, b := filepath.Join(out, "a"), filepath.Join(out, "b")
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "e2e", "-o", a}); code != 0 {
		t.Fatalf("scan a exit=%d", code)
	}
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "e2e", "--no-rollup", "-o", b}); code != 0 {
		t.Fatalf("scan b exit=%d", code)
	}
	ap := filepath.Join(a, "scan-result.json")
	bp := filepath.Join(b, "scan-result.json")

	if code := cmdDiff([]string{"--old", ap, "--new", bp}); code != 0 {
		t.Errorf("diff exit=%d, want 0", code)
	}
	// Ижил файлыг өөртэй нь тулгавал өөрчлөлт байх ёсгүй — exit 0 хэвээр.
	if code := cmdDiff([]string{"--old", ap, "--new", ap, "--fail-on-new", "low"}); code != 0 {
		t.Errorf("identical diff exit=%d, want 0", code)
	}
	// --no-rollup-д pod-scoped MEDIUM шинээр гарна -> босго давна.
	if code := cmdDiff([]string{"--old", ap, "--new", bp, "--fail-on-new", "medium"}); code != 1 {
		t.Errorf("fail-on-new medium exit=%d, want 1", code)
	}
	// CRITICAL шинэ finding байхгүй -> дамжина.
	if code := cmdDiff([]string{"--old", ap, "--new", bp, "--fail-on-new", "critical"}); code != 0 {
		t.Errorf("fail-on-new critical exit=%d, want 0", code)
	}
	// Заавал флаг дутуу -> 3.
	if code := cmdDiff([]string{"--new", bp}); code != 3 {
		t.Errorf("missing --old exit=%d, want 3", code)
	}
	// Байхгүй файл -> 2.
	if code := cmdDiff([]string{"--old", filepath.Join(out, "nope.json"), "--new", bp}); code != 2 {
		t.Errorf("missing file exit=%d, want 2", code)
	}
}

// Хэл бол ГАРАЛТЫН шинж чанар: нэг scan-result.json-оос хоёр хэл дээрх тайлан
// гарах ёстой, scan-ыг дахин ажиллуулахгүйгээр. v1.0.2 хүртэл хэл нь scan дээр
// л сонгогддог байсан тул монгол тайлан авахын тулд бүх scan дахин ажилладаг
// байв (cluster руу дахин хандах, 4 tool дахин ажиллуулах).
func TestCLI_ReportLangSwitchesWithoutRescan(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "lang", "--lang", "en", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	res := filepath.Join(out, "scan-result.json")
	before, err := os.ReadFile(res)
	if err != nil {
		t.Fatal(err)
	}

	read := func(lang string) finding.ScanResult {
		p := filepath.Join(out, "r-"+lang+".json")
		args := []string{"--input", res, "-o", "json", "--out", p}
		if lang != "" {
			args = append(args, "--lang", lang)
		}
		if code := cmdReport(args); code != 0 {
			t.Fatalf("report --lang %s exit=%d", lang, code)
		}
		var r finding.ScanResult
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	en, mn := read("en"), read("mn")
	if en.Metadata.Lang != "en" || mn.Metadata.Lang != "mn" {
		t.Fatalf("metadata.lang: en=%q mn=%q", en.Metadata.Lang, mn.Metadata.Lang)
	}
	if len(en.Findings) == 0 || len(en.Findings) != len(mn.Findings) {
		t.Fatalf("finding тоо зөрөв: %d vs %d", len(en.Findings), len(mn.Findings))
	}
	// Ядаж нэг гарчиг ҮНЭХЭЭР өөр байх ёстой — эс бөгөөс сэлгээ ажиллаагүй.
	diffs := 0
	for i := range en.Findings {
		if en.Findings[i].ID != mn.Findings[i].ID {
			t.Fatalf("finding эрэмбэ зөрөв: %s vs %s", en.Findings[i].ID, mn.Findings[i].ID)
		}
		if en.Findings[i].Title != mn.Findings[i].Title {
			diffs++
		}
	}
	if diffs == 0 {
		t.Error("en ба mn гарчиг бүгд ижил — ApplyLang ажиллаагүй")
	}

	// --lang өгөөгүй бол scan-ы хэл хэвээр (буцаад нийцтэй).
	if d := read(""); d.Metadata.Lang != "en" {
		t.Errorf("--lang-гүй: lang=%q, want en", d.Metadata.Lang)
	}

	// Хамгийн чухал: эх файл ХӨНДӨГДӨӨГҮЙ байх ёстой — эс бөгөөс result_hash
	// хүчингүй болж verify унана.
	after, err := os.ReadFile(res)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("report --lang нь scan-result.json-ыг өөрчилсөн — result_hash хүчингүй болно")
	}

	// Registry-д байхгүй хэлийг ЧИМЭЭГҮЙ en рүү унагахгүй, алдаа болгоно.
	if code := cmdReport([]string{"--input", res, "-o", "json", "--lang", "de",
		"--out", filepath.Join(out, "de.json")}); code != 3 {
		t.Errorf("--lang de exit=%d, want 3", code)
	}
}

// Офлайн ingest нь өөрийгөө "remote" гэж зарлаж байсан: cluster руу огт
// хандаагүй атлаа "амьд кластерын scan" гэсэн тайлан гаргадаг байв (v1.0.2-т
// mode нь ЗӨВХӨН -f байгаа эсэхээр шийдэгддэг, --raw-dir салаа түүнийг дамжуулдаг
// байсан). Хоёр хор: тайлан гарал үүслээ худал хэлнэ, мөн diff-ийн
// mode_mismatch хамгаалалт амьд scan ба офлайн ingest-ийг ялгаж чадахгүй болно.
func TestCLI_RawDirScanIsOffline(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "mode", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	var res finding.ScanResult
	b, err := os.ReadFile(filepath.Join(out, "scan-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res.Metadata.ScanMode != "offline" {
		t.Errorf("scan_mode=%q, want offline (--raw-dir нь scanner ажиллуулдаггүй)", res.Metadata.ScanMode)
	}
}

// gate --baseline: аль хэдийн байсан олдворт унахгүй, ЗӨВХӨН шинэ ба дордсонд
// унана. Багууд эхний өдөр 200 олдвортой танилцахдаа gate-ээ бүхэлд нь
// унтраахаас сэргийлэх зорилготой — унтраасан gate бол gate биш.
func TestCLI_GateBaseline(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--cluster", "bl", "-o", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	basePath := filepath.Join(out, "scan-result.json")
	none := filepath.Join(out, "none.yaml")

	// Baseline-гүй: demo-д HIGH бий тул унана.
	if code := cmdGate([]string{"--input", basePath, "--policy", none}); code != 1 {
		t.Fatalf("baseline-гүй: exit=%d, want 1", code)
	}
	// Өөрөө өөртэйгээ: өөрчлөлт алга тул давна.
	if code := cmdGate([]string{"--input", basePath, "--policy", none, "--baseline", basePath}); code != 0 {
		t.Errorf("өөрчлөлтгүй baseline: exit=%d, want 0", code)
	}

	var res finding.ScanResult
	b, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}

	write := func(name string, r finding.ScanResult) string {
		p := filepath.Join(out, name)
		d, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, d, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// ШИНЭ critical нэмэхэд унана.
	withNew := res
	withNew.Findings = append(append([]finding.Finding(nil), res.Findings...), finding.Finding{
		ID: "blnew0000001", CanonicalControl: "TATAR-SEC-001", Resource: "deployment/brand-new",
		Namespace: "production", Severity: finding.SeverityCritical, Title: "new",
	})
	if code := cmdGate([]string{"--input", write("new.json", withNew), "--policy", none, "--baseline", basePath}); code != 1 {
		t.Errorf("шинэ CRITICAL: exit=%d, want 1", code)
	}

	// ДОРДСОН олдвор мөн унагана: LOW нь CRITICAL болоход "хуучин асуудал" гэж
	// чимээгүй өнгөрөх нь энэ хэрэгслийн эсэргүүцдэг зүйл.
	worse := res
	worse.Findings = append([]finding.Finding(nil), res.Findings...)
	bumped := false
	for i := range worse.Findings {
		if finding.Rank(worse.Findings[i].Severity) < finding.Rank(finding.SeverityHigh) {
			worse.Findings[i].Severity = finding.SeverityCritical
			bumped = true
			break
		}
	}
	if !bumped {
		t.Fatal("дордуулах олдвор олдсонгүй")
	}
	if code := cmdGate([]string{"--input", write("worse.json", worse), "--policy", none, "--baseline", basePath}); code != 1 {
		t.Errorf("дордсон олдвор: exit=%d, want 1", code)
	}

	// Итгэх боломжгүй baseline (өөр cluster) -> ХЭРЭГСЭХГҮЙ, бүх олдворт унана.
	other := res
	other.Metadata.ClusterName = "staging"
	if code := cmdGate([]string{"--input", basePath, "--policy", none,
		"--baseline", write("other.json", other)}); code != 1 {
		t.Errorf("cluster зөрсөн baseline: exit=%d, want 1 (baseline хэрэгсэхгүй)", code)
	}

	// Байхгүй файл -> уншилтын алдаа.
	if code := cmdGate([]string{"--input", basePath, "--policy", none,
		"--baseline", filepath.Join(out, "missing.json")}); code != 2 {
		t.Errorf("байхгүй baseline: exit=%d, want 2", code)
	}
}

// TestCLI_GateFailOnIsCaseInsensitive — README/action.yml-ийн "Severity босго
// (`--fail-on`, `--fail-on-new`, `fail_on:`) нь үсгийн том/жижигт үл хамаарна"
// гэсэн мэдэгдлийг GATE замд бэхэлнэ.
//
// Өмнө нь энэ мэдэгдэл gate-ийн хувьд ХУДАЛ байв: policy.ValidFailOn() ба
// threshold() нь яг таарах жижиг/ТОМ бичиглэлийг л зөвшөөрдөг тул `fail_on: Low`
// нь танигдахгүй → чимээгүйгээр `high` болж, LOW/MEDIUM олдвор gate-ийг
// унагахаа больдог байв. Босгыг СУЛРУУЛАХ тал руух чимээгүй хувирал нь яг энэ
// хэрэгслийн эсэргүүцдэг зүйл тул флаг ба БОДЛОГЫН ФАЙЛ хоёуланг шалгана.
func TestCLI_GateFailOnIsCaseInsensitive(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--out-dir", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	var res finding.ScanResult
	b, err := os.ReadFile(filepath.Join(out, "scan-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}

	// Босго ҮНЭХЭЭР ялгаатай шийдвэр гаргах fixture: хамгийн өндөр нь MEDIUM.
	// Ингэснээр critical/high -> pass, medium/low -> fail болж, босго
	// "хэрэгсэгдсэн эсэх" нь exit code-оор харагдана.
	var medLow []finding.Finding
	for _, f := range res.Findings {
		if f.Severity == finding.SeverityMedium || f.Severity == finding.SeverityLow {
			medLow = append(medLow, f)
		}
	}
	if len(medLow) == 0 {
		t.Fatal("demo-д MEDIUM/LOW finding алга — fixture үүсгэх боломжгүй")
	}
	res.Findings = medLow
	res.Summary.RiskScore = 0 // min_score шалгалт хөндлөнгөөс оролцохгүй
	d, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(out, "med-low.json")
	if err := os.WriteFile(input, d, 0o644); err != nil {
		t.Fatal(err)
	}
	none := filepath.Join(out, "no-policy.yaml") // байхгүй -> default high

	for _, tc := range []struct {
		failOn string
		want   int
	}{
		{"CRITICAL", 0}, {"critical", 0}, {"Critical", 0}, {"CrItIcAl", 0},
		{"HIGH", 0}, {"high", 0}, {"High", 0}, {"HiGh", 0},
		{"MEDIUM", 1}, {"medium", 1}, {"Medium", 1}, {"MeDiUm", 1},
		{"LOW", 1}, {"low", 1}, {"Low", 1}, {"LoW", 1},
		// Танигдаагүй утга нь ХАТУУ high-д унана (сулруулахгүй) + анхааруулна.
		{"bogus", 0}, {"hgih", 0},
	} {
		// 1) --fail-on флаг.
		if code := cmdGate([]string{"--input", input, "--policy", none, "--fail-on", tc.failOn}); code != tc.want {
			t.Errorf("gate --fail-on %q: exit=%d, want %d", tc.failOn, code, tc.want)
		}
		// 2) .tatar-kuber.yaml дотор fail_on: — README-ийн мэдэгдэл ҮҮНИЙГ Ч
		//    хамардаг тул флагтай ижил байх ёстой.
		polPath := filepath.Join(out, "pol.yaml")
		if err := os.WriteFile(polPath, []byte("fail_on: "+tc.failOn+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code := cmdGate([]string{"--input", input, "--policy", polPath}); code != tc.want {
			t.Errorf("policy fail_on: %s — exit=%d, want %d", tc.failOn, code, tc.want)
		}
	}
}

// TestScanFormatRemediationCommandsActuallyWork — `scan -o <формат>`-ийн
// алдааны мөр нь ҮНЭХЭЭР ажилладаг команд заах ёстой.
//
// Өмнө нь бүх формат `report --format <v>` руу чиглүүлдэг байв, гэтэл `report`
// нь json|sarif|html-ийг л хүлээж авдаг: `scan -o text` нь хэрэглэгчид
// `report --format text` гэж заадаг бөгөөд тэр нь БАС exit 3 — нэг алдааг
// нөгөө алдаагаар нөхөх. `text` нь `diff`-ийн формат.
func TestScanFormatRemediationCommandsActuallyWork(t *testing.T) {
	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--out-dir", out}); code != 0 {
		t.Fatalf("scan exit=%d", code)
	}
	res := filepath.Join(out, "scan-result.json")

	if len(reportFormats) == 0 {
		t.Fatal("reportFormats хоосон — хамгаалалт чимээгүй унтарсан")
	}
	for format, cmd := range reportFormats {
		var code int
		switch cmd {
		case "report":
			code = cmdReport([]string{"--input", res, "--format", format,
				"--out", filepath.Join(out, "r."+format)})
		case "diff":
			code = cmdDiff([]string{"--old", res, "--new", res, "--format", format})
		default:
			t.Errorf("формат %q -> танихгүй команд %q", format, cmd)
			continue
		}
		if code != 0 {
			t.Errorf("scan -o %s нь `tatar-kuber %s --format %s` гэж заадаг, "+
				"гэтэл тэр команд exit=%d буцаалаа — алдааны мөр нь ажиллахгүй "+
				"команд заана", format, cmd, format, code)
		}
	}
	// text нь `diff`-ийн формат, `report`-ийн БИШ (регрессийн анхор).
	if got := reportFormats["text"]; got != "diff" {
		t.Errorf(`reportFormats["text"]=%q, want "diff"`, got)
	}
}
