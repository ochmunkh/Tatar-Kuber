package cli

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
	"github.com/ochmunkh/tatar-kuber/internal/report/audit"
	htmlrep "github.com/ochmunkh/tatar-kuber/internal/report/html"
	jsonrep "github.com/ochmunkh/tatar-kuber/internal/report/json"
	"github.com/ochmunkh/tatar-kuber/internal/report/sarif"
)

var cyrillic = regexp.MustCompile(`[\x{0400}-\x{04FF}]`)

// Хоёр хэлтэй төсөлд хэл нь хоорондоо асдаг — нэг нэмсэн мөр, нэг мартсан
// орчуулга л хангалттай. Англи тайлан руу монгол үг орвол CI улаан болохгүй,
// хэрэглэгч л хардаг. Тиймээс гаралтыг нь өөрийг нь шалгана.
//
// Энэ төслийн кодын ТАЙЛБАРУУД монголоор бичигдсэн — тэр зөв. Шалгаж буй зүйл
// бол эх код биш, ГАРАЛТ: англи горимоор ажиллуулсан бүх тайлангийн форматад
// кирилл тэмдэгт байж болохгүй.
func TestEnglishOutputHasNoCyrillic(t *testing.T) {
	res := runDemoPipeline(t) // Lang: "en"

	// (1) машин уншдаг үндсэн баримт
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	checkNoCyrillic(t, "scan-result.json", string(raw))

	// (2) бүх тайлангийн формат
	var sb strings.Builder
	if err := jsonrep.Render(&sb, res); err != nil {
		t.Fatal(err)
	}
	checkNoCyrillic(t, "report --format json", sb.String())

	sb.Reset()
	if err := sarif.Render(&sb, res); err != nil {
		t.Fatal(err)
	}
	checkNoCyrillic(t, "report --format sarif", sb.String())

	sb.Reset()
	if err := htmlrep.Render(&sb, res); err != nil {
		t.Fatal(err)
	}
	checkNoCyrillic(t, "report --format html", sb.String())

	sb.Reset()
	if err := audit.Render(&sb, res, "en"); err != nil {
		t.Fatal(err)
	}
	checkNoCyrillic(t, "report --format audit", sb.String())
}

// Монгол горимд эсрэгээр: хүнд харагдах гол талбарууд англиар үлдэж болохгүй.
//
// Үл хамаарах зүйл: scanner өөрөө бичсэн тодорхой тайлбар ("secret detected:
// AWS") англиар үлдэнэ — энэ нь олдворын баримт, орчуулбал мэдээлэл алдагдана.
// Тиймээс энд ЗӨВХӨН remediation-ыг шалгана: тэр нь үргэлж canonical
// registry-гээс ирдэг тул англиар үлдэх ямар ч шалтгаангүй.
func TestMongolianOutputTranslatesRemediation(t *testing.T) {
	p, err := buildPipeline("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raws, inv, err := loadRawDir("../../examples/demo")
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Process(raws, orchestrator.Meta{
		ClusterName: "lang-purity", ScanMode: "offline", Lang: "mn", Inventory: inv,
	})
	if err != nil {
		t.Fatal(err)
	}

	bad := map[string]string{} // control → орчуулагдаагүй текст
	for _, f := range res.Findings {
		if f.Remediation == "" {
			continue
		}
		if !cyrillic.MatchString(f.Remediation) {
			bad[f.CanonicalControl] = f.Remediation
		}
	}
	if len(bad) > 0 {
		t.Errorf("монгол тайланд %d control-ын remediation орчуулагдаагүй байна:", len(bad))
		for ctrl, text := range bad {
			t.Errorf("  %s → %q", ctrl, text)
		}
		t.Errorf("schema/canonical-controls.yaml дотор remediation.mn-ийг гүйцээнэ.")
	}
}

func checkNoCyrillic(t *testing.T, what, out string) {
	t.Helper()
	locs := cyrillic.FindAllStringIndex(out, -1)
	if len(locs) == 0 {
		return
	}
	t.Errorf("%s: англи гаралт дотор кирилл тэмдэгт %d газар олдлоо", what, len(locs))
	shown := 0
	for _, loc := range locs {
		start, end := loc[0]-60, loc[1]+60
		if start < 0 {
			start = 0
		}
		if end > len(out) {
			end = len(out)
		}
		t.Errorf("  …%s…", strings.ReplaceAll(out[start:end], "\n", " "))
		if shown++; shown >= 5 {
			t.Errorf("  (цааш нь %d газар)", len(locs)-shown)
			break
		}
	}
}
