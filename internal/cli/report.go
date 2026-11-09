package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
	auditrep "github.com/ochmunkh/tatar-kuber/internal/report/audit"
	htmlrep "github.com/ochmunkh/tatar-kuber/internal/report/html"
	jsonrep "github.com/ochmunkh/tatar-kuber/internal/report/json"
	sarifrep "github.com/ochmunkh/tatar-kuber/internal/report/sarif"
)

func cmdReport(args []string) int {
	// explicitLang — хэрэглэгч хэлээ ТОДОРХОЙ зааж өгсөн эсэх. `--lang`-гүй үед
	// CLI-ийн өөрийн мөрүүд default (англи) хэлээр гарах боловч ТАЙЛАН өөрөө
	// scan-д сонгосон хэлээрээ үлдэнэ — энэ нь v1.0.3-ийн гэрээ (нэг scan,
	// хоёр хэл) бөгөөд буцаад нийцтэй байдал.
	explicitLang, code := setLang(args)
	if code != 0 {
		return code
	}
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	input := fs.String("input", "scan-result.json", msg("flag.input"))
	// --format нь -o-ийн бүтэн нэр. `scan -o` бол ХАВТАС, `report -o` бол ФОРМАТ
	// байсан тул README-ийн хажуу хажуугийн хоёр мөрөнд нэг флаг хоёр өөр зүйл
	// гэж харагдаж байв. -o хэвээр ажиллана (CI эвдрэхгүй), харин баримтад
	// бүтэн нэрийг ашиглана.
	format := fs.String("o", "html", msg("flag.report.format"))
	fs.StringVar(format, "format", "html", msg("flag.report.format.long"))
	out := fs.String("out", "", msg("flag.report.out"))
	failOn := fs.String("fail-on", "", msg("flag.report.failon"))
	addLangFlag(fs, "flag.report.lang")
	registry := fs.String("registry", "", msg("flag.report.registry"))
	_ = fs.Parse(args)

	data, err := os.ReadFile(*input)
	if err != nil {
		errln(err)
		return 2
	}
	var res finding.ScanResult
	if err := jsonUnmarshal(data, &res); err != nil {
		errln(msg("report.parse.failed"), err)
		return 2
	}

	// Хэл бол ГАРАЛТЫН шинж чанар — scan-ы биш. Нэг scan-result.json-оос хоёр
	// хэл дээрх тайланг scan-ыг дахин ажиллуулалгүйгээр гаргана.
	if explicitLang {
		if code := relang(&res, uiLang, *registry); code != 0 {
			return code
		}
	}

	// PDF нь урсгал руу бичигддэггүй: хөрвүүлэгч файл шаардана. Тиймээс
	// --out-гүй үед өөрөө нэр сонгоно.
	target := *out
	switch {
	case target == "" && *format == "html":
		target = "report.html"
	case target == "" && *format == "audit":
		target = "audit.html"
	case target == "" && *format == "pdf":
		target = "audit.pdf"
	}

	// PDF-ийн зам тусдаа: эхлээд хөрвүүлэгч БАЙГАА эсэхийг шалгана, дараа нь л
	// ямар нэг зүйл үүсгэнэ. Тайланг бичээд сүүлд нь "хөрвүүлэгч алга" гэж
	// хэлэх нь хагас үр дүн үлдээнэ.
	// Хэл: --lang тодорхой өгөгдсөн үед л дарна. Эс бөгөөс тайлан нь scan-д
	// сонгосон хэлээрээ үлдэнэ (v1.0.3-ийн гэрээ).
	reportLang := ""
	if explicitLang {
		reportLang = uiLang
	}
	if *format == "pdf" {
		return renderAuditPDF(res, target, reportLang, *failOn)
	}

	w := os.Stdout
	if target != "" {
		// #nosec G304 -- target бол хэрэглэгчийн --out туг: тайлангаа хаана
		// бичихийг хэрэглэгч шийднэ.
		f, err := os.Create(target)
		if err != nil {
			errln(err)
			return 2
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "json":
		err = jsonrep.Render(w, res)
	case "sarif":
		err = sarifrep.Render(w, res)
	case "html":
		err = htmlrep.Render(w, res)
	case "audit":
		err = auditrep.Render(w, res, reportLang)
	default:
		fmt.Fprintln(os.Stderr, msg("report.format.unknown"), *format)
		return 3
	}
	if err != nil {
		errln(msg("report.render.failed"), err)
		return 2
	}
	if target != "" {
		fmt.Println(msg("report.wrote", target))
	}

	// Босгыг ШУУД finding.Severity() болгож хөрвүүлэхгүй: "critical" (жижиг
	// үсгээр — action.yml, .tatar-kuber.yaml.example, README бүгд ингэж бичдэг)
	// нь Rank 0 болж, `>= 0` нь INFO хүртэл БҮХ finding-тэй таарч, "high-аас
	// дээшид унана" гэсэн gate "бүхэнд унана" болж хувирдаг байв.
	if *failOn != "" {
		if th, ok := parseSeverityThreshold(*failOn, "--fail-on"); ok && exceedsThreshold(res, th) {
			return 1
		}
	}
	return 0
}

// relang — scan-result-ийн finding гарчиг/засварыг өөр хэл рүү сэлгэнэ.
//
// scan-result.json дотор гарчиг нь scan хийх үед сонгосон НЭГ хэлээр шингэсэн
// байдаг. Орчуулгын эх сурвалж нь canonical registry тул тайлан гаргах үед
// дахин хэрэглэж болно — cluster руу дахин хандах, 4 tool-ыг дахин ажиллуулах
// шаардлагагүй.
//
// res-ийг ЗӨВХӨН санах ойд өөрчилнө; scan-result.json файл хөндөгдөхгүй тул
// түүний result_hash хүчинтэй хэвээр (`verify` ажиллана).
func relang(res *finding.ScanResult, lang, registryPath string) int {
	path, err := resolveRegistry(registryPath)
	if err != nil {
		errln(err)
		return 2
	}
	reg, err := loadRegistry(path)
	if err != nil {
		errln(err)
		return 2
	}
	// Байхгүй хэлийг ЧИМЭЭГҮЙ en рүү унагавал хэрэглэгч буруу хэлээр гаргасныг
	// мэдэхгүй өнгөрнө. Тиймээс шууд зогсоож, юу байгааг нь хэлнэ.
	if !reg.HasLang(lang) {
		errln(msg("report.lang.missing", lang, strings.Join(reg.Languages(), ", ")))
		return 3
	}

	orchestrator.ApplyLang(res.Findings, reg, lang)
	res.Metadata.Lang = lang

	// Attestation-ийн гарчиг нь apply хийх үеийн хэлээр шингэсэн байдаг.
	// Түүнийг ч сэлгэнэ — эс бөгөөс монгол тайлан дунд англи гарчигтай мөр
	// үлдэж, "нэг scan, хоёр хэл" гэсэн гэрээ хагас биелнэ. Хүний бичсэн
	// талбаруудад (rationale, scope) ГАР ХҮРЭХГҮЙ: тэдгээр нь орчуулга биш,
	// гэрчлэл — бичигдсэн хэлээрээ үлдэх ёстой.
	for i := range res.Attestations {
		if c, ok := reg.Get(res.Attestations[i].Control); ok {
			res.Attestations[i].Title = c.Title.Get(lang)
		}
	}

	// Зөвлөмж нь finding-ийн remediation-оос үүсдэг тул дээрх дуудлагаар
	// сэлгэгдэнэ. Гэхдээ registry-д байхгүй control-ийн гарчиг scanner-ийн эх
	// текстээрээ үлдэх тул тайланд холимог хэл үлдэж болзошгүйг нуухгүй.
	if n := untranslatable(res.Findings, reg); n > 0 {
		warnln(msg("report.untranslatable", n))
	}
	return 0
}

// untranslatable — canonical registry-д тохирохгүй тул орчуулагдах боломжгүй
// finding-ийн тоо.
func untranslatable(fs []finding.Finding, reg *canonical.Registry) int {
	n := 0
	for _, f := range fs {
		if _, ok := reg.Get(f.CanonicalControl); !ok {
			n++
		}
	}
	return n
}

func exceedsThreshold(res finding.ScanResult, th finding.Severity) bool {
	t := finding.Rank(th)
	for _, f := range res.Findings {
		if finding.Rank(f.Severity) >= t {
			return true
		}
	}
	return false
}
