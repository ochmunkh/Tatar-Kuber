package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

func cmdScan(args []string) int {
	if _, code := setLang(args); code != 0 {
		return code
	}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	file := fs.String("f", "", msg("flag.scan.file"))
	kubeconfig := fs.String("kubeconfig", "", msg("flag.scan.kubeconfig"))
	context_ := fs.String("context", "", msg("flag.scan.context"))
	namespaces := fs.String("namespace", "", msg("flag.scan.namespace"))
	rawDir := fs.String("raw-dir", "", msg("flag.scan.rawdir"))
	cluster := fs.String("cluster", "cluster", msg("flag.scan.cluster"))
	outDir := fs.String("o", ".", msg("flag.scan.outdir"))
	fs.StringVar(outDir, "out-dir", ".", msg("flag.scan.outdir.long"))
	registry := fs.String("registry", "", msg("flag.registry"))
	// Тайлангийн хэл нь CLI-ийн гаралтын хэлтэй НЭГ: scan-result.json дотор
	// шингэх гарчиг/зөвлөмж хэрэглэгчийн сонгосон хэлээр бичигдэнэ.
	addLangFlag(fs, "flag.lang")
	noRaw := fs.Bool("no-raw", false, msg("flag.scan.noraw"))
	noRollup := fs.Bool("no-rollup", false, msg("flag.scan.norollup"))
	_ = fs.Parse(args)

	if code := rejectFormatAsOutDir(*outDir); code != 0 {
		return code
	}

	regPath, err := resolveRegistry(*registry)
	if err != nil {
		errln(err)
		return 3
	}
	p, err := buildPipeline(regPath)
	if err != nil {
		errln(err)
		return 2
	}

	mode := "remote"
	if *file != "" {
		mode = "local"
	}

	if *rawDir != "" {
		// Offline ingest: цуглуулсан raw-г нэгтгэнэ.
		//
		// scan_mode="offline" — mode хувьсагчийг ДАМЖУУЛАХГҮЙ. v1.0.2 хүртэл
		// офлайн ingest нь "remote" гэж тайлагнагддаг байсан (mode нь зөвхөн -f
		// байгаа эсэхээр шийдэгддэг тул): cluster руу огт хандаагүй атлаа
		// "амьд кластерын scan" гэж зарладаг байв. Хоёр хор: (1) тайлан өөрийн
		// гарал үүслийг худал хэлнэ, (2) diff-ийн mode_mismatch хамгаалалт
		// амьд scan ба офлайн ingest-ийг ялгаж чадахгүй болно.
		//
		// "offline" гэдэг нь ҮНЭН мэдэгдэл: scanner-ыг бид ажиллуулаагүй, урьд
		// цуглуулсан гаралтыг уншсан. Тэр гаралт нь анх local эсвэл remote
		// горимоор цуглуулагдсаныг энэ давхаргаас МЭДЭХ БОЛОМЖГҮЙ тул таамаглахгүй.
		raws, inv, err := loadRawDir(*rawDir)
		if err != nil {
			errln(err)
			return 2
		}
		r, err := p.Process(raws, orchestrator.Meta{ClusterName: *cluster, ScanMode: "offline", Lang: uiLang, Inventory: inv, NoRollup: *noRollup})
		if err != nil {
			errln(err)
			return 2
		}
		warnRuns(r.Metadata.ScannerRuns)
		reportRollup(r.Metadata.Rollup)
		return writeResult(r, *outDir)
	}

	// Live scan: adapter-уудыг ажиллуулна (scanner binary шаардлагатай).
	if *file == "" && *kubeconfig == "" && *context_ == "" {
		fmt.Fprintln(os.Stderr, msg("scan.input.required"))
		return 3
	}
	target := scanner.Target{
		Mode:       scanner.Mode(mode),
		Path:       *file,
		Kubeconfig: *kubeconfig,
		Context:    *context_,
		Namespaces: splitCSV(*namespaces),
	}
	raws, runs := p.Collect(context.Background(), target)

	// Түүхий гаралтыг нотолгоо болгон хадгална (<out>/raw/<scanner>.json + versions.json).
	// Энэ хавтас нь `scan --raw-dir` оролттой яг ижил бүтэцтэй → дахин боловсруулж болно.
	if !*noRaw && len(raws) > 0 {
		if err := saveRaw(filepath.Join(*outDir, "raw"), raws); err != nil {
			warnln(msg("warn.raw.save.failed"), err)
		}
	}

	r, err := p.Process(raws, orchestrator.Meta{ClusterName: *cluster, ScanMode: mode, Lang: uiLang, Runs: runs, NoRollup: *noRollup})
	if err != nil {
		errln(err)
		return 2
	}
	warnRuns(r.Metadata.ScannerRuns)
	reportRollup(r.Metadata.Rollup)
	if len(raws) == 0 {
		warnln(msg("warn.no.scanner.ran"))
	}
	return writeResult(r, *outDir)
}

// reportFormats — форматын нэр -> тэр форматыг ҮНЭХЭЭР хүлээж авдаг команд
// (scan-ийн хавтас БИШ). `report` нь json|sarif|html, `diff` нь text|json тул
// "text"-ийг `report`-т заавал exit 3-тай ХОЁР ДАХЬ буруу команд болно —
// алдааны мөр нь хэрэглэгчийг ажилладаг команд руу л чиглүүлэх ёстой.
var reportFormats = map[string]string{
	"json":  "report",
	"sarif": "report",
	"html":  "report",
	"text":  "diff",
}

// rejectFormatAsOutDir — `scan -o html` нь өмнө нь exit 0 буцааж, "html" нэртэй
// ХАВТАС үүсгэж, scan-result.json-ыг хэрэглэгчийн хүлээгээгүй газар бичдэг байв:
// ямар ч анхааруулгагүй, "амжилттай" харагдах бүтэлгүйтэл. "0 finding-тэй
// scanner хэзээ ч чимээгүй өнгөрөхгүй" гэсэн өөрийн стандарттаа нийцэхгүй.
//
// Үнэхээр тэр нэртэй хавтас хэрэгтэй бол зам хэлбэрээр (`-o ./html`) өгнө —
// false positive-ыг зориуд нарийн барьсан.
func rejectFormatAsOutDir(dir string) int {
	cmd, isFormat := reportFormats[dir]
	if !isFormat {
		return 0
	}
	errln(msg("scan.outdir.is.format", dir, cmd, dir, dir, dir))
	return 3
}

// warnRuns — scanner бүрийн явцыг stderr-т нэг мөрөөр, асуудалтайг нь тодруулж хэвлэнэ.
// Зорилго: "scanner суусан байсан ч 0 finding" нөхцөл хэзээ ч чимээгүй өнгөрөхгүй.
func warnRuns(runs []finding.ScannerRun) {
	for _, r := range runs {
		switch r.Status {
		case "unsupported":
			continue
		case "ok", "ingested":
			fmt.Fprintf(os.Stderr, "scanner %-10s %-9s findings=%d", r.Scanner, r.Status, r.Findings)
			if r.UnmappedCount > 0 {
				fmt.Fprintf(os.Stderr, "  unmapped=%d (%d rule)", r.UnmappedCount, len(r.UnmappedRules))
			}
			fmt.Fprintln(os.Stderr)
		default:
			fmt.Fprintf(os.Stderr, "scanner %-10s %-9s %s\n", r.Scanner, r.Status, r.Error)
		}
	}
	for _, p := range orchestrator.Problems(runs) {
		warnln(problemText(p))
	}
}

// problemText — orchestrator-ийн анхааруулгыг хэрэглэгчийн хэл рүү буулгана.
// Тэр багц нь БИЧВЭР биш, КОД буцаадаг (diff.Warning-тай ижил зарчим) тул
// хэлний сонголт нэг л газар — энэ каталогт — үлдэнэ.
func problemText(p orchestrator.Problem) string {
	if p.Code == orchestrator.ProblemNoFindings {
		s := msg("warn.scanner.no.findings", p.Scanner)
		if p.Unmapped != "" {
			s += msg("warn.scanner.unmapped", p.Unmapped)
		}
		return s
	}
	return p.Scanner + ": " + p.Status + " — " + p.Error
}

// reportRollup — Pod -> controller зөөлтийг stderr-т мэдэгдэнэ. Тоо буурсан нь
// "асуудал арилсан" гэсэн үг биш тул чимээгүй байж болохгүй.
func reportRollup(r *finding.RollupInfo) {
	if r == nil || r.Moved == 0 {
		return
	}
	fmt.Fprint(os.Stderr, msg("scan.rollup", r.Moved, len(r.Pods)))
}

// saveRaw — raw scanner гаралтыг <dir>/<scanner>.json, хувилбаруудыг versions.json болгон бичнэ.
func saveRaw(dir string, raws []scanner.RawResult) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	vers := map[string]string{}
	for _, raw := range raws {
		if err := os.WriteFile(filepath.Join(dir, raw.Scanner+".json"), raw.Data, 0o644); err != nil {
			return err
		}
		if raw.Version != "" {
			vers[raw.Scanner] = raw.Version
		}
	}
	vb, _ := json.MarshalIndent(vers, "", "  ")
	return os.WriteFile(filepath.Join(dir, "versions.json"), vb, 0o644)
}

func writeResult(r interface{}, outDir string) int {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		errln(err)
		return 2
	}
	path := filepath.Join(outDir, "scan-result.json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		errln(err)
		return 2
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		errln(err)
		return 2
	}
	fmt.Println(msg("scan.wrote", path))
	return 0
}
