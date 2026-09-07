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
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	file := fs.String("f", "", "local manifest/Helm зам (Mode A)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig файл (Mode B)")
	context_ := fs.String("context", "", "kubeconfig context (Mode B)")
	namespaces := fs.String("namespace", "", "хязгаарлах namespace-ууд (таслалаар, Mode B)")
	rawDir := fs.String("raw-dir", "", "цуглуулсан scanner raw JSON-уудын хавтас (offline ingest)")
	cluster := fs.String("cluster", "cluster", "cluster/target нэр (тайланд)")
	outDir := fs.String("o", ".", "гаралтын хавтас")
	registry := fs.String("registry", "", "canonical-controls.yaml зам")
	lang := fs.String("lang", "en", "тайлангийн хэл: en | mn")
	noRaw := fs.Bool("no-raw", false, "live scan-д scanner-уудын түүхий гаралтыг <out>/raw/ дотор ХАДГАЛАХГҮЙ (default: хадгална — нотолгоо)")
	_ = fs.Parse(args)

	regPath, err := resolveRegistry(*registry)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 3
	}
	p, err := buildPipeline(regPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}

	mode := "remote"
	if *file != "" {
		mode = "local"
	}

	if *rawDir != "" {
		// Offline ingest: цуглуулсан raw-г нэгтгэнэ.
		raws, inv, err := loadRawDir(*rawDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "алдаа:", err)
			return 2
		}
		r, err := p.Process(raws, orchestrator.Meta{ClusterName: *cluster, ScanMode: mode, Lang: *lang, Inventory: inv})
		if err != nil {
			fmt.Fprintln(os.Stderr, "алдаа:", err)
			return 2
		}
		warnRuns(r.Metadata.ScannerRuns)
		return writeResult(r, *outDir)
	}

	// Live scan: adapter-уудыг ажиллуулна (scanner binary шаардлагатай).
	if *file == "" && *kubeconfig == "" && *context_ == "" {
		fmt.Fprintln(os.Stderr, "scan: -f, --kubeconfig/--context эсвэл --raw-dir шаардлагатай")
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
			fmt.Fprintln(os.Stderr, "анхаар: raw хадгалж чадсангүй:", err)
		}
	}

	r, err := p.Process(raws, orchestrator.Meta{ClusterName: *cluster, ScanMode: mode, Lang: *lang, Runs: runs})
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	warnRuns(r.Metadata.ScannerRuns)
	if len(raws) == 0 {
		fmt.Fprintln(os.Stderr, "анхаар: ямар ч scanner ажиллаагүй (scanner binary суулгасан эсэхээ `tatar-kuber doctor`-оор шалгана уу). Offline горим: --raw-dir")
	}
	return writeResult(r, *outDir)
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
	for _, msg := range orchestrator.Problems(runs) {
		fmt.Fprintln(os.Stderr, "анхаар:", msg)
	}
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
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	path := filepath.Join(outDir, "scan-result.json")
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}
	fmt.Println("scan-result.json бичигдлээ:", path)
	return 0
}
