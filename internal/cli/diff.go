package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/diff"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// diffLabels — хоёр хэлт шошго (тайлантай ижил зарчим: --lang en|mn).
type diffLabels struct {
	Header, Score, Findings, Changes, Scanners, Warnings string
	New, Fixed, Worsened, Improved, Unchanged            string
	NoChange, Identical, Regressed, FailNew, Legend      string
}

var diffMN = diffLabels{
	Header: "TATAR-Kuber diff", Score: "Эрсдэлийн оноо", Findings: "Finding",
	Changes: "Өөрчлөлт", Scanners: "Scanner хамрах хүрээ", Warnings: "Анхааруулга",
	New: "шинэ", Fixed: "зассан", Worsened: "дордсон", Improved: "сайжирсан", Unchanged: "хэвээр",
	NoChange: "Өөрчлөлт алга.", Identical: "result_hash ижил — өгөгдөл огт хөдөлсөнгүй.",
	Regressed: "ХАМРАХ ХҮРЭЭ БУУРСАН", FailNew: "шинэ finding нь босгоос өндөр",
	Legend: "+ шинэ  ↑ дордсон  − зассан  ↓ сайжирсан",
}

var diffEN = diffLabels{
	Header: "TATAR-Kuber diff", Score: "Risk score", Findings: "Findings",
	Changes: "Changes", Scanners: "Scanner coverage", Warnings: "Warnings",
	New: "new", Fixed: "fixed", Worsened: "worsened", Improved: "improved", Unchanged: "unchanged",
	NoChange: "No changes.", Identical: "identical result_hash — nothing moved.",
	Regressed: "COVERAGE REGRESSED", FailNew: "new finding at or above threshold",
	Legend: "+ new  ↑ worsened  − fixed  ↓ improved",
}

var changeMark = map[diff.Change]string{
	diff.ChangeNew: "+", diff.ChangeWorsened: "↑", diff.ChangeFixed: "−",
	diff.ChangeImproved: "↓", diff.ChangeUnchanged: " ",
}

// cmdDiff — хоёр scan-result.json-ыг тулгаж, юу өөрчлөгдсөнийг харуулна.
//
//	exit 0 — OK; exit 1 — --fail-on-new босго давсан; exit 2/3 — алдаа.
func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	oldPath := fs.String("old", "", "өмнөх scan-result.json (заавал)")
	newPath := fs.String("new", "", "шинэ scan-result.json (заавал)")
	format := fs.String("o", "text", "гаралт: text|json")
	lang := fs.String("lang", "mn", "хэл: mn|en")
	failOnNew := fs.String("fail-on-new", "", "шинэ finding энэ severity-с дээш байвал exit 1: critical|high|medium|low")
	all := fs.Bool("all", false, "өөрчлөгдөөгүй finding-үүдийг ч хэвлэх")
	_ = fs.Parse(args)

	if *oldPath == "" || *newPath == "" {
		fmt.Fprintln(os.Stderr, "алдаа: --old ба --new заавал")
		return 3
	}
	oldRes, code := loadScan(*oldPath)
	if code != 0 {
		return code
	}
	newRes, code := loadScan(*newPath)
	if code != 0 {
		return code
	}

	r := diff.Compare(oldRes, newRes)

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, "алдаа:", err)
			return 2
		}
	} else {
		printDiff(r, *lang, *all)
	}

	if *failOnNew != "" {
		threshold := finding.NormalizeSeverity(strings.ToUpper(*failOnNew))
		if finding.Rank(threshold) == 0 {
			fmt.Fprintf(os.Stderr, "анхаар: --fail-on-new='%s' танигдсангүй — хэрэгсэхгүй\n", *failOnNew)
			return 0
		}
		if maxNew := r.MaxNewSeverity(); finding.Rank(maxNew) >= finding.Rank(threshold) {
			fmt.Fprintf(os.Stderr, "\nFAIL: %s (%s >= %s)\n", labelsFor(*lang).FailNew, maxNew, threshold)
			return 1
		}
	}
	return 0
}

func labelsFor(lang string) diffLabels {
	if lang == "en" {
		return diffEN
	}
	return diffMN
}

func loadScan(path string) (finding.ScanResult, int) {
	var res finding.ScanResult
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return res, 2
	}
	if err := json.Unmarshal(b, &res); err != nil {
		fmt.Fprintf(os.Stderr, "алдаа: %s parse: %v\n", path, err)
		return res, 2
	}
	return res, 0
}

func printDiff(r diff.Result, lang string, all bool) {
	L := labelsFor(lang)
	fmt.Printf("%s — %s\n", L.Header, shortWhen(r.OldAt, r.NewAt))
	fmt.Println(strings.Repeat("─", 64))

	// Оноо ба нийт тоо.
	fmt.Printf("%-22s %6d → %-6d %s\n", L.Score, r.OldScore, r.NewScore, signed(r.ScoreDelta))
	fmt.Printf("%-22s %6d → %-6d %s\n", L.Findings, r.OldTotal, r.NewTotal, signed(r.NewTotal-r.OldTotal))

	// Severity тус бүрээр.
	fmt.Println()
	for _, s := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh,
		finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		o, n := r.CountsOld[s], r.CountsNew[s]
		if o == 0 && n == 0 {
			continue
		}
		fmt.Printf("  %-10s %6d → %-6d %s\n", s, o, n, signed(n-o))
	}

	// Өөрчлөлтийн хураангуй.
	fmt.Printf("\n%s: %s %d · %s %d · %s %d · %s %d · %s %d\n", L.Changes,
		L.New, r.Counts[diff.ChangeNew], L.Worsened, r.Counts[diff.ChangeWorsened],
		L.Fixed, r.Counts[diff.ChangeFixed], L.Improved, r.Counts[diff.ChangeImproved],
		L.Unchanged, r.Counts[diff.ChangeUnchanged])

	if r.SameResult {
		fmt.Printf("\n%s\n", L.Identical)
	}

	// Мөр бүрчлэн.
	shown := 0
	for _, it := range r.Items {
		if it.Change == diff.ChangeUnchanged && !all {
			continue
		}
		if shown == 0 {
			fmt.Printf("\n%s\n", L.Legend)
			fmt.Println(strings.Repeat("─", 64))
		}
		shown++
		sev := string(it.Severity)
		if it.OldSeverity != "" {
			sev = string(it.OldSeverity) + "→" + string(it.Severity)
		}
		ns := it.Namespace
		if ns != "" {
			ns = ns + "/"
		}
		fmt.Printf("%s %-11s %-16s %s%s\n", changeMark[it.Change], sev, it.CanonicalControl, ns, it.Resource)
	}
	if shown == 0 {
		fmt.Printf("\n%s\n", L.NoChange)
	}

	// Scanner хамрах хүрээ — тоо буурсан нь scanner унаснаас болсон эсэхийг харуулна.
	if len(r.Scanners) > 0 {
		fmt.Printf("\n%s\n", L.Scanners)
		fmt.Println(strings.Repeat("─", 64))
		for _, d := range r.Scanners {
			flag := ""
			if d.Regressed {
				flag = "  ← " + L.Regressed
			}
			// Тал нь огт ажиллаагүй бол тоог 0 гэж БИШ, "—" гэж харуулна:
			// 0 гэдэг нь "олдсонгүй", "—" нь "мэдэгдэхгүй".
			fmt.Printf("  %-12s %-12s → %-12s %5s → %-5s%s\n",
				d.Scanner, dashIf(d.OldStatus), dashIf(d.NewStatus),
				countOr(d.OldStatus, d.OldFindings), countOr(d.NewStatus, d.NewFindings), flag)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Printf("\n%s\n", L.Warnings)
		fmt.Println(strings.Repeat("─", 64))
		for _, w := range r.Warnings {
			fmt.Println("  ! " + w.Text(lang))
		}
	}
}

// countOr — төлөв байхгүй (scanner энэ scan-д огт бүртгэгдээгүй) бол тоо нь
// утгагүй тул "—".
func countOr(status string, n int) string {
	if status == "" {
		return "—"
	}
	return fmt.Sprintf("%d", n)
}

func dashIf(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func signed(n int) string {
	switch {
	case n > 0:
		return fmt.Sprintf("(+%d)", n)
	case n < 0:
		return fmt.Sprintf("(%d)", n)
	}
	return "(=)"
}

func shortWhen(oldAt, newAt string) string {
	o, n := oldAt, newAt
	if len(o) >= 10 {
		o = o[:10]
	}
	if len(n) >= 10 {
		n = n[:10]
	}
	if o == "" && n == "" {
		return "—"
	}
	return o + " → " + n
}
