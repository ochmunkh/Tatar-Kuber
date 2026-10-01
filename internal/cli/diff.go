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

// Шошгууд нь бусад бүх CLI бичвэрийн хамт messages.go-ийн каталогт ("diff.*")
// байдаг: хоёр хэлийг зэрэгцээ хоёр газар барих нь тэднийг чимээгүй зөрүүлдэг.

var changeMark = map[diff.Change]string{
	diff.ChangeNew: "+", diff.ChangeWorsened: "↑", diff.ChangeFixed: "−",
	diff.ChangeImproved: "↓", diff.ChangeUnchanged: " ",
}

// cmdDiff — хоёр scan-result.json-ыг тулгаж, юу өөрчлөгдсөнийг харуулна.
//
//	exit 0 — OK; exit 1 — --fail-on-new босго давсан; exit 2/3 — алдаа.
func cmdDiff(args []string) int {
	if _, code := setLang(args); code != 0 {
		return code
	}
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	oldPath := fs.String("old", "", msg("flag.diff.old"))
	newPath := fs.String("new", "", msg("flag.diff.new"))
	format := fs.String("o", "text", msg("flag.diff.format"))
	fs.StringVar(format, "format", "text", msg("flag.diff.format.long"))
	addLangFlag(fs, "flag.lang")
	failOnNew := fs.String("fail-on-new", "", msg("flag.diff.failonnew"))
	all := fs.Bool("all", false, msg("flag.diff.all"))
	_ = fs.Parse(args)

	if *oldPath == "" || *newPath == "" {
		errln(msg("diff.old.new.required"))
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
			errln(err)
			return 2
		}
	} else {
		printDiff(r, *all)
	}

	if *failOnNew != "" {
		threshold, ok := parseSeverityThreshold(*failOnNew, "--fail-on-new")
		if !ok {
			return 0
		}
		if maxNew := r.MaxNewSeverity(); finding.Rank(maxNew) >= finding.Rank(threshold) {
			fmt.Fprintf(os.Stderr, "\nFAIL: %s (%s >= %s)\n", msg("diff.failnew"), maxNew, threshold)
			return 1
		}
	}
	return 0
}

func loadScan(path string) (finding.ScanResult, int) {
	var res finding.ScanResult
	b, err := os.ReadFile(path)
	if err != nil {
		errln(err)
		return res, 2
	}
	if err := json.Unmarshal(b, &res); err != nil {
		errln(msg("diff.parse", path, err))
		return res, 2
	}
	return res, 0
}

func printDiff(r diff.Result, all bool) {
	fmt.Printf("%s — %s\n", msg("diff.header"), shortWhen(r.OldAt, r.NewAt))
	fmt.Println(strings.Repeat("─", 64))

	// Оноо ба нийт тоо.
	fmt.Printf("%-22s %6d → %-6d %s\n", msg("diff.score"), r.OldScore, r.NewScore, signed(r.ScoreDelta))
	fmt.Printf("%-22s %6d → %-6d %s\n", msg("diff.findings"), r.OldTotal, r.NewTotal, signed(r.NewTotal-r.OldTotal))

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
	fmt.Printf("\n%s: %s %d · %s %d · %s %d · %s %d · %s %d\n", msg("diff.changes"),
		msg("diff.new"), r.Counts[diff.ChangeNew], msg("diff.worsened"), r.Counts[diff.ChangeWorsened],
		msg("diff.fixed"), r.Counts[diff.ChangeFixed], msg("diff.improved"), r.Counts[diff.ChangeImproved],
		msg("diff.unchanged"), r.Counts[diff.ChangeUnchanged])

	if r.SameResult {
		fmt.Printf("\n%s\n", msg("diff.identical"))
	}

	// Мөр бүрчлэн.
	shown := 0
	for _, it := range r.Items {
		if it.Change == diff.ChangeUnchanged && !all {
			continue
		}
		if shown == 0 {
			fmt.Printf("\n%s\n", msg("diff.legend"))
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
		fmt.Printf("\n%s\n", msg("diff.nochange"))
	}

	// Scanner хамрах хүрээ — тоо буурсан нь scanner унаснаас болсон эсэхийг харуулна.
	if len(r.Scanners) > 0 {
		fmt.Printf("\n%s\n", msg("diff.scanners"))
		fmt.Println(strings.Repeat("─", 64))
		for _, d := range r.Scanners {
			flag := ""
			if d.Regressed {
				flag = "  ← " + msg("diff.regressed")
			}
			// Тал нь огт ажиллаагүй бол тоог 0 гэж БИШ, "—" гэж харуулна:
			// 0 гэдэг нь "олдсонгүй", "—" нь "мэдэгдэхгүй".
			fmt.Printf("  %-12s %-12s → %-12s %5s → %-5s%s\n",
				d.Scanner, dashIf(d.OldStatus), dashIf(d.NewStatus),
				countOr(d.OldStatus, d.OldFindings), countOr(d.NewStatus, d.NewFindings), flag)
		}
	}

	if len(r.Warnings) > 0 {
		fmt.Printf("\n%s\n", msg("diff.warnings"))
		fmt.Println(strings.Repeat("─", 64))
		for _, w := range r.Warnings {
			fmt.Println("  ! " + w.Text(uiLang))
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
