package canonical

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// ── Хамрах хүрээний матриц ───────────────────────────────────────────────────
//
// Аудитын хэрэгслийн хамгийн чухал баримт нь "юу олсон" биш, "ЮУГ ОГТ ХАРААГҮЙ"
// вэ гэдэг. 33 control гэсэн тоо нь юу ч хэлэхгүй — тэдгээрийн аль нь бодит
// scanner rule-тай холбогдсон, аль нь нэрийн төдий байгааг хэрэглэгч мэдэх ёстой.
//
// Энэ тест registry-ээс docs/coverage.md-г үүсгэж, commit хийсэнтэй нь тулгана.
// Зураглал нэмэх/хасахад тест унаж, баримтыг шинэчлэхийг шаардана — ингэснээр
// матриц хэзээ ч хуучирахгүй, мөн зураглалгүй control нүдэнд эвгүй харагдсаар
// байж өөрөө засуулна.
//
// ШИНЭЧЛЭХ:  go test ./internal/canonical/ -run TestCoverageDoc -update

var updateCoverage = flag.Bool("update", false, "docs/coverage.md-г дахин үүсгэнэ")

const coveragePath = "../../docs/coverage.md"

var coverageScanners = []string{"trivy", "kubescape", "checkov", "popeye"}

func TestCoverageDoc(t *testing.T) {
	r, err := Load(regPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := renderCoverage(r)

	if *updateCoverage {
		if err := os.WriteFile(coveragePath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("шинэчлэгдэв: %s", coveragePath)
		return
	}
	want, err := os.ReadFile(coveragePath)
	if err != nil {
		t.Fatalf("уншиж чадсангүй: %v\nҮүсгэх: go test ./internal/canonical/ -run TestCoverageDoc -update", err)
	}
	if string(want) != got {
		t.Errorf("docs/coverage.md нь registry-тэй зөрж байна — зураглал өөрчлөгдсөн бол\n"+
			"баримтыг дагуулж шинэчилнэ:\n  go test ./internal/canonical/ -run TestCoverageDoc -update\n%s",
			coverageDiffHint(string(want), got))
	}
}

// coverageDiffHint — бүтэн файлыг хэвлэхгүй, зөрсөн эхний хэдэн мөрийг л заана.
func coverageDiffHint(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	n := 0
	for i := 0; i < len(w) || i < len(g); i++ {
		var lw, lg string
		if i < len(w) {
			lw = w[i]
		}
		if i < len(g) {
			lg = g[i]
		}
		if lw != lg {
			n++
			if n > 6 {
				fmt.Fprintf(&b, "\n  ... цаашид ч зөрүүтэй")
				break
			}
			fmt.Fprintf(&b, "\n  мөр %d:\n    баримт: %s\n    registry: %s", i+1, lw, lg)
		}
	}
	return b.String()
}

func renderCoverage(r *Registry) string {
	var b strings.Builder

	b.WriteString(`<!-- ҮҮСГЭСЭН ФАЙЛ — гараар засахгүй.
     Эх сурвалж: schema/canonical-controls.yaml
     Шинэчлэх:   go test ./internal/canonical/ -run TestCoverageDoc -update -->

# Control coverage

Which canonical controls TATAR-Kuber actually checks, and with which scanner rules.

A control with no rule mapped to it is **not checked** — it is a placeholder, and it
is listed here rather than hidden. Numbers are how many scanner rule IDs map to that
control, so a higher number is not "better": it means that scanner spells the same
issue several ways.

Энэ бол үүсгэсэн баримт: аль control бодитоор шалгагддаг, алийг нь огт шалгадаггүйг
ил гаргана. Rule зураглагдаагүй control нь **шалгагддаггүй** — нуулгүй энд гарна.

`)

	// ── Хураангуй ────────────────────────────────────────────────────────────
	var mapped, unmapped, heuristic int
	perScanner := map[string]int{}
	perScannerControls := map[string]int{}
	for _, c := range r.Controls {
		has := false
		for _, s := range coverageScanners {
			n := len(c.Mappings[s])
			perScanner[s] += n
			if n > 0 {
				perScannerControls[s]++
				has = true
			}
		}
		if has {
			mapped++
		} else {
			unmapped++
		}
		if c.Heuristic {
			heuristic++
		}
	}

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Controls in the registry | **%d** |\n", len(r.Controls))
	fmt.Fprintf(&b, "| Checked by at least one scanner | **%d** |\n", mapped)
	fmt.Fprintf(&b, "| **Not checked** (no rule mapped) | **%d** |\n", unmapped)
	fmt.Fprintf(&b, "| Heuristic (context-dependent, lower confidence) | %d |\n", heuristic)
	fmt.Fprintf(&b, "| Registry schema / last updated | %s / %s |\n\n", r.SchemaVersion, r.LastUpdated)

	fmt.Fprintf(&b, "| Scanner | Controls it can reach | Rule IDs mapped |\n|---|---:|---:|\n")
	for _, s := range coverageScanners {
		fmt.Fprintf(&b, "| %s | %d | %d |\n", s, perScannerControls[s], perScanner[s])
	}
	b.WriteString("\n")

	// ── Шалгагддаггүй control ────────────────────────────────────────────────
	if unmapped > 0 {
		b.WriteString("## Not checked\n\nThese controls exist in the registry but no scanner rule maps to them. " +
			"They are reported by no scan.\n\n")
		for _, c := range r.Controls {
			if coverageTotal(c) == 0 {
				fmt.Fprintf(&b, "- **%s** — %s\n", c.ID, c.Title.Get("en"))
			}
		}
		// Цоорхойг нэрлэх нь шударга, гэхдээ хаасан гэсэн үг биш. Энэ баримт
		// хаах замаа өөрөө заадаг байх ёстой — эс бөгөөс "шалгагддаггүй 1" нь
		// хэрэглэгчийн хувьд ямар ч үйлдэлгүй мэдэгдэл хэвээр үлдэнэ.
		b.WriteString("\nA control here is not a bug; it is a gap this project refuses to hide. " +
			"To close one, `tatar-kuber attest` records a human's signed decision — with a reason, " +
			"a name and a mandatory expiry — and merges it into the result. When that expiry lapses " +
			"the control counts as unchecked again and `gate` says so.\n")
		b.WriteString("\n")
	}

	// ── Ангилал тус бүрийн матриц ────────────────────────────────────────────
	b.WriteString("## Matrix\n\nEach cell is the number of scanner rule IDs mapped to that control.\n")

	for _, cat := range r.Categories {
		var rows []Control
		for _, c := range r.Controls {
			if c.Category == categoryName(r, cat.ID) {
				rows = append(rows, c)
			}
		}
		if len(rows) == 0 {
			continue
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

		fmt.Fprintf(&b, "\n### %s\n\n", cat.Name)
		b.WriteString("| Control | Title | Severity | Trivy | Kubescape | Checkov | Popeye |\n")
		b.WriteString("|---|---|---|---:|---:|---:|---:|\n")
		for _, c := range rows {
			title := c.Title.Get("en")
			if c.Heuristic {
				title += " *(heuristic)*"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
				c.ID, title, c.DefaultSeverity,
				coverageCell(c, "trivy"), coverageCell(c, "kubescape"),
				coverageCell(c, "checkov"), coverageCell(c, "popeye"))
		}
	}

	b.WriteString("\n---\n\nA scanner column being empty does not mean that scanner is broken — " +
		"most rules exist in one tool only. What matters is the **Not checked** section above, " +
		"and that every scanner listed as reachable actually produces findings in the daily " +
		"live run (`.github/workflows/real-cluster.yml`).\n")

	return b.String()
}

func coverageTotal(c Control) int {
	n := 0
	for _, s := range coverageScanners {
		n += len(c.Mappings[s])
	}
	return n
}

func coverageCell(c Control, scanner string) string {
	if n := len(c.Mappings[scanner]); n > 0 {
		return fmt.Sprintf("%d", n)
	}
	return "—"
}

// categoryName — categories[] дахь ID-гаас нэрийг олно (control.Category нь нэрээр
// бичигддэг).
func categoryName(r *Registry, id string) string {
	for _, c := range r.Categories {
		if c.ID == id {
			return c.Name
		}
	}
	return id
}
