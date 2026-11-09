// Package audit renders the print-ready, bilingual audit report.
//
// ЯАГААД ТУСДАА ФОРМАТ: `report --format html` нь ДЭЛГЭЦИЙН самбар —
// шүүлтүүр, задардаг хэсэг, интерактив. Аудиторын үйлчлүүлэгчдээ өгдөг зүйл
// бол өөр баримт: хамрах хүрээ, арга зүй, юу ШАЛГААГҮЙ, оноо хэрхэн гарсан,
// гараар баталсан хяналтууд — хэвлэгдэхэд дэс дараатай, хуудаслагдсан байх
// ёстой. Самбарыг PDF рүү шахах нь хоёуланг нь муутгана.
//
// ЭНЭ ФАЙЛ PDF ҮҮСГЭДЭГГҮЙ. Хуудаслалтад бэлэн HTML гаргана; PDF рүү
// хөрвүүлэх нь CLI давхаргын ажил бөгөөд тэнд хөрвүүлэгч байхгүй бол ИЛ
// татгалздаг (чимээгүй хоосон файл гаргахгүй).
package audit

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// group — нэг canonical хяналтын доорх олдворууд.
type group struct {
	Control     string
	Title       string
	Description string
	Remediation string
	Severity    finding.Severity
	Confidence  finding.Confidence
	Reason      string
	FoundBy     []string
	Attack      []finding.AttackTechnique
	References  []string
	Rows        []row
}

type row struct {
	Resource   string
	Namespace  string
	Severity   finding.Severity
	BlindShot  bool
	BSReason   string
	Evidence   []string
	Contribute float64
}

type runRow struct {
	Scanner, Status, Version, Duration string
	Findings, Unmapped                 int
	Bad                                bool // анхаарал татах төлөв
}

type view struct {
	L        labels
	Lang     string
	Res      finding.ScanResult
	Runs     []runRow
	Groups   []group
	Counts   []countRow
	HasRuns  bool
	HasAtt   bool
	ExpiredN int
}

type countRow struct {
	Severity finding.Severity
	N        int
}

var funcs = template.FuncMap{
	"join": func(s []string) string { return strings.Join(s, ", ") },
	"pct":  func(f float64) string { return fmt.Sprintf("%.0f%%", f) },
	"num":  func(f float64) string { return fmt.Sprintf("%.1f", f) },
}

var tmpl = template.Must(template.New("audit").Funcs(funcs).Parse(doc))

// Render — аудитын тайланг бичнэ. lang нь "" бол үр дүнгийн metadata.lang,
// тэр ч байхгүй бол англи.
func Render(w io.Writer, res finding.ScanResult, lang string) error {
	if lang == "" {
		lang = res.Metadata.Lang
	}
	if lang == "" {
		lang = "en"
	}
	l := pick(lang)

	v := view{L: l, Lang: lang, Res: res}

	// Scanner-ийн бүртгэл: "юу ажиллаагүй" нь ил харагдах ёстой (§6).
	for _, r := range res.Metadata.ScannerRuns {
		st := l.Statuses[r.Status]
		if st == "" {
			st = r.Status
		}
		dur := ""
		if r.DurationMS > 0 {
			dur = fmt.Sprintf("%.1fs", float64(r.DurationMS)/1000)
		}
		v.Runs = append(v.Runs, runRow{
			Scanner: r.Scanner, Status: st, Version: r.Version, Duration: dur,
			Findings: r.Findings, Unmapped: r.UnmappedCount,
			Bad: r.Status != "ok" && r.Status != "ingested",
		})
	}
	v.HasRuns = len(v.Runs) > 0

	for _, a := range res.Attestations {
		if a.Status == finding.AttestExpired {
			v.ExpiredN++
		}
	}
	v.HasAtt = len(res.Attestations) > 0

	for _, s := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh,
		finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		if n := res.Summary.Counts[s]; n > 0 {
			v.Counts = append(v.Counts, countRow{s, n})
		}
	}

	v.Groups = groupFindings(res.Findings, l)
	return tmpl.Execute(w, v)
}

// groupFindings — олдворуудыг canonical хяналтаар бүлэглэж, хяналт дотор нь
// ноцтой байдал, дараа нь нэрээр эрэмбэлнэ. Эрэмбэ ДЕТЕРМИНИСТИК (§3):
// ижил оролт ижил баримт өгөх ёстой, эс бөгөөс хоёр тайланг тулгах утгагүй.
func groupFindings(fs []finding.Finding, l labels) []group {
	idx := map[string]*group{}
	var order []string
	for _, f := range fs {
		g, ok := idx[f.CanonicalControl]
		if !ok {
			reason := l.Reasons[string(f.ConfidenceReason)]
			if reason == "" {
				reason = string(f.ConfidenceReason)
			}
			g = &group{
				Control: f.CanonicalControl, Title: f.Title, Description: f.Description,
				Remediation: f.Remediation, Severity: f.Severity, Confidence: f.Confidence,
				Reason: reason, Attack: f.Attack, References: f.References,
			}
			idx[f.CanonicalControl] = g
			order = append(order, f.CanonicalControl)
		}
		if finding.Rank(f.Severity) > finding.Rank(g.Severity) {
			g.Severity = f.Severity
		}
		for _, s := range f.FoundBy {
			if !contains(g.FoundBy, s) {
				g.FoundBy = append(g.FoundBy, s)
			}
		}
		var ev []string
		for _, e := range f.Evidence {
			if e.Path != "" {
				ev = append(ev, e.Path)
			}
		}
		g.Rows = append(g.Rows, row{
			Resource: f.Resource, Namespace: f.Namespace, Severity: f.Severity,
			BlindShot: f.BlindShot, BSReason: f.BlindShotReason, Evidence: ev,
			Contribute: f.RiskContribution,
		})
	}

	out := make([]group, 0, len(order))
	for _, k := range order {
		g := idx[k]
		sort.Strings(g.FoundBy)
		sort.SliceStable(g.Rows, func(i, j int) bool {
			if a, b := finding.Rank(g.Rows[i].Severity), finding.Rank(g.Rows[j].Severity); a != b {
				return a > b
			}
			if g.Rows[i].Namespace != g.Rows[j].Namespace {
				return g.Rows[i].Namespace < g.Rows[j].Namespace
			}
			return g.Rows[i].Resource < g.Rows[j].Resource
		})
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := finding.Rank(out[i].Severity), finding.Rank(out[j].Severity); a != b {
			return a > b
		}
		return out[i].Control < out[j].Control
	})
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
