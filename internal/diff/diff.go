// Package diff — хоёр scan-result.json-ыг тулгаж, хооронд нь юу өөрчлөгдсөнийг
// гаргана: шинэ / зассан / дордсон / сайжирсан / хэвээр.
//
// ЯАГААД ХЭРЭГТЭЙ. Аудитыг нэг удаа хийгээд орхидоггүй — засварын дараа дахин
// шалгадаг. Тэр үед "нийт 26 finding" гэсэн тоо юу ч хэлэхгүй: 26 нь хуучин
// 26 мөн үү, эсвэл 20 зассан дээр 20 шинэ гарсан уу гэдэг нь тэс өөр дүр зураг.
//
// ТУЛГАХ ТҮЛХҮҮР. finding.ID нь StableID(canonical_control, resource, namespace)
// тул scan хооронд тогтвортой: severity, confidence, нотолгоо өөрчлөгдсөн ч ID
// хэвээр үлдэнэ. Тиймээс ID-гаар тулгавал "ижил асуудал дордов" гэдгийг
// "хуучин нь арилж, шинэ нь гарав" гэхээс ялгаж чадна.
//
// ХИЙЖ БОЛОХГҮЙ ХАРЬЦУУЛАЛТ. Түлхүүрт resource багтдаг тул дараах тохиолдолд
// ID бөөнөөрөө өөрчлөгдөж, diff утгагүй болно — эдгээрийг сэрэмжлүүлгээр хэлнэ:
//   - нэг scan rollup-тай, нөгөө нь --no-rollup (pod/x -> deployment/x болно)
//   - өөр cluster, эсвэл өөр горим (Mode A vs Mode B)
//
// SCANNER-ИЙН ЗӨРҮҮ. Тоо буурсан нь үргэлж сайн мэдээ биш: scanner унасан ч
// тоо буурна. Тиймээс metadata.scanner_runs-ыг мөн тулгаж, "өмнө finding өгч
// байсан scanner одоо 0 өгсөн" тохиолдлыг ТУСАД нь анхааруулна.
package diff

import (
	"sort"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Change — нэг finding-ийн scan хоорондын төлөв.
type Change string

const (
	ChangeNew       Change = "new"       // зөвхөн шинэ scan-д
	ChangeFixed     Change = "fixed"     // зөвхөн хуучин scan-д
	ChangeWorsened  Change = "worsened"  // хоёуланд, severity өссөн
	ChangeImproved  Change = "improved"  // хоёуланд, severity буурсан
	ChangeUnchanged Change = "unchanged" // хоёуланд, severity ижил
)

// Item — нэг finding-ийн өөрчлөлт.
type Item struct {
	Change           Change           `json:"change"`
	ID               string           `json:"id"`
	CanonicalControl string           `json:"canonical_control"`
	Resource         string           `json:"resource"`
	Namespace        string           `json:"namespace,omitempty"`
	Title            string           `json:"title"`
	Severity         finding.Severity `json:"severity"`               // шинэ төлөв (fixed бол хуучных)
	OldSeverity      finding.Severity `json:"old_severity,omitempty"` // зөвхөн worsened / improved
	FoundBy          []string         `json:"found_by,omitempty"`
	RiskDelta        float64          `json:"risk_delta,omitempty"` // risk_contribution-ийн зөрүү
}

// ScannerDelta — нэг scanner-ийн хоёр scan дахь явцын зөрүү.
type ScannerDelta struct {
	Scanner     string `json:"scanner"`
	OldStatus   string `json:"old_status,omitempty"`
	NewStatus   string `json:"new_status,omitempty"`
	OldFindings int    `json:"old_findings"`
	NewFindings int    `json:"new_findings"`
	// Regressed — өмнө finding өгч байсан scanner одоо юу ч өгөөгүй, эсвэл
	// төлөв нь ok-оос гарсан. Энэ нь "цэвэрлэгдсэн" биш, "хамрах хүрээ буурсан".
	Regressed bool `json:"regressed"`
}

// Result — тулгалтын бүрэн үр дүн.
type Result struct {
	OldScanID  string `json:"old_scan_id,omitempty"`
	NewScanID  string `json:"new_scan_id,omitempty"`
	OldAt      string `json:"old_finished_at,omitempty"`
	NewAt      string `json:"new_finished_at,omitempty"`
	SameResult bool   `json:"same_result_hash"` // result_hash ижил — өгөгдөл огт хөдөлсөнгүй

	OldScore   int `json:"old_score"`
	NewScore   int `json:"new_score"`
	ScoreDelta int `json:"score_delta"` // new - old (эерэг = сайжирсан)

	OldTotal int `json:"old_total"`
	NewTotal int `json:"new_total"`

	CountsOld map[finding.Severity]int `json:"counts_old"`
	CountsNew map[finding.Severity]int `json:"counts_new"`

	Counts map[Change]int `json:"counts"` // change тус бүрийн тоо
	Items  []Item         `json:"items"`

	Scanners []ScannerDelta `json:"scanners,omitempty"`

	// Warnings — харьцуулалтыг үнэмшилгүй болгож болзошгүй нөхцөлүүд.
	Warnings []string `json:"warnings,omitempty"`
}

// severities — тайланд гардаг эрэмбэ (өндрөөс нам руу).
var severities = []finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
	finding.SeverityLow, finding.SeverityInfo,
}

func index(fs []finding.Finding) map[string]finding.Finding {
	m := make(map[string]finding.Finding, len(fs))
	for _, f := range fs {
		if _, dup := m[f.ID]; dup {
			continue // dedup-ийн дараа давхардах ёсгүй; давхарлавал эхнийхийг авна
		}
		m[f.ID] = f
	}
	return m
}

func counts(fs []finding.Finding) map[finding.Severity]int {
	c := map[finding.Severity]int{}
	for _, s := range severities {
		c[s] = 0
	}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}

// Compare — old -> new чиглэлд тулгана.
func Compare(old, nw finding.ScanResult) Result {
	oi, ni := index(old.Findings), index(nw.Findings)

	r := Result{
		OldScanID:  old.Metadata.ScanID,
		NewScanID:  nw.Metadata.ScanID,
		OldAt:      old.Metadata.FinishedAt,
		NewAt:      nw.Metadata.FinishedAt,
		SameResult: old.Metadata.ResultHash != "" && old.Metadata.ResultHash == nw.Metadata.ResultHash,
		OldScore:   old.Summary.RiskScore,
		NewScore:   nw.Summary.RiskScore,
		ScoreDelta: nw.Summary.RiskScore - old.Summary.RiskScore,
		OldTotal:   len(old.Findings),
		NewTotal:   len(nw.Findings),
		CountsOld:  counts(old.Findings),
		CountsNew:  counts(nw.Findings),
		Counts:     map[Change]int{},
	}

	for id, nf := range ni {
		of, ok := oi[id]
		if !ok {
			r.Items = append(r.Items, item(ChangeNew, nf, "", nf.RiskContribution))
			continue
		}
		on, nn := finding.Rank(of.Severity), finding.Rank(nf.Severity)
		switch {
		case nn > on:
			r.Items = append(r.Items, item(ChangeWorsened, nf, of.Severity, nf.RiskContribution-of.RiskContribution))
		case nn < on:
			r.Items = append(r.Items, item(ChangeImproved, nf, of.Severity, nf.RiskContribution-of.RiskContribution))
		default:
			r.Items = append(r.Items, item(ChangeUnchanged, nf, "", nf.RiskContribution-of.RiskContribution))
		}
	}
	for id, of := range oi {
		if _, ok := ni[id]; !ok {
			r.Items = append(r.Items, item(ChangeFixed, of, "", -of.RiskContribution))
		}
	}

	for _, it := range r.Items {
		r.Counts[it.Change]++
	}
	sortItems(r.Items)

	r.Scanners = compareScanners(old.Metadata.ScannerRuns, nw.Metadata.ScannerRuns)
	r.Warnings = warnings(old, nw, r.Scanners)
	return r
}

func item(c Change, f finding.Finding, oldSev finding.Severity, delta float64) Item {
	return Item{
		Change: c, ID: f.ID, CanonicalControl: f.CanonicalControl,
		Resource: f.Resource, Namespace: f.Namespace, Title: f.Title,
		Severity: f.Severity, OldSeverity: oldSev, FoundBy: f.FoundBy,
		RiskDelta: round2(delta),
	}
}

func round2(v float64) float64 {
	return float64(int64(v*100+sign(v)*0.5)) / 100
}
func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}

// changeOrder — гаралтын эрэмбэ: анхаарал татах ёстой нь эхэнд.
var changeOrder = map[Change]int{
	ChangeNew: 0, ChangeWorsened: 1, ChangeFixed: 2, ChangeImproved: 3, ChangeUnchanged: 4,
}

func sortItems(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if changeOrder[a.Change] != changeOrder[b.Change] {
			return changeOrder[a.Change] < changeOrder[b.Change]
		}
		if ra, rb := finding.Rank(a.Severity), finding.Rank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.CanonicalControl != b.CanonicalControl {
			return a.CanonicalControl < b.CanonicalControl
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.ID < b.ID
	})
}

func compareScanners(oldRuns, newRuns []finding.ScannerRun) []ScannerDelta {
	if len(oldRuns) == 0 && len(newRuns) == 0 {
		return nil
	}
	om := map[string]finding.ScannerRun{}
	for _, r := range oldRuns {
		om[r.Scanner] = r
	}
	nm := map[string]finding.ScannerRun{}
	for _, r := range newRuns {
		nm[r.Scanner] = r
	}
	names := map[string]bool{}
	for k := range om {
		names[k] = true
	}
	for k := range nm {
		names[k] = true
	}
	var out []ScannerDelta
	for name := range names {
		o, oOK := om[name]
		n, nOK := nm[name]
		d := ScannerDelta{Scanner: name}
		if oOK {
			d.OldStatus, d.OldFindings = o.Status, o.Findings
		}
		if nOK {
			d.NewStatus, d.NewFindings = n.Status, n.Findings
		}
		// Хамрах хүрээ буурсан гэж үзэх нөхцөл: өмнө finding өгч байсан scanner
		// одоо юу ч өгөөгүй, эсвэл өмнө ok байсан нь ok-оос гарсан, эсвэл огт алга.
		switch {
		case oOK && !nOK && o.Findings > 0:
			d.Regressed = true
		case oOK && nOK && o.Findings > 0 && n.Findings == 0:
			d.Regressed = true
		case oOK && nOK && o.Status == "ok" && n.Status != "ok" && n.Status != "ingested":
			d.Regressed = true
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Regressed != out[j].Regressed {
			return out[i].Regressed // унасан нь эхэнд
		}
		return out[i].Scanner < out[j].Scanner
	})
	return out
}

func warnings(old, nw finding.ScanResult, sd []ScannerDelta) []string {
	var w []string
	if a, b := old.Metadata.ClusterName, nw.Metadata.ClusterName; a != "" && b != "" && a != b {
		w = append(w, "өөр cluster харьцуулж байна: "+a+" -> "+b)
	}
	if a, b := old.Metadata.ScanMode, nw.Metadata.ScanMode; a != "" && b != "" && a != b {
		w = append(w, "өөр горим харьцуулж байна: "+a+" -> "+b+" (Mode A ба Mode B-ийн объектын нэр өөр)")
	}
	// rollup зөрөх нь resource-ийг өөрчилдөг тул ID бөөнөөрөө солигдоно.
	oR, nR := old.Metadata.Rollup != nil, nw.Metadata.Rollup != nil
	if oR != nR {
		w = append(w, "нэг scan Pod->controller rollup-тай, нөгөө нь үгүй — объектын нэр өөр тул diff үнэмшилгүй (--no-rollup-ыг хоёуланд ижил өг)")
	}
	if a, b := old.SchemaVersion, nw.SchemaVersion; a != "" && b != "" && a != b {
		w = append(w, "схемийн хувилбар өөр: "+a+" -> "+b)
	}
	if a, b := old.Metadata.TatarVersion, nw.Metadata.TatarVersion; a != "" && b != "" && a != b {
		w = append(w, "TATAR-Kuber хувилбар өөр: "+a+" -> "+b+" (зураглал өөрчлөгдсөн бол finding шилжсэн байж болно)")
	}
	for _, d := range sd {
		if !d.Regressed {
			continue
		}
		switch {
		case d.NewStatus == "":
			w = append(w, "scanner '"+d.Scanner+"' энэ удаа огт ажиллаагүй (өмнө нь "+itoa(d.OldFindings)+" finding өгсөн) — тоо буурсан нь цэвэрлэгдсэний шинж БИШ")
		case d.NewFindings == 0 && d.OldFindings > 0:
			w = append(w, "scanner '"+d.Scanner+"' одоо 0 finding өгөв (өмнө "+itoa(d.OldFindings)+", төлөв "+d.NewStatus+") — хамрах хүрээ буурсан байж магадгүй")
		default:
			w = append(w, "scanner '"+d.Scanner+"' төлөв "+d.OldStatus+" -> "+d.NewStatus)
		}
	}
	return w
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// MaxNewSeverity — шинээр гарсан finding-үүдийн хамгийн өндөр severity.
// CI gate-д (--fail-on-new) ашиглана. Шинэ finding байхгүй бол "".
func (r Result) MaxNewSeverity() finding.Severity {
	best := finding.Severity("")
	for _, it := range r.Items {
		if it.Change != ChangeNew {
			continue
		}
		if finding.Rank(it.Severity) > finding.Rank(best) {
			best = it.Severity
		}
	}
	return best
}

// Regressions — хамрах хүрээ буурсан scanner-ууд.
func (r Result) Regressions() []ScannerDelta {
	var out []ScannerDelta
	for _, d := range r.Scanners {
		if d.Regressed {
			out = append(out, d)
		}
	}
	return out
}
