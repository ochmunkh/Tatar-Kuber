// Package policy implements the TATAR-Kuber CI/CD gatekeeper: a .tatar-kuber.yaml
// бодлого унших, suppression хэрэглэх, severity босго / cluster score-оор
// pass/fail шийдэх. Pipeline энэ шийдвэрийг exit code болгон CI-д дамжуулна.
package policy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"gopkg.in/yaml.v3"
)

// Suppression — тодорхой олдворыг (accepted risk) gate-ээс хасах дүрэм.
type Suppression struct {
	Control   string `yaml:"control"`             // TATAR-* (заавал)
	Resource  string `yaml:"resource,omitempty"`  // ж: deployment/api (сонголт)
	Namespace string `yaml:"namespace,omitempty"` // сонголт
	Reason    string `yaml:"reason"`              // яагаад (аудитын мөр)
	Expires   string `yaml:"expires,omitempty"`   // YYYY-MM-DD; хугацаа дуусвал suppress болихгүй
}

// Policy — .tatar-kuber.yaml.
type Policy struct {
	FailOn   string        `yaml:"fail_on"`             // critical|high|medium|low (default: high)
	MinScore int           `yaml:"min_score,omitempty"` // cluster score үүнээс доош бол унана (0 = хэрэгсэхгүй)
	Suppress []Suppression `yaml:"suppress,omitempty"`
}

// Default — бодлогын файл байхгүй үеийн үндсэн утга (high болон дээш унана).
func Default() Policy { return Policy{FailOn: "high"} }

// Load — .tatar-kuber.yaml-ыг уншина. Файл байхгүй бол Default-ыг буцаана
// (алдаа биш — бодлогогүй ажиллаж болно).
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return Policy{}, err
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("policy parse (%s): %w", path, err)
	}
	if p.FailOn == "" {
		p.FailOn = "high"
	}
	return p, nil
}

// normalizedFailOn — fail_on-ыг ТОМ/жижиг үсгээс үл хамааран severity болгоно
// ("low", "Low", "LOW", бүр "LoW" ч ижил). Танигдахгүй бол "" буцаана.
//
// Энэ бол босгыг уншдаг ЦОР ЗӨВХӨН цэг: ValidFailOn() ба threshold() хоёул
// үүгээр дамжина, тул "танигдсан" гэж мэдэгдээд өөр босго хэрэглэх зөрөө
// үүсэх боломжгүй. Өмнө нь хоёулаа тус тусдаа яг таарах жижиг/ТОМ бичиглэлийг
// л зөвшөөрдөг байсан: `fail_on: Low` танигдахгүй → чимээгүйгээр `high` болж,
// LOW ба MEDIUM олдвор gate-ийг унагахаа болино. Босго СУЛРУУЛАХ тал руу
// чимээгүй өөрчлөгдөх нь энэ хэрэгслийн хамгийн эсэргүүцэх зан.
//
// INFO-г ЗӨРИУД хүлээж авахгүй: баримтжуулсан олонлог нь critical|high|medium|low
// (README, --fail-on флагийн тайлбар, action.yml) — түүнээс өргөтгөх нь өөр асуудал.
func normalizedFailOn(raw string) finding.Severity {
	switch s := finding.NormalizeSeverity(strings.ToUpper(raw)); s {
	case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow:
		return s
	}
	return ""
}

// ValidFailOn — fail_on утга танигдах эсэх (танигдахгүй бол threshold high-г ашиглана,
// CLI анхааруулга хэвлэнэ — чимээгүй default руу унахгүй).
func (p Policy) ValidFailOn() bool { return normalizedFailOn(p.FailOn) != "" }

// threshold — fail_on severity-ийн rank (танигдахгүй бол high).
func (p Policy) threshold() int {
	if s := normalizedFailOn(p.FailOn); s != "" {
		return finding.Rank(s)
	}
	return finding.Rank(finding.SeverityHigh)
}

// matches — suppression тухайн finding-д тохирч байгаа эсэх.
func (s Suppression) matches(f finding.Finding) bool {
	if s.Control != f.CanonicalControl {
		return false
	}
	if s.Resource != "" && s.Resource != f.Resource {
		return false
	}
	if s.Namespace != "" && s.Namespace != f.Namespace {
		return false
	}
	return true
}

// expired — expires өнгөрсөн эсэх (today-оос хатуу бага).
func (s Suppression) expired(now time.Time) bool {
	if s.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", s.Expires)
	if err != nil {
		return false // буруу формат — хугацаагүй гэж үзнэ (warn нь Evaluate дотор)
	}
	return now.After(t.Add(24 * time.Hour)) // тухайн өдрийг оруулж тооцно
}

// UnknownControls — canonical registry-д БАЙХГҮЙ control руу заасан suppression-ууд.
// Бичиглэлийн алдаатай дүрэм нь хэзээ ч тохирохгүй тул "хүлээн зөвшөөрсөн
// эрсдэл" гэж бүртгэсэн зүйл бодитоор хамгаалагдаагүй байхад анзаарагдахгүй.
// Registry нь policy пакетад хамаарахгүй тул known-ыг гаднаас (CLI) дамжуулна.
func (p Policy) UnknownControls(known map[string]bool) []Suppression {
	if len(known) == 0 {
		return nil
	}
	var out []Suppression
	for _, s := range p.Suppress {
		if s.Control != "" && !known[s.Control] {
			out = append(out, s)
		}
	}
	return out
}

// Result — gate-ийн шийдвэр.
type Result struct {
	Passed        bool
	FailOn        string
	Threshold     int
	Violations    []finding.Finding // босго давсан, suppress хийгдээгүй олдворууд
	Suppressed    []finding.Finding // suppress хийгдсэн олдворууд
	ExpiredRules  []Suppression     // хугацаа дууссан suppression (анхааруулга)
	InvalidRules  []Suppression     // буруу форматтай expires
	UnusedRules   []Suppression     // ямар ч finding-д тохироогүй (хуучирсан дүрэм — аудитын эрсдэл)
	UnknownRules  []Suppression     // canonical registry-д байхгүй control руу заасан
	Score         int
	MinScore      int
	ScoreViolated bool

	// Reasons — gate унасан шалтгаануудын ТОГТМОЛ КОД (бичвэр биш).
	// CLI нь `--lang`-аар сонгогдсон хэл дээр хэвлэдэг тул шалтгааны бичвэр
	// нэг л газар — CLI-ийн мессежийн каталогт — амьдрах ёстой. Кодод хэрэгтэй
	// тоонууд (Violations, FailOn, Score, MinScore) энэ бүтцэд аль хэдийн бий.
	Reasons []string
}

// Result.Reasons-д гарах кодууд.
const (
	ReasonThreshold = "threshold" // босго давсан олдвор бий
	ReasonMinScore  = "min_score" // cluster score шаардсанаас доогуур
)

// Evaluate — scan үр дүнг бодлоготой тулгаж pass/fail шийднэ.
func (p Policy) Evaluate(res finding.ScanResult, now time.Time) Result {
	out := Result{Passed: true, FailOn: p.FailOn, Threshold: p.threshold(), Score: res.Summary.RiskScore, MinScore: p.MinScore}

	// Идэвхтэй (хугацаа дуусаагүй) suppression-ууд.
	var active []Suppression
	for _, s := range p.Suppress {
		if s.Expires != "" {
			if _, err := time.Parse("2006-01-02", s.Expires); err != nil {
				out.InvalidRules = append(out.InvalidRules, s)
			}
		}
		if s.expired(now) {
			out.ExpiredRules = append(out.ExpiredRules, s)
			continue // хугацаа дууссан — suppress болихгүй
		}
		active = append(active, s)
	}

	used := make([]bool, len(active))
	for _, f := range res.Findings {
		suppressed := false
		for i, s := range active {
			if s.matches(f) {
				suppressed = true
				used[i] = true
				break
			}
		}
		if suppressed {
			out.Suppressed = append(out.Suppressed, f)
			continue
		}
		if finding.Rank(f.Severity) >= out.Threshold {
			out.Violations = append(out.Violations, f)
		}
	}
	// Ямар ч finding-д тохироогүй suppression — resource дахин нэрлэгдсэн, эсвэл
	// асуудал зассан байж болно. Аль ч тохиолдолд ЧИМЭЭГҮЙ байж болохгүй:
	// хуучирсан дүрэм нь дараа өөр finding-ийг санамсаргүй хаах эрсдэлтэй, мөн
	// "хүлээн зөвшөөрсөн эрсдэл" гэсэн бүртгэл бодит биш болсныг харуулна.
	for i, s := range active {
		if !used[i] {
			out.UnusedRules = append(out.UnusedRules, s)
		}
	}

	if len(out.Violations) > 0 {
		out.Passed = false
		out.Reasons = append(out.Reasons, ReasonThreshold)
	}
	if p.MinScore > 0 && res.Summary.RiskScore < p.MinScore {
		out.Passed = false
		out.ScoreViolated = true
		out.Reasons = append(out.Reasons, ReasonMinScore)
	}
	return out
}
