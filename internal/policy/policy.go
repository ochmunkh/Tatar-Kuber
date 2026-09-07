// Package policy implements the TATAR-Kuber CI/CD gatekeeper: a .tatar-kuber.yaml
// бодлого унших, suppression хэрэглэх, severity босго / cluster score-оор
// pass/fail шийдэх. Pipeline энэ шийдвэрийг exit code болгон CI-д дамжуулна.
package policy

import (
	"fmt"
	"os"
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

// ValidFailOn — fail_on утга танигдах эсэх (танигдахгүй бол threshold high-г ашиглана,
// CLI анхааруулга хэвлэнэ — чимээгүй default руу унахгүй).
func (p Policy) ValidFailOn() bool {
	switch p.FailOn {
	case "critical", "CRITICAL", "high", "HIGH", "medium", "MEDIUM", "low", "LOW":
		return true
	}
	return false
}

// threshold — fail_on severity-ийн rank (танигдахгүй бол high).
func (p Policy) threshold() int {
	switch p.FailOn {
	case "critical", "CRITICAL":
		return finding.Rank(finding.SeverityCritical)
	case "high", "HIGH":
		return finding.Rank(finding.SeverityHigh)
	case "medium", "MEDIUM":
		return finding.Rank(finding.SeverityMedium)
	case "low", "LOW":
		return finding.Rank(finding.SeverityLow)
	default:
		return finding.Rank(finding.SeverityHigh)
	}
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

// Result — gate-ийн шийдвэр.
type Result struct {
	Passed        bool
	FailOn        string
	Threshold     int
	Violations    []finding.Finding // босго давсан, suppress хийгдээгүй олдворууд
	Suppressed    []finding.Finding // suppress хийгдсэн олдворууд
	ExpiredRules  []Suppression     // хугацаа дууссан suppression (анхааруулга)
	InvalidRules  []Suppression     // буруу форматтай expires
	Score         int
	MinScore      int
	ScoreViolated bool
	Reasons       []string
}

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

	for _, f := range res.Findings {
		suppressed := false
		for _, s := range active {
			if s.matches(f) {
				suppressed = true
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

	if len(out.Violations) > 0 {
		out.Passed = false
		out.Reasons = append(out.Reasons, fmt.Sprintf("%d олдвор '%s' болон дээш түвшинд байна", len(out.Violations), p.FailOn))
	}
	if p.MinScore > 0 && res.Summary.RiskScore < p.MinScore {
		out.Passed = false
		out.ScoreViolated = true
		out.Reasons = append(out.Reasons, fmt.Sprintf("cluster score %d < шаардлагатай %d", res.Summary.RiskScore, p.MinScore))
	}
	return out
}
