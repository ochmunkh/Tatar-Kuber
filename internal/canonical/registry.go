// Package canonical loads and queries the TATAR Canonical Control Registry
// (schema/canonical-controls.yaml) — product-ийн гол хөрөнгө.
package canonical

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"gopkg.in/yaml.v3"
)

// I18n — олон хэлт текст (ж: {en: "...", mn: "..."}).
type I18n map[string]string

// Get — тухайн хэл дээрх текст. Байхгүй бол en -> аль нэг руу fallback.
func (i I18n) Get(lang string) string {
	if v := i[lang]; v != "" {
		return v
	}
	if v := i["en"]; v != "" {
		return v
	}
	for _, v := range i {
		if v != "" {
			return v
		}
	}
	return ""
}

// BlindShotRule — контекстээр severity downgrade хийх дүрэм (устгахгүй).
type BlindShotRule struct {
	Namespace     string `yaml:"namespace"`
	ResourceMatch string `yaml:"resource_match"`
	Reason        string `yaml:"reason"`
	DowngradeTo   string `yaml:"downgrade_to"`
}

// Control — нэг canonical control.
type Control struct {
	ID              string                    `yaml:"id"`
	Title           I18n                      `yaml:"title"`
	Category        string                    `yaml:"category"`
	Type            string                    `yaml:"type"`
	DefaultSeverity string                    `yaml:"default_severity"`
	Status          string                    `yaml:"status"` // active | deprecated
	Description     string                    `yaml:"description"`
	Remediation     I18n                      `yaml:"remediation"`
	References      []string                  `yaml:"references"`
	Attack          []finding.AttackTechnique `yaml:"attack,omitempty"` // энэ control БОЛОМЖТОЙ БОЛГОХ MITRE ATT&CK техник(үүд)
	Mappings        map[string][]string       `yaml:"mappings"`         // scanner -> rule IDs
	BlindShotRules  []BlindShotRule           `yaml:"blind_shot_rules"`
	SupersededBy    string                    `yaml:"superseded_by,omitempty"`

	// Heuristic — контекст шаарддаг эвристик шалгалт эсэх. false (default)
	// бол deterministic (CVE, тодорхой талбарын шалгалт). Confidence-д нөлөөлнө.
	Heuristic bool `yaml:"heuristic"`
}

// Category — ангилал.
type Category struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

// Registry — бүх canonical control.
type Registry struct {
	SchemaVersion string     `yaml:"schema_version"`
	LastUpdated   string     `yaml:"last_updated"`
	Categories    []Category `yaml:"categories"`
	Controls      []Control  `yaml:"controls"`

	// байгуулагдах index: scanner -> ruleID -> []canonicalID
	// Тэмдэглэл: нэг scanner rule ОЛОН canonical control руу зурагдаж болно
	// (ж: trivy "CVE-*" -> IMG-001/IMG-002 severity-ээр; kubescape C-0018 ->
	// OPS-001/OPS-002 probe төрлөөр). Тиймээс утга нь жагсаалт.
	index map[string]map[string][]string
}

// Load — canonical-controls.yaml ачаалж index байгуулна.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("canonical registry уншиж чадсангүй: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes — registry-г шууд байтаас ачаална (go:embed-тэй ажиллах, тестэд).
func LoadBytes(data []byte) (*Registry, error) {
	var r Registry
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("canonical registry parse алдаа: %w", err)
	}
	if err := r.buildIndex(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Registry) buildIndex() error {
	r.index = map[string]map[string][]string{}
	seen := map[string]bool{}
	for _, c := range r.Controls {
		if seen[c.ID] {
			return fmt.Errorf("давхардсан canonical ID: %s", c.ID)
		}
		seen[c.ID] = true
		for scanner, rules := range c.Mappings {
			if r.index[scanner] == nil {
				r.index[scanner] = map[string][]string{}
			}
			for _, rule := range rules {
				k := NormalizeRuleID(scanner, rule)
				r.index[scanner][k] = append(r.index[scanner][k], c.ID)
			}
		}
	}
	return nil
}

var leadingZeros = regexp.MustCompile(`([A-Z])0+(\d)`)

// NormalizeRuleID — scanner rule ID-г хувилбар хоорондын бичиглэлийн зөрүүнээс
// хамааралгүй нэг түлхүүр болгоно. Registry-д бичсэн ID ба scanner-ийн бодит
// гаралт хоёулаа энэ функцээр дамждаг тул хоёр тал ижил хэлбэрт орно.
//
// Жишээ (trivy): "AVD-KSV-0017", "AVD-KSV0017", "KSV017", "KSV-0017" -> "KSV17".
// (kubescape) "C-0057" -> "C57"; (popeye) "POP-106" -> "POP106".
// Wildcard/тусгай түлхүүр ("CVE-*", "secret") хэвээр (зөвхөн uppercase).
func NormalizeRuleID(scanner, id string) string {
	s := strings.ToUpper(strings.TrimSpace(id))
	if strings.ContainsAny(s, "*") {
		return s
	}
	if scanner == "trivy" {
		s = strings.TrimPrefix(s, "AVD-")
	}
	s = strings.ReplaceAll(s, "-", "")
	return leadingZeros.ReplaceAllString(s, "$1$2")
}

// Resolve — scanner + rule ID-аас canonical control ID-уудыг (candidates) олно.
// Нэг rule олон control руу зурагдаж болох тул жагсаалт буцаана. Хэрэв нэгээс
// олон бол normalizer нь finding-ийн дэд мэдээллээр (CVE severity, probe төрөл,
// resource kind г.м) дискриминаци хийж зөв canonical-ыг сонгоно.
// Олдоогүй бол (nil, false).
func (r *Registry) Resolve(scanner, ruleID string) ([]string, bool) {
	m, ok := r.index[scanner]
	if !ok {
		return nil, false
	}
	ids, ok := m[NormalizeRuleID(scanner, ruleID)]
	return ids, ok
}

// Get — canonical ID-аар Control авна.
func (r *Registry) Get(id string) (Control, bool) {
	for _, c := range r.Controls {
		if c.ID == id {
			return c, true
		}
	}
	return Control{}, false
}

// ResolverContext — нэг scanner rule олон canonical руу зурагдсан үед
// зөв canonical-ыг сонгоход хэрэглэх finding-ийн дэд мэдээлэл.
// Жишээ: trivy "CVE-*" -> IMG-001(CRITICAL)/IMG-002(HIGH)-ыг Severity-ээр;
//
//	kubescape "C-0018" -> OPS-001(readiness)/OPS-002(liveness)-ыг Detail-ээр.
type ResolverContext struct {
	ResourceKind string // Deployment, Service, Role, ...
	Namespace    string
	Severity     string // scanner-ийн өгсөн severity (CVE-д чухал)
	Detail       string // rule-specific тэмдэг (ж: "readiness", "liveness", "image", "env")
}

// Resolver — Registry дээр суурилсан, олон candidate-аас нэгийг сонгодог.
// disamb: (candidateIDs, ctx) -> сонгосон canonicalID.
type Resolver struct {
	reg   *Registry
	rules map[string]func([]string, ResolverContext) string // scanner|ruleID -> selector

	mu     sync.Mutex
	misses map[string]map[string]int // scanner -> ruleID -> тоо (canonical зураглал олдоогүй)
}

// recordMiss — зураглалгүй rule-ыг тэмдэглэнэ (чимээгүй хаяхгүй).
func (rs *Resolver) recordMiss(scanner, ruleID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.misses == nil {
		rs.misses = map[string]map[string]int{}
	}
	if rs.misses[scanner] == nil {
		rs.misses[scanner] = map[string]int{}
	}
	rs.misses[scanner][ruleID]++
}

// Unmapped — тухайн scanner-ийн зураглалгүй rule ID-ууд (эрэмбэлсэн) ба нийт тоо.
func (rs *Resolver) Unmapped(scanner string) (rules []string, total int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for id, n := range rs.misses[scanner] {
		rules = append(rules, id)
		total += n
	}
	sort.Strings(rules)
	return rules, total
}

// ResetUnmapped — тоолуурыг цэвэрлэнэ (scan бүрийн эхэнд).
func (rs *Resolver) ResetUnmapped() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.misses = nil
}

// NewResolver — resolver үүсгэж, олон-candidate rule-уудад selector бүртгэнэ.
func (r *Registry) NewResolver() *Resolver {
	res := &Resolver{reg: r, rules: map[string]func([]string, ResolverContext) string{}}
	// selector-ийн түлхүүр ч мөн normalize хийгдэнэ (Resolve-тэй ижил хэлбэр).
	key := func(scanner, rule string) string { return scanner + "|" + NormalizeRuleID(scanner, rule) }

	// CVE severity-ээр IMG-001(CRITICAL) vs IMG-002(HIGH)
	bySeverity := func(cands []string, ctx ResolverContext) string {
		if ctx.Severity == "CRITICAL" {
			return pick(cands, "TATAR-IMG-001")
		}
		return pick(cands, "TATAR-IMG-002")
	}
	res.rules[key("trivy", "CVE-*")] = bySeverity
	// Тэмдэглэл (v1.0.2 аудит): kubescape C-0078 нь "Images from allowed registry" —
	// image CVE-тэй ХОЛБООГҮЙ, гэтэл CVE severity-ээр IMG-001/002 руу зурагдаж байв.
	// C-0018 нь ЗӨВХӨН readiness probe (liveness нь C-0056) тул probe selector
	// шаардлагагүй болов. C-0260 нь зөвхөн NET-001 (default-deny нь C-0030).

	// secret байршлаар SEC-001(env) / SEC-002(image) / SEC-004(configmap)
	res.rules[key("trivy", "secret")] = func(cands []string, ctx ResolverContext) string {
		switch ctx.Detail {
		case "image":
			return pick(cands, "TATAR-SEC-002")
		case "configmap":
			return pick(cands, "TATAR-SEC-004")
		default:
			return pick(cands, "TATAR-SEC-001")
		}
	}

	return res
}

// ResolveOne — scanner + ruleID + context-оос ганц canonical ID сонгоно.
func (rs *Resolver) ResolveOne(scanner, ruleID string, ctx ResolverContext) (string, bool) {
	cands, ok := rs.reg.Resolve(scanner, ruleID)
	if !ok || len(cands) == 0 {
		rs.recordMiss(scanner, ruleID)
		return "", false
	}
	if len(cands) == 1 {
		return cands[0], true
	}
	if sel, ok := rs.rules[scanner+"|"+NormalizeRuleID(scanner, ruleID)]; ok {
		if id := sel(cands, ctx); id != "" {
			return id, true
		}
	}
	// Selector алга бол эхний candidate-ыг сонгоод анхааруулга үлдээх ёстой.
	// (TODO: normalizer-т warning лог гаргах.)
	return cands[0], true
}

func pick(cands []string, want string) string {
	for _, c := range cands {
		if c == want {
			return c
		}
	}
	return ""
}

// Control — Resolver-оос canonical control авах туслах.
func (rs *Resolver) Control(id string) (Control, bool) { return rs.reg.Get(id) }
