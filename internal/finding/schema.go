// Package finding defines the TATAR-Kuber Unified Finding Schema v1.
// Энэ бол бүх scanner-ийн гаралт хөрвөх ганц стандарт загвар.
package finding

// Severity — normalize хийсэн 5 түвшин.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Type — finding-ийн төрөл.
type Type string

const (
	TypeMisconfig     Type = "misconfiguration"
	TypeVulnerability Type = "vulnerability"
	TypeSecret        Type = "secret"
	TypeRBAC          Type = "rbac"
	TypeNetwork       Type = "network"
	TypeHygiene       Type = "hygiene"
)

// Status — finding lifecycle. MVP-д бүх finding OPEN. Шилжилт нь Enterprise/v2.
type Status string

const (
	StatusOpen           Status = "OPEN"
	StatusAcknowledged   Status = "ACKNOWLEDGED"
	StatusMitigationPlan Status = "MITIGATION_PLANNED"
	StatusFixed          Status = "FIXED"
	StatusVerified       Status = "VERIFIED"
	StatusClosed         Status = "CLOSED"
)

// Confidence — итгэлийн зэрэг (scanner corroboration).
type Confidence string

const (
	// Тэмдэглэл: эдгээрийг risk.Confidence(scannerCount, heuristic) тооцоолно —
	// scanner тоо БА шалгалтын determinism хоёулангаас (Doc #4 §4.3):
	//   2+ scanner                     -> HIGH   (олон scanner санал нийлсэн)
	//   1 scanner + deterministic      -> HIGH   (CVE, тодорхой талбарын шалгалт)
	//   1 scanner + эвристик           -> MEDIUM (canonical control heuristic: true)
	//   0 scanner (зөвхөн контекст)    -> LOW
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// RawRef — raw scanner гаралт руу заасан лавлагаа.
type RawRef struct {
	Scanner string `json:"scanner"`
	RuleID  string `json:"rule_id"`
}

// Evidence — асуудал яг хаана байгааг харуулах нотолгоо (scanner бүрээр).
// Path: spec зам эсвэл файл:мөр. Value: ажиглагдсан/зөвлөмж утга.
// Detail: чөлөөт текст (message, pkg@ver, secret match).
type Evidence struct {
	Scanner string `json:"scanner"`
	Path    string `json:"path,omitempty"`
	Value   string `json:"value,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Finding — атомын нэгж (Unified Schema §3).
type Finding struct {
	ID               string            `json:"id"`
	CanonicalControl string            `json:"canonical_control"`
	Resource         string            `json:"resource"`
	Namespace        string            `json:"namespace,omitempty"`
	Type             Type              `json:"type"`
	Category         string            `json:"category"`
	Severity         Severity          `json:"severity"`
	OriginalSeverity Severity          `json:"original_severity,omitempty"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Evidence         []Evidence        `json:"evidence,omitempty"` // асуудал яг хаана (scanner бүрээр)
	Remediation      string            `json:"remediation"`
	FoundBy          []string          `json:"found_by"`
	Confidence       Confidence        `json:"confidence"`
	BlindShot        bool              `json:"blind_shot"`
	BlindShotReason  string            `json:"blind_shot_reason,omitempty"`
	RiskContribution float64           `json:"risk_contribution,omitempty"`
	RiskFactors      *RiskFactors      `json:"risk_factors,omitempty"` // оноо яагаад ийм болсныг задлан харуулна
	Attack           []AttackTechnique `json:"attack,omitempty"`       // энэ сул тал БОЛОМЖТОЙ БОЛГОДОГ MITRE ATT&CK техник(үүд)
	Status           Status            `json:"status"`
	Owner            string            `json:"owner,omitempty"`
	FirstSeen        string            `json:"first_seen"`
	LastSeen         string            `json:"last_seen"`
	References       []string          `json:"references,omitempty"`
	RawRefs          []RawRef          `json:"raw_refs,omitempty"`
}

// AttackTechnique — тухайн сул тал (misconfiguration) ямар MITRE ATT&CK for
// Containers техникийг БОЛОМЖТОЙ БОЛГОДГИЙГ (enables) илэрхийлнэ. Энэ бол
// "илрүүлсэн техник" биш — posture дахь эмзэг байдал халдлагыг хөнгөвчилдгийг
// заана (Tatar-Triage-ийн detection-аас ялгаатай, зориудаар "may enable" хүрээтэй).
type AttackTechnique struct {
	Technique string `json:"technique" yaml:"technique"` // ж: T1611
	Name      string `json:"name" yaml:"name"`           // ж: Escape to Host
	Tactic    string `json:"tactic" yaml:"tactic"`       // ж: Privilege Escalation
}

// RiskFactors — finding-ийн risk_contribution-ыг үржүүлэгч тус бүрээр задалж
// харуулна: contribution = base_weight × asset_context × exposure × confidence.
// Ингэснээр оноо "хар хайрцаг" биш, шалгагдах, тайлбарлагдах болно.
type RiskFactors struct {
	BaseWeight   float64 `json:"base_weight"`   // severity-ийн суурь жин (Crit10..Info0)
	AssetContext float64 `json:"asset_context"` // prod 1.5 / unknown 1.0 / dev 0.8
	Exposure     float64 `json:"exposure"`      // internet 1.5 / internal 1.0
	Confidence   float64 `json:"confidence"`    // scanner corroboration 1.2/1.0/0.8
	Contribution float64 `json:"contribution"`  // эцсийн үржвэр
}

// TopContributor — cluster оноог хамгийн ихээр бууруулсан findings.
type TopContributor struct {
	ID               string   `json:"id"`
	CanonicalControl string   `json:"canonical_control"`
	Resource         string   `json:"resource"`
	Severity         Severity `json:"severity"`
	Contribution     float64  `json:"contribution"`
	Share            float64  `json:"share"` // нийт penalty-д эзлэх хувь (0..100)
}

// RiskBreakdown — cluster оноог хэрхэн тооцсоны бүрэн тайлбар (explainable score).
type RiskBreakdown struct {
	TotalPenalty     float64          `json:"total_penalty"`      // score-д орсон эцсийн penalty
	HighPenalty      float64          `json:"high_penalty"`       // CRITICAL/HIGH/MEDIUM нийлбэр
	LowPenaltyRaw    float64          `json:"low_penalty_raw"`    // LOW-ийн түүхий нийлбэр
	LowPenaltyCapped float64          `json:"low_penalty_capped"` // min(cap, raw)
	LowPoolCap       float64          `json:"low_pool_cap"`       // LOW pool дээд хязгаар
	Scale            float64          `json:"scale"`              // diminishing масштаб K
	Formula          string           `json:"formula"`            // "100 / (1 + P/K)"
	TopContributors  []TopContributor `json:"top_contributors"`
}

// ScanResult — scan-result.json дээд түвшний бүтэц (§2).
type ScanResult struct {
	SchemaVersion string    `json:"schema_version"`
	Metadata      Metadata  `json:"metadata"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

type Metadata struct {
	ScanID          string            `json:"scan_id"`
	ClusterName     string            `json:"cluster_name"`
	ScanMode        string            `json:"scan_mode"`      // local | remote
	Lang            string            `json:"lang,omitempty"` // тайлангийн хэл: en | mn
	TatarVersion    string            `json:"tatar_version"`
	ScannerVersions map[string]string `json:"scanner_versions"`
	ScannerRuns     []ScannerRun      `json:"scanner_runs,omitempty"` // scanner бүрийн бодит үр дүн (шударга тайлан)
	Rollup          *RollupInfo       `json:"rollup,omitempty"`       // Pod -> controller зөөлтийн хураангуй
	StartedAt       string            `json:"started_at"`
	FinishedAt      string            `json:"finished_at"`
	ResultHash      string            `json:"result_hash"`
	Inventory       map[string]int    `json:"inventory,omitempty"` // cluster объектын тоо (сонголт)
}

// RollupInfo — Pod хэмжээний finding-ийг эзэмшигч controller руу зөөсөн тухай.
// Аудитад ил байх ёстой: тоо буурсан нь "асуудал арилсан" гэсэн үг биш,
// "нэг зөрчил нэг удаа тоологдож байна" гэсэн үг.
type RollupInfo struct {
	Moved int      `json:"moved"`          // зөөгдсөн finding-ийн тоо
	Pods  []string `json:"pods,omitempty"` // зөөгдсөн өвөрмөц pod-ууд
}

// ScannerRun — нэг scanner-ийн энэ scan дахь бодит явц. "Scanner суусан" гэдэг
// нь "finding өгсөн" гэсэн үг биш: unasan/timeout/parse алдаа/canonical mapping
// олдоогүй rule бүр энд ил харагдана. Ингэснээр "0 finding" нь "цэвэр" үү,
// "scanner ажиллаагүй" юу гэдэг нь тайланд ялгарна.
type ScannerRun struct {
	Scanner       string   `json:"scanner"`
	Status        string   `json:"status"` // ok | unavailable | unsupported | error | timeout | parse_error | ingested
	Version       string   `json:"version,omitempty"`
	DurationMS    int64    `json:"duration_ms,omitempty"`
	Error         string   `json:"error,omitempty"`
	RawBytes      int      `json:"raw_bytes,omitempty"`      // scanner-ийн түүхий гаралтын хэмжээ
	Findings      int      `json:"findings"`                 // normalize хийгдсэн (dedup-ээс ӨМНӨХ) finding тоо
	UnmappedRules []string `json:"unmapped_rules,omitempty"` // canonical registry-д зураглалгүй тул хаягдсан rule ID-ууд
	UnmappedCount int      `json:"unmapped_count,omitempty"` // зураглалгүй илрүүлэлтийн нийт тоо
}

type Summary struct {
	Counts        map[Severity]int `json:"counts"`
	BlindShot     int              `json:"blind_shot"`
	RiskScore     int              `json:"risk_score"`
	RiskBand      string           `json:"risk_band"`
	TotalFindings int              `json:"total_findings"`
	RiskBreakdown *RiskBreakdown   `json:"risk_breakdown,omitempty"` // оноо хэрхэн гарсны тайлбар
}

// Rank — severity-ийн эрэмбийн тоо (CRITICAL=5 … INFO=1, тодорхойгүй=0).
// Бүх package (dedup, policy, sarif, orchestrator, cli) энэ НЭГ эх сурвалжийг ашиглана.
func Rank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// NormalizeSeverity — scanner severity string -> TATAR Severity. Хоосон/UNKNOWN -> "".
func NormalizeSeverity(s string) Severity {
	switch s {
	case "CRITICAL", "Critical", "critical":
		return SeverityCritical
	case "HIGH", "High", "high":
		return SeverityHigh
	case "MEDIUM", "Medium", "medium":
		return SeverityMedium
	case "LOW", "Low", "low":
		return SeverityLow
	case "INFO", "Info", "info", "INFORMATIONAL":
		return SeverityInfo
	default:
		return "" // тодорхойгүй — canonical default_severity ашиглана
	}
}
