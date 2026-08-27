// Package risk implements the TATAR-Kuber Risk Scoring Model v1.2.
// Level 1: Finding Risk = base_weight × asset_context × exposure × confidence
// Level 2: Security Score = 100 − Total Penalty (LOW pool cap = 10)
package risk

import (
	"math"
	"sort"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// ---- Level 1 multipliers (LOCK, Doc #4) ----

var baseWeight = map[finding.Severity]float64{
	finding.SeverityCritical: 10,
	finding.SeverityHigh:     7,
	finding.SeverityMedium:   3,
	finding.SeverityLow:      1,
	finding.SeverityInfo:     0,
}

var confidenceMul = map[finding.Confidence]float64{
	finding.ConfidenceHigh:   1.2,
	finding.ConfidenceMedium: 1.0,
	finding.ConfidenceLow:    0.8,
}

// AssetContext / Exposure үржүүлэгч.
const (
	CtxProduction  = 1.5
	CtxUnknown     = 1.0
	CtxDevelopment = 0.8

	ExpInternet = 1.5
	ExpInternal = 1.0
	ExpUnknown  = 1.0
)

// LowPoolCap — бүх LOW finding-ийн нийт penalty дээд хязгаар.
const LowPoolCap = 10.0

// ScoreScale — diminishing загварын масштаб (K). Score = 100/(1 + P/K).
const ScoreScale = 100.0

// Context — finding-ийн орчны мэдээлэл (илрүүлэгчээс).
type Context struct {
	AssetContext float64 // Ctx*
	Exposure     float64 // Exp*
}

// factors — finding-ийн risk үржүүлэгчдийг задалж буцаана (тэг бол default).
// Энэ бол explainable score-ийн эх сурвалж: FindingRisk болон RiskFactors
// хоёул эндээс гарна (нэг эх, зөрөхгүй).
func factors(f finding.Finding, ctx Context) finding.RiskFactors {
	w := baseWeight[f.Severity]
	c := confidenceMul[f.Confidence]
	if c == 0 {
		c = 1.0
	}
	ac := ctx.AssetContext
	if ac == 0 {
		ac = CtxUnknown
	}
	ex := ctx.Exposure
	if ex == 0 {
		ex = ExpUnknown
	}
	return finding.RiskFactors{
		BaseWeight:   w,
		AssetContext: ac,
		Exposure:     ex,
		Confidence:   c,
		Contribution: w * ac * ex * c,
	}
}

// FindingRisk — Level 1 оноо (finding.RiskContribution).
func FindingRisk(f finding.Finding, ctx Context) float64 {
	return factors(f, ctx).Contribution
}

// buildBreakdown — cluster оноог хэрхэн тооцсоны explainable задаргаа:
// high/low penalty, LOW pool cap-ийн нөлөө, томьёо, топ хувь нэмэгч findings.
func buildBreakdown(fs []finding.Finding, penalties []float64, severities []finding.Severity) finding.RiskBreakdown {
	var high, lowRaw float64
	for i := range penalties {
		switch severities[i] {
		case finding.SeverityLow:
			lowRaw += penalties[i]
		case finding.SeverityInfo:
			// оноонд нөлөөлөхгүй
		default:
			high += penalties[i]
		}
	}
	lowCapped := math.Min(LowPoolCap, lowRaw)
	total := high + lowCapped

	type pc struct {
		idx int
		p   float64
	}
	ranked := make([]pc, 0, len(fs))
	for i := range fs {
		if severities[i] == finding.SeverityInfo || penalties[i] <= 0 {
			continue
		}
		ranked = append(ranked, pc{i, penalties[i]})
	}
	sort.Slice(ranked, func(a, b int) bool {
		if ranked[a].p != ranked[b].p {
			return ranked[a].p > ranked[b].p
		}
		return fs[ranked[a].idx].ID < fs[ranked[b].idx].ID // тай-брейк: detrministik
	})

	denom := high + lowRaw // share-ийн суурь: түүхий нийт penalty (INFO-гүй)
	n := len(ranked)
	if n > 5 {
		n = 5
	}
	tops := make([]finding.TopContributor, 0, n)
	for _, e := range ranked[:n] {
		share := 0.0
		if denom > 0 {
			share = e.p / denom * 100
		}
		f := fs[e.idx]
		tops = append(tops, finding.TopContributor{
			ID:               f.ID,
			CanonicalControl: f.CanonicalControl,
			Resource:         f.Resource,
			Severity:         f.Severity,
			Contribution:     round1(e.p),
			Share:            round1(share),
		})
	}

	return finding.RiskBreakdown{
		TotalPenalty:     round1(total),
		HighPenalty:      round1(high),
		LowPenaltyRaw:    round1(lowRaw),
		LowPenaltyCapped: round1(lowCapped),
		LowPoolCap:       LowPoolCap,
		Scale:            ScoreScale,
		Formula:          "100 / (1 + P/K)",
		TopContributors:  tops,
	}
}

// ClusterScore — Level 2 (0..100), DIMINISHING загвар (v1.2.1).
//
//	Total Penalty = Σ FindingRisk (CRITICAL/HIGH/MEDIUM)
//	              + min(LowPoolCap, Σ FindingRisk (LOW))
//	Score = 100 / (1 + Total Penalty / ScoreScale)
//
// Diminishing функц нь оноог хэзээ ч яг 0 болгодоггүй бөгөөд эрэмбийг
// хадгална (linear-cap загварын saturate асуудлыг арилгана): penalty өссөөр
// оноо жигд буурч, "дөнгөж босго давсан" ба "гамшигт" cluster-ыг ялгана.
func ClusterScore(penalties []float64, severities []finding.Severity) (int, string) {
	var high, low float64
	for i, p := range penalties {
		if i < len(severities) && severities[i] == finding.SeverityLow {
			low += p
		} else if i < len(severities) && severities[i] == finding.SeverityInfo {
			// INFO оноонд нөлөөлөхгүй
		} else {
			high += p
		}
	}
	total := high + math.Min(LowPoolCap, low)
	score := int(math.Round(100 / (1 + total/ScoreScale)))
	if score < 1 {
		score = 1 // хэзээ ч яг 0 болохгүй
	}
	if score > 100 {
		score = 100
	}
	return score, Band(score)
}

// Band — оноо → эрсдэлийн зурвас.
func Band(score int) string {
	switch {
	case score >= 90:
		return "Excellent"
	case score >= 70:
		return "Good"
	case score >= 50:
		return "Fair"
	case score >= 30:
		return "Poor"
	default:
		return "Critical"
	}
}

// Confidence — итгэлийн зэргийг scanner corroboration БА check determinism
// хоёулангаас тодорхойлно (Doc #4 §4.3, v1.2 уточнение).
//
//	scannerCount >= 2            -> HIGH  (олон scanner санал нийлсэн)
//	scannerCount == 1 && !heur   -> HIGH  (deterministic шалгалт, ж: CVE, талбар)
//	scannerCount == 1 && heur    -> MEDIUM (ганц scanner, эвристик)
//	scannerCount == 0            -> LOW   (зөвхөн контекст/дүгнэлт)
//
// heuristic нь canonical control-ийн шинж (Registry.Control.Heuristic).
func Confidence(scannerCount int, heuristic bool) finding.Confidence {
	switch {
	case scannerCount >= 2:
		return finding.ConfidenceHigh
	case scannerCount == 1 && !heuristic:
		return finding.ConfidenceHigh
	case scannerCount == 1 && heuristic:
		return finding.ConfidenceMedium
	default:
		return finding.ConfidenceLow
	}
}
