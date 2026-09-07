// Risk scoring-ийн context илрүүлэлт ба findings дээр хэрэглэх wiring.
package risk

import (
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// prodTokens / devTokens / negTokens — namespace нэрийг ТОКЕНООР тааруулна.
//
// v1.0.2 хүртэл strings.Contains ашигладаг байсан нь бодит алдаа гаргаж байв:
//
//	"non-prod"     -> production (1.5x)  ← dev байх ёстой
//	"nonprod"      -> production (1.5x)
//	"reproduction" -> production (1.5x)  ← "prod" дэд мөр агуулсны улмаас
//	"device"       -> development (0.8x) ← "dev" дэд мөр агуулсны улмаас
//
// Ингэснээр dev namespace-ийн эрсдэл ~87%-иар хөөрөгдөж (0.8 -> 1.5), эсрэгээр
// production-ийнх дорд үнэлэгдэж, аудитын тайланд бодит зөрүү үүсдэг байв.
var (
	prodTokens = map[string]bool{"prod": true, "production": true, "prd": true, "live": true}
	devTokens  = map[string]bool{
		"dev": true, "devel": true, "develop": true, "development": true,
		"test": true, "tests": true, "testing": true, "tst": true,
		"stage": true, "staging": true, "stg": true,
		"qa": true, "uat": true, "sandbox": true, "sbx": true, "demo": true,
		"nonprod": true, "preprod": true,
	}
	// negTokens — дараа орох "prod"-ыг үгүйсгэнэ ("non-prod", "pre-prod").
	negTokens = map[string]bool{"non": true, "no": true, "not": true, "pre": true}
)

// nsTokens — namespace нэрийг K8s-д зөвшөөрөгдсөн тусгаарлагчаар хуваана.
func nsTokens(ns string) []string {
	return strings.FieldsFunc(strings.ToLower(ns), func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
}

// DetectAssetContext — namespace нэрээс production/development/unknown үржүүлэгч.
// Токеноор бүтэн таарсан үед л шийднэ; эргэлзээтэй үед Unknown (1.0) — өөрөөр
// хэлбэл дорд ч үнэлэхгүй, хөөрөгдөхгүй.
//
// (v2: namespace-ийн label-аар баяжуулах — ж: env=production. Нэр нь эвристик,
// label нь тунхаглал тул илүү найдвартай.)
func DetectAssetContext(namespace string) float64 {
	var hasProd, hasDev, hasNeg bool
	for _, t := range nsTokens(namespace) {
		if prodTokens[t] {
			hasProd = true
		}
		if devTokens[t] {
			hasDev = true
		}
		if negTokens[t] {
			hasNeg = true
		}
	}
	switch {
	case hasProd && !hasNeg && !hasDev:
		return CtxProduction
	case hasDev || (hasProd && hasNeg):
		return CtxDevelopment
	default:
		return CtxUnknown
	}
}

// DetectExposure — MVP-д Unknown (1.0). Ил гарсан байдлыг тодорхойлоход
// Service type / Ingress хэрэгтэй тул orchestrator дараа баяжуулна.
func DetectExposure(f finding.Finding) float64 {
	return ExpUnknown
}

// ApplyScores — finding бүрийн RiskContribution + RiskFactors (explainable)-ыг
// тооцоолж, cluster оноо (0..100), band, БА оноог хэрхэн гаргасны бүрэн
// задаргаа (RiskBreakdown)-ыг буцаана.
func ApplyScores(findings []finding.Finding) ([]finding.Finding, int, string, finding.RiskBreakdown) {
	out := make([]finding.Finding, len(findings))
	copy(out, findings)

	penalties := make([]float64, len(out))
	severities := make([]finding.Severity, len(out))
	for i := range out {
		ctx := Context{
			AssetContext: DetectAssetContext(out[i].Namespace),
			Exposure:     DetectExposure(out[i]),
		}
		rf := factors(out[i], ctx)
		penalties[i] = rf.Contribution
		severities[i] = out[i].Severity

		out[i].RiskContribution = round1(rf.Contribution)
		rounded := rf
		rounded.Contribution = round1(rf.Contribution)
		out[i].RiskFactors = &rounded // задаргаа finding дотор шингэнэ
	}
	score, band := ClusterScore(penalties, severities)
	bd := buildBreakdown(out, penalties, severities)
	return out, score, band, bd
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
