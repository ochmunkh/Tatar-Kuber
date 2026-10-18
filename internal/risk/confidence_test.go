package risk

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Итгэлийн зэрэг нь ТАЙЛБАРТАЙГАА хамт гарах ёстой. `confidence: HIGH` гэсэн
// үг дангаараа хоёр огт өөр нөхцөлийг ялгадаггүй: хоёр scanner нийлсэн үү,
// эсвэл нэг scanner шууд шалгалт хийсэн үү. Аудиторын хувьд энэ хоёр нь
// өөр хүчтэй мэдэгдэл.
func TestConfidenceOf_ReasonDistinguishesEqualGrades(t *testing.T) {
	cases := []struct {
		name      string
		scanners  int
		heuristic bool
		want      finding.Confidence
		reason    finding.ConfidenceReason
	}{
		{"хоёр scanner нийлсэн", 2, false, finding.ConfidenceHigh, finding.ConfidenceReasonCorroborated},
		{"хоёр scanner, эвристик ч гэсэн", 2, true, finding.ConfidenceHigh, finding.ConfidenceReasonCorroborated},
		{"нэг scanner, шууд шалгалт", 1, false, finding.ConfidenceHigh, finding.ConfidenceReasonSingleScanner},
		{"нэг scanner, эвристик", 1, true, finding.ConfidenceMedium, finding.ConfidenceReasonHeuristic},
		{"scanner алга", 0, false, finding.ConfidenceLow, finding.ConfidenceReasonUnattributed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := ConfidenceOf(c.scanners, c.heuristic)
			if got != c.want || reason != c.reason {
				t.Errorf("ConfidenceOf(%d, %v) = %s/%s, want %s/%s",
					c.scanners, c.heuristic, got, reason, c.want, c.reason)
			}
		})
	}

	// Хоёр HIGH нь ижил зэрэгтэй ч ӨӨР тайлбартай байх ёстой — энэ тестийн
	// гол санаа нь яг тэр: зэрэг нь мэдээллийг алддаг, тайлбар нь хадгална.
	a, ra := ConfidenceOf(3, false)
	b, rb := ConfidenceOf(1, false)
	if a != b {
		t.Fatalf("хоёулаа HIGH байх ёстой: %s vs %s", a, b)
	}
	if ra == rb {
		t.Errorf("гурван scanner ба нэг scanner ижил тайлбартай байна (%s) — зэрэг нь ялгааг нуусан хэвээр", ra)
	}
}

// Confidence нь ConfidenceOf-ийн нимгэн бүрхүүл: хоёр нь хэзээ ч зөрч
// болохгүй, эс бөгөөс тайлан өөрийн тайлбартайгаа зөрнө.
func TestConfidence_AgreesWithConfidenceOf(t *testing.T) {
	for _, n := range []int{0, 1, 2, 5} {
		for _, h := range []bool{false, true} {
			want, _ := ConfidenceOf(n, h)
			if got := Confidence(n, h); got != want {
				t.Errorf("Confidence(%d,%v)=%s, ConfidenceOf=%s", n, h, got, want)
			}
		}
	}
}
