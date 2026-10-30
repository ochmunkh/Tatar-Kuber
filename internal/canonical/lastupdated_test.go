package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Бүртгэл сүүлд хэзээ өөрчлөгдсөнөө ӨӨРӨӨ хэлдэг — `last_updated`. Тэр утгыг
// юу ч барьдаггүй байсан: 2026-10-18-нд 33 control бүрийн тайлбар нэмэгдсэн
// атлаа файл '2026-09-07' гэж бичсэн хэвээр үлдэж, `docs/coverage.md` түүнийг
// хэрэглэгчид давтан хэлж байв.
//
// Энэ бол төслийн нэрлэсэн эвдрэл: хэрэгсэл өөрийгөө худал тайлбарлаж байгаа
// нь чимээгүй. Тиймээс бүртгэлийн УТГА САНААНЫ агуулгыг (сэтгэгдэл, мөрийн
// эрэмбэ биш) hash-даж, доорх тогтмолтой тулгана. Зураглал, severity, тайлбар
// зэрэг аль нэг нь өөрчлөгдвөл энэ тест унаж, `last_updated`-ыг шинэчлэхийг
// шаардана.
const (
	registryDigest      = "3731ca39f705fd9bbfeb070f805dad1496ca61e19b961c4bb06a4942b4876876"
	registryLastUpdated = "2026-10-18"
)

func TestRegistryLastUpdatedTracksContent(t *testing.T) {
	reg, err := Load("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("бүртгэл ачаалж чадсангүй: %v", err)
	}
	got := semanticDigest(reg)

	if reg.LastUpdated != registryLastUpdated {
		t.Errorf("last_updated=%q, тест %q гэж хүлээж байна — хоёулангийг нь хамт шинэчил",
			reg.LastUpdated, registryLastUpdated)
	}
	if got != registryDigest {
		t.Fatalf("бүртгэлийн агуулга өөрчлөгдсөн байна.\n"+
			"  хуучин digest: %s\n  шинэ   digest: %s\n\n"+
			"Хийх зүйл: schema/canonical-controls.yaml дотор last_updated-ыг өнөөдрийн "+
			"огноо болгож, энэ файл дотор registryDigest болон registryLastUpdated "+
			"хоёрыг дээрх шинэ утгуудаар сольж тавь.",
			registryDigest, got)
	}
}

// semanticDigest — бүртгэлийн утга санааны агуулгын тогтвортой hash.
// Сэтгэгдэл, зай, map-ийн давталтын эрэмбээс хамаарахгүй байхаар гараар
// бичигдсэн: талбар бүрийг тодорхой дарааллаар бичнэ.
func semanticDigest(reg *Registry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "schema_version=%s\n", reg.SchemaVersion)
	for _, c := range reg.Categories {
		fmt.Fprintf(&b, "cat|%s|%s\n", c.ID, c.Name)
	}
	for _, c := range reg.Controls {
		fmt.Fprintf(&b, "ctl|%s|%s|%s|%s|%s|%t|%s\n",
			c.ID, c.Category, c.Type, c.DefaultSeverity, c.Status, c.Heuristic, c.SupersededBy)
		writeI18n(&b, "title", c.Title)
		writeI18n(&b, "desc", c.Description)
		writeI18n(&b, "rem", c.Remediation)
		for _, r := range c.References {
			fmt.Fprintf(&b, "  ref|%s\n", r)
		}
		for _, a := range c.Attack {
			fmt.Fprintf(&b, "  atk|%v\n", a)
		}
		scanners := make([]string, 0, len(c.Mappings))
		for s := range c.Mappings {
			scanners = append(scanners, s)
		}
		sort.Strings(scanners)
		for _, s := range scanners {
			rules := append([]string(nil), c.Mappings[s]...)
			sort.Strings(rules)
			fmt.Fprintf(&b, "  map|%s|%s\n", s, strings.Join(rules, ","))
		}
		for _, r := range c.BlindShotRules {
			fmt.Fprintf(&b, "  bsr|%s|%s|%s|%s\n", r.Namespace, r.ResourceMatch, r.DowngradeTo, r.Reason)
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func writeI18n(b *strings.Builder, key string, v I18n) {
	langs := make([]string, 0, len(v))
	for l := range v {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	for _, l := range langs {
		fmt.Fprintf(b, "  %s|%s|%s\n", key, l, v[l])
	}
}
