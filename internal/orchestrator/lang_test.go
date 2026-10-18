package orchestrator

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Control-ийн тайлбар хоёр хэлээр солигдох ёстой, ГЭХДЭЭ scanner өөрөө бичсэн
// тодорхой тайлбарыг дарж болохгүй: "secret detected: AWS" гэдэг нь тухайн
// олдворын тухай баримт, control-ынх нь ерөнхий тодорхойлолт.
func TestApplyLang_SwitchesControlDescriptionButKeepsScannerText(t *testing.T) {
	reg := &canonical.Registry{Controls: []canonical.Control{{
		ID:          "TATAR-TST-001",
		Title:       canonical.I18n{"en": "Test control", "mn": "Тест контрол"},
		Description: canonical.I18n{"en": "The generic explanation.", "mn": "Ерөнхий тайлбар."},
		Remediation: canonical.I18n{"en": "Fix it.", "mn": "Зас."},
	}}}

	fs := []finding.Finding{
		// (1) control-оос ирсэн тайлбар — хэл солигдох ёстой
		{CanonicalControl: "TATAR-TST-001", Description: "The generic explanation."},
		// (2) scanner-ийн бичсэн тодорхой тайлбар — хэвээр үлдэх ёстой
		{CanonicalControl: "TATAR-TST-001", Description: "secret detected: AWS"},
		// (3) огт тайлбаргүй — дүүргэгдэх ёстой
		{CanonicalControl: "TATAR-TST-001", Description: ""},
	}
	ApplyLang(fs, reg, "mn")

	if fs[0].Description != "Ерөнхий тайлбар." {
		t.Errorf("control-ийн тайлбар монгол руу солигдоогүй: %q", fs[0].Description)
	}
	if fs[1].Description != "secret detected: AWS" {
		t.Errorf("scanner-ийн тодорхой тайлбар дарагдав: %q — олдворын мэдээлэл алдагдаж байна", fs[1].Description)
	}
	if fs[2].Description != "Ерөнхий тайлбар." {
		t.Errorf("хоосон тайлбар дүүргэгдээгүй: %q", fs[2].Description)
	}

	ApplyLang(fs, reg, "en")
	if fs[0].Description != "The generic explanation." {
		t.Errorf("буцаад англи руу солигдоогүй: %q", fs[0].Description)
	}
	if fs[1].Description != "secret detected: AWS" {
		t.Errorf("scanner-ийн тайлбар хоёр дахь дуудлагад дарагдав: %q", fs[1].Description)
	}
}
