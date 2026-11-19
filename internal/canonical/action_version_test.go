package canonical

import (
	"os"
	"regexp"
	"testing"
)

// action.yml-ийн `version` default нь `latest` БИШ, сүүлд гарсан release tag
// байх ёстой. `latest` нь хөдөлгөөнтэй заагч: тэр өдөр master дээр юу байна
// түүнийг хэрэглэгчийн CI-д ажиллуулна. Аюулгүй байдлын gate-ийг ингэж
// суулгах нь тухайн өдрийн хянагдаагүй кодыг итгэмжлэгдсэн алхам болгоно.
func TestActionDefaultVersionIsPinnedRelease(t *testing.T) {
	data, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)\n  version:.*?default:\s*"([^"]*)"`).FindSubmatch(data)
	if m == nil {
		t.Fatal("action.yml: version input-ийн default олдсонгүй")
	}
	got, want := string(m[1]), "v"+latestRelease(t)
	if got != want {
		t.Errorf("action.yml version default = %q, хүлээсэн %q (сүүлд гарсан release).\n"+
			"  Release гаргасны дараа үүнийг README-тэй хамт шинэчилнэ; `latest` ашиглахгүй.", got, want)
	}
}
