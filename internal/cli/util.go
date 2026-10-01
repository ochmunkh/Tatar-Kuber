package cli

import (
	"encoding/json"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func jsonUnmarshal(data []byte, v interface{}) error { return json.Unmarshal(data, v) }

// parseSeverityThreshold — severity босгыг ТОМ/жижиг үсгээс үл хамааран уншина
// ("high", "High", "HIGH", бүр "HiGh" ч ижил). Танигдаагүй бол анхааруулаад
// ok=false.
//
// Rank("") = 0 тул танигдаагүй утгыг шалгалтад ШУУД дамжуулбал `>= 0` нь finding
// БҮРТЭЙ таарч, босго нь "бүхэнд унах" болж эсрэгээрээ хувирна — gate-ээ хамгийн
// их хэрэгтэй үед чимээгүй эвддэг зан. Тиймээс энд зогсоож, `diff --fail-on-new`
// аль хэдийн сонгосон зарчмаар ХЭРЭГСЭХГҮЙ (анхааруулна, харин унагахгүй).
//
// ToUpper нь NormalizeSeverity-ийн хувьд ЗАЙЛШГҮЙ БИШ (тэр "critical"/"Critical"/
// "CRITICAL" гурвыг хүлээж авдаг) ч ҮЛДЭЭВ: `diff --fail-on-new` өмнө нь үүнийг
// хэрэглэдэг байсан тул хасвал "HiGh" гэх дур зоргын том/жижиг үсэгтэй бичиглэл
// танигдахаа болиод gate ЧИМЭЭГҮЙ унтарна — босгыг сулруулах нь хүлээн зөвшөөрөхгүй.
func parseSeverityThreshold(value, flagName string) (finding.Severity, bool) {
	th := finding.NormalizeSeverity(strings.ToUpper(value))
	if finding.Rank(th) == 0 {
		warnln(msg("warn.threshold.unrecognised", flagName, value))
		return "", false
	}
	return th, true
}

// splitCSV — "a, b ,c" -> ["a","b","c"] (хоосныг алгасна).
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
