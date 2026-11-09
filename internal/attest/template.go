package attest

import (
	"fmt"
	"strings"
)

// Labels — загварын бичвэрүүд. ЭНД хатуу бичигдээгүй: CLI нь `--lang`-ийн дагуу
// өөрийн каталогоос дүүргэж дамжуулна.
//
// Яагаад: v1.0.3-д бүх гаралт нэг хэлээр хатуу бичигдсэн байсныг засаж, бичвэр
// бүрийг НЭГ каталогт төвлөрүүлсэн. Шинэ команд тэр дүрмийг зөрчиж, өөрийн
// бичвэрийг дотроо нуувал хоёр хэл дахин чимээгүй зөрнө.
type Labels struct {
	Header     string // бүтэн толгойн тайлбар (мөр бүрийн "# " нь энд байхгүй)
	Generated  string // "Үүсгэсэн: %s · санал болгох expires: %s"
	Decision   string
	Rationale  string
	AttestedBy string
	Expires    string
	Evidence   string
	Scope      string
	NoGaps     string
	Severity   string
}

// Template — баталгаажуулах загвар YAML үүсгэнэ.
//
// Загвар нь БӨГЛӨӨГҮЙ байхаар зориудаар гардаг: decision, rationale,
// attested_by гурав хоосон. Урьдчилан "compliant" гэж бөглөсөн загвар нь
// хүнийг уншилгүй баталдаг болгоно — баталгаажуулалтын бүх утгыг устгах
// хамгийн хялбар арга. Хоосон decision нь Validate дээр унана.
//
// expires-ийг мөн бөглөхгүй: хугацааг хүн ухамсартай сонгох ёстой. Санал
// болгосон утга зөвхөн сэтгэгдэлд гарна.
func Template(l Labels, controls []Control, cluster, today, suggestedExpiry string) []byte {
	var b strings.Builder

	b.WriteString("# TATAR-Kuber — attestations\n#\n")
	for _, line := range strings.Split(strings.TrimRight(l.Header, "\n"), "\n") {
		if line == "" {
			b.WriteString("#\n")
			continue
		}
		fmt.Fprintf(&b, "# %s\n", line)
	}
	b.WriteString("#\n")
	fmt.Fprintf(&b, "# %s\n\n", fmt.Sprintf(l.Generated, today, suggestedExpiry))

	fmt.Fprintf(&b, "schema_version: %q\n", SchemaVersion)
	if cluster != "" {
		fmt.Fprintf(&b, "cluster: %q\n", cluster)
	}
	b.WriteString("\nattestations:\n")

	if len(controls) == 0 {
		fmt.Fprintf(&b, "  # %s\n", l.NoGaps)
		return []byte(b.String())
	}

	for _, c := range controls {
		b.WriteString("\n")
		fmt.Fprintf(&b, "  # %s — %s  [%s: %s]\n", c.ID, orDash(c.Title), l.Severity, orDash(string(c.Severity)))
		fmt.Fprintf(&b, "  - control: %s\n", c.ID)
		fmt.Fprintf(&b, "    decision:      # %s\n", l.Decision)
		fmt.Fprintf(&b, "    rationale:     # %s\n", l.Rationale)
		fmt.Fprintf(&b, "    attested_by:   # %s\n", l.AttestedBy)
		fmt.Fprintf(&b, "    attested_at: %q\n", today)
		fmt.Fprintf(&b, "    expires:       # %s\n", l.Expires)
		fmt.Fprintf(&b, "    # evidence:    # %s\n", l.Evidence)
		b.WriteString("    #   - \"https://...\"\n")
		fmt.Fprintf(&b, "    # scope:       # %s\n", l.Scope)
	}
	return []byte(b.String())
}
