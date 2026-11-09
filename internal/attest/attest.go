// Package attest implements the manual attestation layer: the answers a human
// signs for controls that no scanner can check.
//
// Яагаад энэ байх ёстой вэ. `docs/coverage.md` нь ямар ч scanner rule
// зурагдаагүй control-ыг нэрээр нь ил гаргадаг. Тэр жагсаалт бол ЗАРЛАГДСАН
// цоорхой — ил зарласан нь шударга, гэхдээ хаагдсан гэсэн үг биш. Scanner
// шалгаж чадахгүй зүйлийг (процесс, гэрээ, байгууллагын хяналт, эсвэл зүгээр л
// автоматжуулах боломжгүй тохиргоо) хүн шалгаж, үндэслэлээ бичиж, нэрээ
// бүртгүүлж, хугацаа тавьж баталдаг — тэр хариулт нь үр дүнд нэгдэж ордог.
//
// Энэ пакетын бүх шийдвэр ХААЛТТАЙ ТАЛДАА унах зарчимтай:
//
//   - хугацаа ЗААВАЛ. Хугацаагүй attestation нь хугацаагүй suppression-тай
//     ижил согог: нэг л удаа бичигдээд үүрд үнэн мэт уншигдана.
//   - бүртгэлд БАЙХГҮЙ control руу заасан attestation бол алдаа, анхааруулга
//     биш. Бичиглэлийн алдаатай мөр нь юу ч хамгаалахгүй атлаа хамгаалсан мэт
//     харагдана — энэ нь хамгийн муу хослол.
//   - үндэслэлгүй, нэргүй attestation хүлээн авахгүй. Гарын үсэггүй баталгаа
//     бол баталгаа биш.
//   - severity-г ЭНД бичдэггүй: canonical бүртгэл бол severity-ийн цорын ганц
//     эх сурвалж. Attestation файлаар severity солих боломж нээвэл тэр нь
//     gate-ийг тойрох чимээгүй зам болно.
package attest

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"gopkg.in/yaml.v3"
)

// DateLayout — бүх огнооны талбарын цорын ганц формат.
const DateLayout = "2006-01-02"

// SchemaVersion — attestation файлын хувилбар.
const SchemaVersion = "1.0"

// File — attestations.yaml.
type File struct {
	SchemaVersion string                `yaml:"schema_version"`
	Cluster       string                `yaml:"cluster,omitempty"`
	Attestations  []finding.Attestation `yaml:"attestations"`
}

// Control — бүртгэлээс attest-д хэрэгтэй хэсэг. canonical пакетыг импортлохгүй
// байхын тулд (attest нь report, policy хоёроос доогуур давхарга) дуудагч тал
// энэ хэлбэрээр дамжуулна.
type Control struct {
	ID       string
	Title    string
	Severity finding.Severity
}

// Load — attestations.yaml уншина. Файл байхгүй бол алдаа: `attest apply`-г
// файлгүй дуудах нь хэрэглээний алдаа, чимээгүй "attestation алга" биш.
func Load(path string) (File, error) {
	// #nosec G304 -- зам нь --attestations туг.
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("attestations parse (%s): %w", path, err)
	}
	return f, nil
}

// Validate — файлыг бүртгэлтэй тулгаж шалгана. АЛДАА БҮРИЙГ цуглуулж буцаана:
// нэг нэгээр нь засуулах нь 20 control баталж буй хүнд утгагүй.
func Validate(f File, known map[string]Control) []error {
	var errs []error
	if f.SchemaVersion != "" && f.SchemaVersion != SchemaVersion {
		errs = append(errs, fmt.Errorf("schema_version %q: энэ хувилбар зөвхөн %q-г уншина", f.SchemaVersion, SchemaVersion))
	}
	if len(f.Attestations) == 0 {
		errs = append(errs, errors.New("attestations хоосон — баталгаажуулах зүйл алга"))
		return errs
	}

	seen := map[string]int{}
	for i, a := range f.Attestations {
		where := fmt.Sprintf("attestations[%d] (%s)", i, orDash(a.Control))

		switch {
		case strings.TrimSpace(a.Control) == "":
			errs = append(errs, fmt.Errorf("%s: control хоосон", where))
		case len(known) > 0:
			if _, ok := known[a.Control]; !ok {
				errs = append(errs, fmt.Errorf("%s: canonical бүртгэлд ийм control алга — "+
					"бичиглэлийн алдаатай мөр юу ч хамгаалахгүй атлаа хамгаалсан мэт харагдана", where))
			}
		}
		if n, dup := seen[a.Control]; dup && a.Control != "" {
			errs = append(errs, fmt.Errorf("%s: %s-г attestations[%d] дээр аль хэдийн баталсан — "+
				"нэг control хоёр удаа батлагдвал аль нь хүчинтэйг хэн ч хэлж чадахгүй", where, a.Control, n))
		} else if a.Control != "" {
			seen[a.Control] = i
		}

		switch a.Decision {
		case finding.AttestCompliant, finding.AttestNonCompliant, finding.AttestNotApplicable:
		case "":
			errs = append(errs, fmt.Errorf("%s: decision хоосон (compliant | non-compliant | not-applicable)", where))
		default:
			errs = append(errs, fmt.Errorf("%s: decision %q танигдахгүй (compliant | non-compliant | not-applicable)", where, a.Decision))
		}

		if strings.TrimSpace(a.Rationale) == "" {
			errs = append(errs, fmt.Errorf("%s: rationale хоосон — үндэслэлгүй баталгаа бол баталгаа биш", where))
		}
		if strings.TrimSpace(a.AttestedBy) == "" {
			errs = append(errs, fmt.Errorf("%s: attested_by хоосон — гарын үсэггүй баталгаа бол баталгаа биш", where))
		}

		at, atOK := parseDate(a.AttestedAt)
		if !atOK {
			errs = append(errs, fmt.Errorf("%s: attested_at %q буруу (YYYY-MM-DD)", where, a.AttestedAt))
		}
		exp, expOK := parseDate(a.Expires)
		switch {
		case strings.TrimSpace(a.Expires) == "":
			errs = append(errs, fmt.Errorf("%s: expires ЗААВАЛ — хугацаагүй attestation нь "+
				"хугацаагүй suppression-тай ижил согог", where))
		case !expOK:
			errs = append(errs, fmt.Errorf("%s: expires %q буруу (YYYY-MM-DD)", where, a.Expires))
		case atOK && !exp.After(at):
			errs = append(errs, fmt.Errorf("%s: expires (%s) нь attested_at (%s)-аас хойш байх ёстой",
				where, a.Expires, a.AttestedAt))
		}
	}
	return errs
}

// Apply — баталгаажсан файлыг scan үр дүнд нэгтгэнэ. Findings-д ГАР ХҮРЭХГҮЙ.
//
// known хоосон биш бол title, severity нь бүртгэлээс бөглөгдөнө. Status нь
// now-той харьцуулж тооцогдоно: хугацаа дууссан бол `expired` — энэ нь
// "алга болсон"-той утгын хувьд адил бөгөөд gate түүнийг хэлнэ.
func Apply(res *finding.ScanResult, f File, known map[string]Control, now time.Time) {
	out := make([]finding.Attestation, 0, len(f.Attestations))
	var sum finding.AttestSummary

	for _, a := range f.Attestations {
		if c, ok := known[a.Control]; ok {
			a.Title = c.Title
			a.Severity = c.Severity
		}
		if Expired(a, now) {
			a.Status = finding.AttestExpired
			sum.Expired++
		} else {
			a.Status = finding.AttestActive
			switch a.Decision {
			case finding.AttestCompliant:
				sum.Compliant++
			case finding.AttestNonCompliant:
				sum.NonCompliant++
			case finding.AttestNotApplicable:
				sum.NotApplicable++
			}
		}
		out = append(out, a)
	}

	// Детерминистик гаралт (§3): control-оор эрэмбэлнэ.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Control < out[j].Control })

	res.Attestations = out
	res.Summary.Attested = &sum
}

// Expired — attestation-ийн хугацаа дууссан эсэх. Хугацаа ЗААГААГҮЙ бол
// дууссанд тооцно: Validate үүнийг аль хэдийн алдаа гэж барьсан байх ёстой ч
// гараар засагдсан файл gate хүртэл хүрч болно, тэр үед "хугацаагүй" нь
// "үүрд хүчинтэй" гэж уншигдах ёсгүй.
func Expired(a finding.Attestation, now time.Time) bool {
	t, ok := parseDate(a.Expires)
	if !ok {
		return true
	}
	return now.After(t.Add(24 * time.Hour)) // дуусах өдрийг оруулж тооцно
}

func parseDate(s string) (time.Time, bool) {
	t, err := time.Parse(DateLayout, strings.TrimSpace(s))
	return t, err == nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
