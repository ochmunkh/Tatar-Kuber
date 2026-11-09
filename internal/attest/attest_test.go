package attest

import (
	"strings"
	"testing"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

var known = map[string]Control{
	"TATAR-NET-004": {ID: "TATAR-NET-004", Title: "Ingress without TLS", Severity: finding.SeverityHigh},
	"TATAR-OPS-001": {ID: "TATAR-OPS-001", Title: "No liveness probe", Severity: finding.SeverityLow},
}

func good() finding.Attestation {
	return finding.Attestation{
		Control:    "TATAR-NET-004",
		Decision:   finding.AttestCompliant,
		Rationale:  "TLS terminates at the edge LB; verified against the config export.",
		AttestedBy: "maintainer",
		AttestedAt: "2026-01-01",
		Expires:    "2027-01-01",
	}
}

func file(as ...finding.Attestation) File {
	return File{SchemaVersion: SchemaVersion, Attestations: as}
}

func errText(errs []error) string {
	var b strings.Builder
	for _, e := range errs {
		b.WriteString(e.Error())
		b.WriteString("\n")
	}
	return b.String()
}

// ── Validate: хаалттай талдаа унах дүрмүүд ───────────────────────────────────

// Хугацаагүй attestation нь хугацаагүй suppression-тай ИЖИЛ согог: нэг удаа
// бичигдээд үүрд үнэн мэт уншигдана. Энэ бол энэ пакетын гол шалтгаан.
func TestValidate_ExpiryIsMandatory(t *testing.T) {
	a := good()
	a.Expires = ""
	errs := Validate(file(a), known)
	if !strings.Contains(errText(errs), "expires") {
		t.Fatalf("хугацаагүй attestation хүлээн авагдлаа:\n%s", errText(errs))
	}
}

// Бичиглэлийн алдаатай control нь ЮУ Ч хамгаалахгүй атлаа хамгаалсан мэт
// харагдана — хамгийн муу хослол. Тиймээс анхааруулга биш, АЛДАА.
func TestValidate_UnknownControlIsAnError(t *testing.T) {
	a := good()
	a.Control = "TATAR-NET-04" // нэг цифр дутуу
	errs := Validate(file(a), known)
	if len(errs) == 0 {
		t.Fatal("бүртгэлд байхгүй control хүлээн авагдлаа")
	}
}

// Нэг control хоёр удаа батлагдвал аль нь хүчинтэйг хэн ч хэлж чадахгүй.
func TestValidate_DuplicateControlIsAnError(t *testing.T) {
	errs := Validate(file(good(), good()), known)
	if !strings.Contains(errText(errs), "аль хэдийн баталсан") {
		t.Fatalf("давхардсан control хүлээн авагдлаа:\n%s", errText(errs))
	}
}

// Үндэслэлгүй, нэргүй баталгаа бол баталгаа биш — аудитад юу ч нотлохгүй.
func TestValidate_RationaleAndSignatureAreMandatory(t *testing.T) {
	a := good()
	a.Rationale, a.AttestedBy = "   ", ""
	got := errText(Validate(file(a), known))
	for _, want := range []string{"rationale", "attested_by"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s шалгагдсангүй:\n%s", want, got)
		}
	}
}

func TestValidate_ExpiryMustFollowAttestedAt(t *testing.T) {
	a := good()
	a.AttestedAt, a.Expires = "2026-05-01", "2026-04-01"
	if len(Validate(file(a), known)) == 0 {
		t.Fatal("expires < attested_at хүлээн авагдлаа")
	}
}

func TestValidate_UnknownDecisionIsRejected(t *testing.T) {
	a := good()
	a.Decision = "probably-fine"
	if len(Validate(file(a), known)) == 0 {
		t.Fatal("танигдахгүй decision хүлээн авагдлаа")
	}
}

// Алдаа бүрийг цуглуулна: 20 control баталж буй хүнийг нэг нэгээр нь
// засуулах нь энэ механизмыг хэрэглэхгүй болгоно.
func TestValidate_CollectsEveryProblemNotJustTheFirst(t *testing.T) {
	a := good()
	a.Decision, a.Rationale, a.AttestedBy, a.Expires = "", "", "", ""
	if n := len(Validate(file(a), known)); n < 4 {
		t.Fatalf("алдааны тоо = %d, 4-өөс цөөнгүй байх ёстой:\n%s", n, errText(Validate(file(a), known)))
	}
}

// ── Expired ─────────────────────────────────────────────────────────────────

// Гараар засагдсан файл gate хүртэл хүрч болно. Тэр үед "хугацаагүй" нь
// "үүрд хүчинтэй" гэж уншигдах ёсгүй.
func TestExpired_MissingExpiryCountsAsExpired(t *testing.T) {
	a := good()
	a.Expires = ""
	if !Expired(a, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("хугацаагүй attestation идэвхтэй гэж тооцогдлоо")
	}
}

// Дуусах өдөр нь ӨӨРӨӨ хүчинтэй: "2026-06-01 хүртэл" гэдэг нь тэр өдрийг
// оруулна. Suppression-ий дүрэмтэй ижил — хоёр механизм зөрвөл хэрэглэгч
// аль нэгэнд нь итгэхээ болино.
func TestExpired_TheExpiryDayItselfIsStillValid(t *testing.T) {
	a := good()
	a.Expires = "2026-06-01"
	if Expired(a, time.Date(2026, 6, 1, 23, 0, 0, 0, time.UTC)) {
		t.Error("дуусах өдөр дууссанд тооцогдлоо")
	}
	if !Expired(a, time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)) {
		t.Error("дууссаны дараа идэвхтэй хэвээр")
	}
}

// ── Apply ───────────────────────────────────────────────────────────────────

// Severity, title хоёр бүртгэлээс ирнэ — attestation файлаар severity солих
// боломж нээвэл тэр нь gate-ийг тойрох чимээгүй зам болно.
func TestApply_FillsTitleAndSeverityFromTheRegistry(t *testing.T) {
	var res finding.ScanResult
	Apply(&res, file(good()), known, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	got := res.Attestations[0]
	if got.Severity != finding.SeverityHigh || got.Title != "Ingress without TLS" {
		t.Fatalf("severity=%q title=%q — бүртгэлээс бөглөгдсөнгүй", got.Severity, got.Title)
	}
}

// Attestation бол scanner-ийн олдвор БИШ: findings-д орохгүй, result_hash
// хөдлөхгүй. Гараар бичсэн хариулт scanner-ийн нотолгоог чимээгүй өөрчилж
// чадахгүй байх ёстой.
func TestApply_LeavesFindingsAndResultHashAlone(t *testing.T) {
	res := finding.ScanResult{
		Findings: []finding.Finding{{CanonicalControl: "TATAR-OPS-001", Resource: "deployment/a"}},
	}
	res.Metadata.ResultHash = "sha256:unchanged"
	Apply(&res, file(good()), known, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if len(res.Findings) != 1 {
		t.Errorf("findings = %d, want 1 — attestation олдвор болж орох ёсгүй", len(res.Findings))
	}
	if res.Metadata.ResultHash != "sha256:unchanged" {
		t.Errorf("result_hash хөдөллөө: %q", res.Metadata.ResultHash)
	}
}

// "10 control батлагдсан" гэдэг нь 3 нь хугацаа дууссан байхад ХУДАЛ
// мэдэгдэл. Тиймээс хугацаа дууссаныг тусад нь тоолно, compliant-д оруулахгүй.
func TestApply_ExpiredIsNotCountedAsCompliant(t *testing.T) {
	a := good()
	a.Expires = "2026-01-05"
	var res finding.ScanResult
	Apply(&res, file(a), known, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))
	s := res.Summary.Attested
	if s.Compliant != 0 || s.Expired != 1 {
		t.Fatalf("compliant=%d expired=%d, want 0/1", s.Compliant, s.Expired)
	}
	if res.Attestations[0].Status != finding.AttestExpired {
		t.Errorf("status=%q, want expired", res.Attestations[0].Status)
	}
}

// §3 — гаралт детерминистик.
func TestApply_SortsByControl(t *testing.T) {
	b := good()
	b.Control = "TATAR-OPS-001"
	var res finding.ScanResult
	Apply(&res, file(b, good()), known, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if res.Attestations[0].Control != "TATAR-NET-004" {
		t.Fatalf("эрэмбэ: %q эхэлж байна", res.Attestations[0].Control)
	}
}
