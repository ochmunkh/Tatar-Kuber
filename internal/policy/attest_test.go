package policy

import (
	"testing"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func att(control string, d finding.AttestDecision, sev finding.Severity, st finding.AttestStatus) finding.Attestation {
	return finding.Attestation{
		Control: control, Decision: d, Severity: sev, Status: st,
		Rationale: "reviewed", AttestedBy: "maintainer",
		AttestedAt: "2026-01-01", Expires: "2027-01-01",
	}
}

func withAttest(as ...finding.Attestation) finding.ScanResult {
	return finding.ScanResult{Attestations: as, Summary: finding.Summary{RiskScore: 90}}
}

// Scanner үүнийг олж чадахгүй (тийм учраас л attestation хэрэгтэй), гэтэл хүн
// баталсан зөрчил нь scanner-ийн олсон зөрчлөөс дутуу бодит биш.
func TestEvaluate_NonCompliantAttestationFailsTheGate(t *testing.T) {
	p := Policy{FailOn: "high"}
	r := p.Evaluate(withAttest(att("TATAR-NET-004", finding.AttestNonCompliant, finding.SeverityHigh, finding.AttestActive)), time.Now())
	if r.Passed {
		t.Fatal("non-compliant attestation gate-ийг унагасангүй")
	}
	if len(r.AttestViolations) != 1 {
		t.Fatalf("AttestViolations=%d, want 1", len(r.AttestViolations))
	}
	var found bool
	for _, c := range r.Reasons {
		if c == ReasonAttestation {
			found = true
		}
	}
	if !found {
		t.Errorf("Reasons-д %q алга: %v", ReasonAttestation, r.Reasons)
	}
}

// Босго бол босго: attestation түүнийг тойрохгүй.
func TestEvaluate_AttestationBelowThresholdDoesNotFail(t *testing.T) {
	p := Policy{FailOn: "critical"}
	r := p.Evaluate(withAttest(att("TATAR-OPS-001", finding.AttestNonCompliant, finding.SeverityLow, finding.AttestActive)), time.Now())
	if !r.Passed {
		t.Fatal("босгоос доогуур attestation gate-ийг унагалаа")
	}
	if len(r.AttestViolations) != 0 {
		t.Errorf("AttestViolations=%d, want 0", len(r.AttestViolations))
	}
}

// Хугацаа дууссан attestation бол "хаагдсан цоорхой" биш, ДАХИН НЭЭГДСЭН
// цоорхой. Зөрчил болгон тоолохгүй, гэхдээ ЧИМЭЭГҮЙ ч өнгөрөхгүй.
func TestEvaluate_ExpiredAttestationIsSurfacedNotCounted(t *testing.T) {
	p := Policy{FailOn: "high"}
	r := p.Evaluate(withAttest(att("TATAR-NET-004", finding.AttestNonCompliant, finding.SeverityHigh, finding.AttestExpired)), time.Now())
	if len(r.AttestExpired) != 1 {
		t.Fatalf("AttestExpired=%d, want 1", len(r.AttestExpired))
	}
	if len(r.AttestViolations) != 0 {
		t.Errorf("хугацаа дууссан attestation зөрчил болж тоологдлоо")
	}
}

// Мэдэгдэхгүй severity-г "аюулгүй" гэж уншуулах нь §6-гийн эсрэг: чимээгүй
// байдал аюулгүй мэт уншигдах ёсгүй. Тиймээс хоосон severity нь босгоос
// доогуур гэж тооцогдохгүй.
func TestEvaluate_AttestationWithNoSeverityIsNotTreatedAsSafe(t *testing.T) {
	p := Policy{FailOn: "critical"}
	r := p.Evaluate(withAttest(att("TATAR-???", finding.AttestNonCompliant, "", finding.AttestActive)), time.Now())
	if r.Passed {
		t.Fatal("severity мэдэгдэхгүй attestation чимээгүй өнгөрлөө")
	}
}

// compliant / not-applicable нь gate-д нөлөөлөхгүй — тэдгээр нь цоорхойг
// ХААЖ байгаа бөгөөд шинэ зөрчил зарлаагүй.
func TestEvaluate_CompliantAttestationDoesNotFail(t *testing.T) {
	p := Policy{FailOn: "low"}
	r := p.Evaluate(withAttest(
		att("TATAR-NET-004", finding.AttestCompliant, finding.SeverityHigh, finding.AttestActive),
		att("TATAR-OPS-001", finding.AttestNotApplicable, finding.SeverityLow, finding.AttestActive),
	), time.Now())
	if !r.Passed {
		t.Fatalf("compliant attestation gate-ийг унагалаа: %v", r.Reasons)
	}
}
