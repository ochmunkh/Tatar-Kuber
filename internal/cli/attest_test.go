package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

const regPathForAttest = "../../schema/canonical-controls.yaml"

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// `attest create` нь DEFAULT-ААР зөвхөн ШАЛГАГДДАГГҮЙ control-ыг гаргана:
// зөвхөн тэдгээр нь зарлагдсан цоорхой. Шалгагддаг control-ыг давхар
// батлуулах нь хүнийг уншилгүй баталдаг болгоно.
func TestCLI_AttestCreate_ListsOnlyTheUncheckedControls(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "att.yaml")
	if code := attestCreate([]string{"--registry", regPathForAttest, "--out", out}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	body, err := os.ReadFile(out) // #nosec G304 -- тестийн түр хавтас
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "TATAR-NET-004") {
		t.Errorf("шалгагддаггүй control загварт алга:\n%s", got)
	}
	if strings.Contains(got, "- control: TATAR-CON-001") {
		t.Errorf("шалгагддаг control загварт орчихлоо (default-аар орох ёсгүй)")
	}
	// Загвар БӨГЛӨӨГҮЙ гарах ёстой: урьдчилан "compliant" гэж бичсэн загвар нь
	// баталгаажуулалтын бүх утгыг устгана.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "decision:") && !strings.HasPrefix(trimmed, "decision:      #") {
			t.Errorf("decision урьдчилан бөглөгдсөн байна: %q", line)
		}
	}
}

// --all нь шалгагддаг control-уудыг бас оруулна (ISO маягийн бүрэн
// баталгаажуулалтад хэрэгтэй), гэхдээ энэ нь ИЛ сонголт.
func TestCLI_AttestCreate_AllIncludesCheckedControls(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "all.yaml")
	if code := attestCreate([]string{"--registry", regPathForAttest, "--out", out, "--all"}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	body, _ := os.ReadFile(out) // #nosec G304 -- тестийн түр хавтас
	if n := strings.Count(string(body), "- control:"); n < 30 {
		t.Fatalf("--all дээр %d control гарлаа, 30-аас цөөнгүй байх ёстой", n)
	}
}

// Алдаатай файл дээр ЮУ Ч бичигдэхгүй. Хагас хэрэгжсэн баталгаажуулалт нь
// аль control хамгаалагдсаныг хэн ч хэлж чадахгүй төлөв үүсгэнэ.
func TestCLI_AttestApply_InvalidFileWritesNothing(t *testing.T) {
	dir := t.TempDir()
	in := writeScan(t, []finding.Finding{f("TATAR-OPS-001", "deployment/a", "prod", finding.SeverityLow)})
	bad := writeFile(t, dir, "bad.yaml", `
schema_version: "1.0"
attestations:
  - control: TATAR-NET-004
    decision: compliant
    rationale: ""
    attested_by: ""
    attested_at: "2026-01-01"
`)
	outDir := filepath.Join(dir, "out")
	if code := attestApply([]string{"--input", in, "--attestations", bad, "--out-dir", outDir, "--registry", regPathForAttest}); code != 2 {
		t.Fatalf("exit=%d, want 2", code)
	}
	if _, err := os.Stat(filepath.Join(outDir, "scan-result.json")); err == nil {
		t.Fatal("алдаатай байхад үр дүн бичигдлээ")
	}
}

// Attestation нь findings-д ОРОХГҮЙ, result_hash ХӨДЛӨХГҮЙ.
func TestCLI_AttestApply_KeepsFindingsAndResultHash(t *testing.T) {
	dir := t.TempDir()
	res := finding.ScanResult{
		Findings: []finding.Finding{f("TATAR-OPS-001", "deployment/a", "prod", finding.SeverityLow)},
	}
	res.Metadata.ResultHash = "sha256:frozen"
	b, _ := json.Marshal(res)
	in := writeFile(t, dir, "scan-result.json", string(b))

	ok := writeFile(t, dir, "ok.yaml", `
schema_version: "1.0"
attestations:
  - control: TATAR-NET-004
    decision: compliant
    rationale: "TLS terminates at the edge load balancer."
    attested_by: "maintainer"
    attested_at: "2026-01-01"
    expires: "2099-01-01"
`)
	outDir := filepath.Join(dir, "out")
	if code := attestApply([]string{"--input", in, "--attestations", ok, "--out-dir", outDir, "--registry", regPathForAttest}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, "scan-result.json")) // #nosec G304 -- тестийн түр хавтас
	if err != nil {
		t.Fatal(err)
	}
	var got finding.ScanResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 {
		t.Errorf("findings=%d, want 1", len(got.Findings))
	}
	if got.Metadata.ResultHash != "sha256:frozen" {
		t.Errorf("result_hash хөдөллөө: %q", got.Metadata.ResultHash)
	}
	if len(got.Attestations) != 1 || got.Attestations[0].Severity != finding.SeverityHigh {
		t.Fatalf("attestation бүртгэлээс severity аваагүй: %+v", got.Attestations)
	}
	if got.Summary.Attested == nil || got.Summary.Attested.Compliant != 1 {
		t.Errorf("summary.attested буруу: %+v", got.Summary.Attested)
	}
}

func TestCLI_Attest_SubcommandErrors(t *testing.T) {
	if code := cmdAttest(nil); code != 3 {
		t.Errorf("дэд командгүй: exit=%d, want 3", code)
	}
	if code := cmdAttest([]string{"verify"}); code != 3 {
		t.Errorf("танигдахгүй дэд команд: exit=%d, want 3", code)
	}
}

// Глобал `--lang mn attest create` нь энд `attest --lang mn create` болж ирдэг
// тул дэд команд эхний байранд БАЙХГҮЙ. Энэ нь v1.0.3-д `--lang`-тай холбоотой
// гарсан алдааны яг тэр хэв маяг.
func TestCLI_Attest_SubcommandAfterGlobalLang(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "att.yaml")
	if code := cmdAttest([]string{"--lang", "mn", "create", "--registry", regPathForAttest, "--out", out}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("файл бичигдсэнгүй: %v", err)
	}
}
