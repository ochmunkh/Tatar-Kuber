package trivy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// What Trivy actually emits for a secret next to other secrets (captured from
// trivy 0.76.1): Match is censored, but Code.Lines carries the neighbouring
// lines in clear. scan-result.json must contain neither the censored value's
// original nor the neighbours.
const trivySecretReport = `{"ClusterName":"t","Resources":[{"Namespace":"default","Kind":"ConfigMap","Name":"leak","Results":[
{"Target":"cm.yaml","Class":"secret","Secrets":[{"RuleID":"github-pat","Category":"GitHub","Severity":"CRITICAL","Title":"GitHub Personal Access Token",
 "StartLine":7,"EndLine":7,"Match":"  gh: ****************************************",
 "Code":{"Lines":[
  {"Number":5,"Content":"  aws_access_key_id: AKIAIOSFODNN7EXAMPLE","IsCause":false},
  {"Number":6,"Content":"  aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","IsCause":false},
  {"Number":7,"Content":"  gh: ****************************************","IsCause":true}]}}]}]}]}`

func normalize(t *testing.T, raw string) []byte {
	t.Helper()
	reg, err := canonical.Load("../../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(reg.NewResolver()).Normalize(scanner.RawResult{Scanner: "trivy", Format: "json", Data: []byte(raw)})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("expected a secret finding")
	}
	out, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNormalize_SecretNeighboursNeverReachTheFindings(t *testing.T) {
	out := string(normalize(t, trivySecretReport))
	for _, leaked := range []string{"wJalrXUtnFEMI", "AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key"} {
		if strings.Contains(out, leaked) {
			t.Errorf("findings must not carry %q from the surrounding code lines", leaked)
		}
	}
	if !strings.Contains(out, "****************") {
		t.Error("the censored match is the evidence and should be kept")
	}
}

func TestNormalize_UncensoredMatchIsWithheld(t *testing.T) {
	raw := strings.Replace(trivySecretReport,
		`"Match":"  gh: ****************************************"`,
		`"Match":"  gh: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"`, 1)
	out := string(normalize(t, raw))
	if strings.Contains(out, "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789") {
		t.Fatal("a match the scanner did not censor must not be copied into the result")
	}
	if !strings.Contains(out, "withheld") {
		t.Error("the report should say the match was withheld")
	}
}
