package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// Тайлан бол кластерын сул талуудыг ХҮН УНШИХААР хэлбэрт хөрвүүлсэн файл:
// имэйлээр явдаг, архивт үлддэг. scan-result.json-ийг 0600 болгоод тайланг
// 0644 орхих нь хамгаалалтыг зөвхөн машины уншдаг хувилбарт хэрэглэсэн хэрэг.
//
// Windows дээр POSIX-ийн эрхийн бит утгагүй тул алгасна.
func TestReport_OutputIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX эрхийн бит Windows дээр хамаарахгүй")
	}
	dir := t.TempDir()
	in := writeScan(t, []finding.Finding{f("TATAR-CON-001", "deployment/a", "prod", finding.SeverityHigh)})

	for _, format := range []string{"html", "audit", "sarif", "json"} {
		out := filepath.Join(dir, "report."+format)
		if code := cmdReport([]string{"--input", in, "--format", format, "--out", out}); code != 0 {
			t.Fatalf("%s: exit=%d", format, code)
		}
		st, err := os.Stat(out)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if mode := st.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s: эрх %04o — бусад хэрэглэгч уншиж чадна", format, mode)
		}
	}
}
