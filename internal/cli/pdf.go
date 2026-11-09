package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
	auditrep "github.com/ochmunkh/tatar-kuber/internal/report/audit"
)

// PDF хөрвүүлэлт.
//
// ЗАРЧИМ: TATAR-Kuber нь PDF бичдэггүй. Хуудаслалтад бэлэн HTML гаргаад,
// системд БАЙГАА хөрвүүлэгчээр PDF болгоно. Яагаад:
//
//   - Go-гийн PDF сан нэмэх нь гадаад хамаарлыг нэгээс хоёр болгоно. Энэ
//     төслийн хувьд хамаарлын тоо бол нийлүүлэлтийн сүлжээний шинж чанар.
//   - Кирилл үсэгт шрифт шигтгэх шаардлагатай болно — лицензийн болон
//     хэмжээний асуудал, мөн "яагаад монгол үсэг хоосон квадрат болов" гэсэн
//     чимээгүй эвдрэлийн шинэ төрөл.
//
// ХАМГИЙН ЧУХАЛ: хөрвүүлэгч олдохгүй бол ИЛ ТАТГАЛЗАНА. Хоосон эсвэл дутуу
// PDF гаргах, эсвэл "болов" гэж хэвлээд юу ч хийхгүй байх нь энэ төслийн
// эсэргүүцдэг яг тэр зан — `update`-ийн Windows дээрх зан үйлтэй ижил.

type converter struct {
	Name string
	Path string
	Args func(htmlPath, pdfPath string) []string
}

// chromiumNames / wkhtmlNames — PATH дээр хайх нэрс.
var chromiumNames = []string{"chromium", "chromium-browser", "google-chrome", "chrome", "msedge"}

// windowsCandidates — Windows дээр хөтөч PATH-д ихэвчлэн байдаггүй.
var windowsCandidates = []string{
	`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
}

// findConverter — HTML -> PDF хөрвүүлэгч хайна. Олдохгүй бол nil.
func findConverter() *converter {
	for _, n := range chromiumNames {
		if p, err := exec.LookPath(n); err == nil {
			return chromium(n, p)
		}
	}
	if runtime.GOOS == "windows" {
		for _, p := range windowsCandidates {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return chromium(filepath.Base(p), p)
			}
		}
	}
	if p, err := exec.LookPath("wkhtmltopdf"); err == nil {
		return &converter{Name: "wkhtmltopdf", Path: p, Args: func(h, o string) []string {
			return []string{"--enable-local-file-access", "--print-media-type", h, o}
		}}
	}
	return nil
}

func chromium(name, path string) *converter {
	return &converter{Name: name, Path: path, Args: func(h, o string) []string {
		return []string{
			"--headless", "--disable-gpu", "--no-sandbox",
			"--no-pdf-header-footer",
			"--print-to-pdf=" + o,
			"file://" + filepath.ToSlash(h),
		}
	}}
}

// convertedNames — татгалзах мессежид жагсаах нэрс.
func convertedNames() string {
	return strings.Join(append(append([]string{}, chromiumNames...), "wkhtmltopdf"), ", ")
}

// renderPDF — htmlPath-аас pdfPath үүсгэнэ.
func renderPDF(c *converter, htmlPath, pdfPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// #nosec G204 -- c.Path нь LookPath/os.Stat-аар батлагдсан хөрвүүлэгч,
	// аргументууд нь энэ пакетын өөрийн үүсгэсэн түр файлын зам.
	cmd := exec.CommandContext(ctx, c.Path, c.Args(htmlPath, pdfPath)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", c.Name, err, strings.TrimSpace(string(out)))
	}
	st, serr := os.Stat(pdfPath)
	if serr != nil || st.Size() == 0 {
		// Хөрвүүлэгч 0 буцаасан ч файл үүсгээгүй байж болно. "Болов" гэж
		// хэвлээд хоосон файл үлдээх нь хамгийн муу төгсгөл.
		return fmt.Errorf("%s: PDF үүсээгүй (%s)", c.Name, pdfPath)
	}
	return nil
}

// renderAuditPDF — аудитын тайланг PDF болгоно.
//
// Дараалал нь зориуд: хөрвүүлэгчийг ЭХЛЭЭД шалгана. Тайланг бичээд сүүлд нь
// "хөрвүүлэгч алга" гэж хэлэх нь хагас үр дүн үлдээнэ.
func renderAuditPDF(res finding.ScanResult, target, lang, failOn string) int {
	c := findConverter()
	if c == nil {
		errln(msg("report.pdf.noconverter", convertedNames()))
		return 2
	}

	tmp, err := os.MkdirTemp("", "tatar-audit-")
	if err != nil {
		errln(err)
		return 2
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	htmlPath := filepath.Join(tmp, "audit.html")
	f, err := os.Create(htmlPath) // #nosec G304 -- өөрийн үүсгэсэн түр хавтас
	if err != nil {
		errln(err)
		return 2
	}
	if err := auditrep.Render(f, res, lang); err != nil {
		_ = f.Close()
		errln(msg("report.render.failed"), err)
		return 2
	}
	if err := f.Close(); err != nil {
		errln(err)
		return 2
	}

	abs, err := filepath.Abs(target)
	if err != nil {
		errln(err)
		return 2
	}
	if dir := filepath.Dir(abs); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			errln(err)
			return 2
		}
	}
	if err := renderPDF(c, htmlPath, abs); err != nil {
		errln(msg("report.pdf.failed", c.Name), err)
		return 2
	}
	fmt.Println(msg("report.pdf.wrote", target, c.Name))

	if failOn != "" {
		if th, ok := parseSeverityThreshold(failOn, "--fail-on"); ok && exceedsThreshold(res, th) {
			return 1
		}
	}
	return 0
}
