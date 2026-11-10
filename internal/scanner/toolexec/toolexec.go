// Package toolexec — гадаад scanner CLI-уудыг (trivy, kubescape, popeye ...)
// ажиллуулах хуваалцсан туслах. Live Mode B-ийн цөм: TATAR-Kuber өөрөө scan
// хийхгүй — эдгээр хэрэгслийг зохион байгуулж, гаралтыг нь normalize хийдэг.
//
// Гол зарчим:
//   - Хэрэгслийг PATH эсвэл ~/.tatar-kuber/tools/-оос хайна.
//   - context-ийн timeout-ыг хүндэтгэнэ (exec.CommandContext автоматаар таслана).
//   - Scanner-ууд асуудал олоход non-zero exit буцааж болзошгүй тул exit code-ыг
//     алдаа гэж үзэхгүй — хүчинтэй JSON гаралт байвал амжилт гэж тооцно.
package toolexec

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// ToolsDir — TATAR-Kuber-ийн татаж авсан хэрэгслүүдийн лавлах.
func ToolsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".tatar-kuber", "tools")
	}
	return filepath.Join(home, ".tatar-kuber", "tools")
}

// Resolve — binary-г PATH эсвэл ToolsDir-ээс хайж бүтэн замыг буцаана.
//
// ToolsDir доторх БАЙРЛАЛ нь хоёр хэлбэртэй байж болно:
//
//	<tools>/<name>            — гараар тавьсан нэг файл
//	<tools>/<name>/<...>      — `tatar-kuber update`-ийн задалсан архив
//
// Хоёр дахийг нь мэдэхгүй байсан нь бодит согог байв: `update` амжилттай
// суулгаад `doctor` нь "суугаагүй" гэж хэлдэг байсан — хоёулаа "ажиллаж"
// байгаа мөртлөө хоорондоо зөрчилдөж, улаан болдоггүй. CI нь scanner-уудаа
// install.sh-ээр /usr/local/bin руу суулгадаг байсан тул энэ зам огт
// шалгагддаггүй байсан (2026-11-10-нд пиннэсэн scanner-ийг CI-д анх
// ажиллуулахад илрэв).
func Resolve(name string) (string, bool) {
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	base := filepath.Join(ToolsDir(), name)
	for _, cand := range []string{base, filepath.Join(base, name)} {
		if p, ok := executableAt(cand); ok {
			return p, true
		}
	}
	// Архив нь binary-г гүнд нь савласан байж болно (findBinary нь суулгах
	// үед нэрээр нь хайдаг — энд ч мөн адил).
	if p, ok := walkFor(base, name); ok {
		return p, true
	}
	return "", false
}

// executableAt — зам нь (Windows дээр .exe дагавартай нь) бодит файл эсэх.
func executableAt(path string) (string, bool) {
	cands := []string{path}
	if runtime.GOOS == "windows" && !strings.HasSuffix(path, ".exe") {
		cands = []string{path + ".exe", path}
	}
	for _, c := range cands {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
			return c, true
		}
	}
	return "", false
}

// walkFor — root доороос <name> (эсвэл <name>.exe) нэртэй файлыг хайна.
// Хамгийн гүехэн нь ялна: багц нь хэрэгслийн нэртэй сан агуулж байвал дээд
// түвшний ажиллуулах файл үлдэнэ. Энэ нь internal/update.findBinary-ийн
// дүрэмтэй санаатайгаар ижил.
func walkFor(root, name string) (string, bool) {
	want := map[string]bool{name: true}
	if runtime.GOOS == "windows" {
		want[name+".exe"] = true
	}
	best, bestDepth := "", -1
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !want[d.Name()] || !d.Type().IsRegular() {
			return nil //nolint:nilerr // алдаатай мөчир нь "олдсонгүй", зогсоох шалтгаан биш
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		dep := strings.Count(rel, string(filepath.Separator))
		if bestDepth < 0 || dep < bestDepth {
			best, bestDepth = path, dep
		}
		return nil
	})
	return best, best != ""
}

// Available — binary олдвол (true, nil). Олдохгүй бол (false, nil) —
// энэ нь алдаа биш, зүгээр л тухайн scanner идэвхгүй гэсэн үг.
func Available(name string) (bool, error) {
	_, ok := Resolve(name)
	return ok, nil
}

// Result — командын гаралт.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Run — командыг ажиллуулж stdout/stderr/exit code-ыг буцаана.
// extraEnv нь os.Environ() дээр нэмэгдэнэ (ж: "KUBECONFIG=/path").
func Run(ctx context.Context, name string, args []string, extraEnv ...string) (Result, error) {
	path, ok := Resolve(name)
	if !ok {
		return Result{ExitCode: -1}, fmt.Errorf("%s: олдсонгүй (PATH эсвэл %s шалгана уу)", name, ToolsDir())
	}
	// Аюулгүй: shell дуудлагагүй (execve шууд), path нь PATH/ToolsDir-ээс шийдэгдсэн,
	// args нь тогтмол флаг + тодорхой утга — shell metachar-ийн injection боломжгүй.
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- see comment above
	cmd.Env = append(os.Environ(), extraEnv...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	res := Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	if err != nil {
		var ee *exec.ExitError
		if ok := asExit(err, &ee); ok {
			res.ExitCode = ee.ExitCode()
			// non-zero exit нь findings байгаа гэсэн үг байж болно — алдаа биш.
			return res, nil
		}
		// binary ажиллуулах боломжгүй / context таслагдсан / бусад.
		return res, err
	}
	return res, nil
}

func asExit(err error, target **exec.ExitError) bool {
	for err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

var semver = regexp.MustCompile(`\d+\.\d+\.\d+`)

// Version — хэрэгслийн хувилбарын командыг ажиллуулж semver-ийг гаргаж авна.
func Version(ctx context.Context, name string, args ...string) (string, error) {
	res, err := Run(ctx, name, args)
	txt := string(res.Stdout)
	if txt == "" {
		txt = string(res.Stderr) // зарим хэрэгсэл version-оо stderr рүү бичдэг
	}
	if m := semver.FindString(txt); m != "" {
		return m, nil
	}
	if err != nil {
		return "", err
	}
	if line := strings.TrimSpace(firstLine(txt)); line != "" {
		return line, nil
	}
	return "", fmt.Errorf("%s: хувилбар танигдсангүй", name)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
