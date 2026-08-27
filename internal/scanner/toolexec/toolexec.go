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
func Resolve(name string) (string, bool) {
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	cand := filepath.Join(ToolsDir(), name)
	if runtime.GOOS == "windows" && !strings.HasSuffix(cand, ".exe") {
		cand += ".exe"
	}
	if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
		return cand, true
	}
	return "", false
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
	cmd := exec.CommandContext(ctx, path, args...)
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
