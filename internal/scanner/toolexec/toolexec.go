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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ochmunkh/tatar-kuber/internal/safeio"
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
	return resolveInTools(name)
}

// resolveInTools — only the TATAR-Kuber tools directory, never PATH.
func resolveInTools(name string) (string, bool) {
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
	cmd.Env = childEnv(os.Environ(), extraEnv)
	out := &capBuffer{max: maxStdout}
	errb := &capBuffer{max: maxStderr, drop: true}
	cmd.Stdout = out
	cmd.Stderr = errb
	err := cmd.Run()

	res := Result{Stdout: out.buf.Bytes(), Stderr: errb.buf.Bytes()}
	if errors.Is(err, ErrOutputTooLarge) || out.buf.Len() >= maxStdout {
		return res, fmt.Errorf("%s: %w (limit %d MiB)", name, ErrOutputTooLarge, maxStdout>>20)
	}
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
		return plainVersionLine(line), nil
	}
	return "", fmt.Errorf("%s: хувилбар танигдсангүй", name)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ── Which binary actually ran ────────────────────────────────────────────────

// Source says where Resolve found the binary.
const (
	SourcePath  = "path"  // found on PATH
	SourceTools = "tools" // found in ~/.tatar-kuber/tools (what `update` installs)
)

// Binary describes the executable a scan would run. It exists so the report can
// say WHICH binary produced a result: Resolve prefers PATH, so a scanner that
// `update` pinned and verified can be silently shadowed by another copy.
type Binary struct {
	Path   string
	Source string // SourcePath | SourceTools
	SHA256 string // hex digest of the file at Path ("" if it could not be read)
	// Shadowed is set when the binary came from PATH although a copy also
	// exists in the tools directory -- the one `update` pins and verifies.
	Shadowed bool
	// PinnedSHA256 is the digest `update` recorded (tools.lock.yaml,
	// installed_sha256) for the copy in the tools directory; "" when the lock
	// holds none (older lock, hand-placed binary, or a PATH binary).
	PinnedSHA256 string
	// Mismatch is set when a tools-directory binary no longer hashes to
	// PinnedSHA256: it was replaced or modified after `update` verified it.
	Mismatch bool
	// Warning is a ready-to-print sentence for the Shadowed case.
	Warning string
}

// Describe resolves name exactly as Run will and reports what it found.
func Describe(name string) (Binary, bool) {
	p, ok := Resolve(name)
	if !ok {
		return Binary{}, false
	}
	b := Binary{Path: p, Source: SourcePath, SHA256: fileSHA256(p)}
	if inToolsDir(p) {
		b.Source = SourceTools
		if pin := lockedInstalledSHA(name); pin != "" {
			b.PinnedSHA256 = pin
			if b.SHA256 != pin {
				b.Mismatch = true
				b.Warning = fmt.Sprintf("%s at %s does not match the SHA-256 recorded by `update` (%s, now %s); it was changed after installation. Run `tatar-kuber update` to reinstall the pinned copy",
					name, p, short(pin), short(b.SHA256))
			}
		}
		return b, true
	}
	if tp, ok := resolveInTools(name); ok && !samePath(tp, p) {
		b.Shadowed = true
		b.Warning = fmt.Sprintf("%s was taken from PATH (%s); the pinned copy in %s was NOT used", name, p, ToolsDir())
	}
	return b, true
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// lockedInstalledSHA — the installed_sha256 `update` wrote for name into
// tools.lock.yaml (the file beside the tools directory), or "" if there is none.
func lockedInstalledSHA(name string) string {
	data, err := safeio.ReadFile(filepath.Join(filepath.Dir(ToolsDir()), "tools.lock.yaml"), safeio.MaxConfig)
	if err != nil {
		return ""
	}
	var l struct {
		Tools map[string]struct {
			InstalledSHA256 string `yaml:"installed_sha256"`
		} `yaml:"tools"`
	}
	if yaml.Unmarshal(data, &l) != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(l.Tools[name].InstalledSHA256))
}

func inToolsDir(p string) bool {
	rel, err := filepath.Rel(ToolsDir(), p)
	return err == nil && rel != "." && filepath.IsLocal(rel)
}

func samePath(a, b string) bool {
	if ea, err := filepath.EvalSymlinks(a); err == nil {
		a = ea
	}
	if eb, err := filepath.EvalSymlinks(b); err == nil {
		b = eb
	}
	return a == b
}

func fileSHA256(path string) string {
	f, err := os.Open(path) // #nosec G304 -- path was resolved by Resolve
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ── What the scanner is allowed to inherit ───────────────────────────────────

// secretEnv — variables that carry a forge or CI credential. No scanner needs
// them to scan a manifest or a cluster, and every scanner is a third-party
// program that may talk to the network, so they are not handed over. Cloud
// credentials (AWS_*, GOOGLE_*, AZURE_*) are deliberately NOT here: a kubeconfig
// `exec` plugin needs them to authenticate to the cluster being scanned.
var secretEnv = map[string]bool{
	"GITHUB_TOKEN":                   true,
	"GH_TOKEN":                       true,
	"GITHUB_PAT":                     true,
	"ACTIONS_RUNTIME_TOKEN":          true,
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN": true,
	"ACTIONS_ID_TOKEN_REQUEST_URL":   true,
	"HOMEBREW_TAP_GITHUB_TOKEN":      true,
	"GITLAB_TOKEN":                   true,
	"CI_JOB_TOKEN":                   true,
	"BITBUCKET_TOKEN":                true,
}

// ForwardEnvVar names the escape hatch (the variable's own name is TATAR_PASS_ENV): a comma-separated list of variables that
// are handed to the scanners even though they are on the list above.
const ForwardEnvVar = "TATAR_PASS_ENV"

// StrictEnvVar — set to "1" to switch the scanners' environment from the
// default deny-list (drop forge credentials) to an allow-list (drop everything
// not needed to run). Opt-in because a kubeconfig `exec` plugin may rely on
// variables only the user knows about; TATAR_PASS_ENV releases those by name.
const StrictEnvVar = "TATAR_STRICT_ENV"

var strictNames = map[string]bool{
	"PATH": true, "HOME": true, "USERPROFILE": true, "USER": true, "LOGNAME": true,
	"TMPDIR": true, "TMP": true, "TEMP": true, "TERM": true, "LANG": true, "SHELL": true,
	"KUBECONFIG": true, "SYSTEMROOT": true, "SYSTEMDRIVE": true, "WINDIR": true,
	"COMSPEC": true, "PATHEXT": true, "APPDATA": true, "LOCALAPPDATA": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "REQUESTS_CA_BUNDLE": true,
	"BC_SKIP_MAPPING": true, ForwardEnvVar: true, StrictEnvVar: true,
}

var strictPrefixes = []string{"LC_", "XDG_", "TRIVY_", "KUBESCAPE_", "POPEYE_", "CHECKOV_", "BC_"}

func strictAllowed(name string) bool {
	u := strings.ToUpper(name)
	if strictNames[u] {
		return true
	}
	for _, p := range strictPrefixes {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

// childEnv — os.Environ() minus the credentials in secretEnv, plus extra.
// extra wins over the inherited value, as before.
func childEnv(environ, extra []string) []string {
	pass := map[string]bool{}
	for _, n := range strings.Split(lookupEnv(environ, ForwardEnvVar), ",") {
		if n = strings.TrimSpace(n); n != "" {
			pass[n] = true
		}
	}
	strict := lookupEnv(environ, StrictEnvVar) == "1"
	out := make([]string, 0, len(environ)+len(extra))
	for _, kv := range environ {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if strict {
			// Allow-list mode: only what a scanner needs to run, plus what the
			// user named in TATAR_PASS_ENV. Cloud credentials are NOT included;
			// a kubeconfig exec plugin that needs them must be listed there.
			if !strictAllowed(name) && !pass[name] {
				continue
			}
		} else if secretEnv[strings.ToUpper(name)] && !pass[name] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

func lookupEnv(environ []string, key string) string {
	for _, kv := range environ {
		if strings.HasPrefix(kv, key+"=") {
			return kv[len(key)+1:]
		}
	}
	return ""
}

// ── Bounded output ───────────────────────────────────────────────────────────

// maxStdout bounds what a scanner may write to stdout. Real cluster reports are
// tens of MiB; the cap stops a hostile manifest or a broken scanner from
// exhausting memory. A variable only so a test can lower it.
var maxStdout = 256 << 20

const maxStderr = 8 << 20

// ErrOutputTooLarge — the scanner wrote more than the cap.
var ErrOutputTooLarge = errors.New("scanner output exceeds the size limit")

// capBuffer is a bytes.Buffer that refuses to grow past max. Once full it fails
// the write, which closes the pipe and ends the scanner instead of buffering on.
type capBuffer struct {
	buf  bytes.Buffer
	max  int
	drop bool // true: silently discard the excess (stderr) instead of failing
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		if c.drop {
			return len(p), nil
		}
		return 0, ErrOutputTooLarge
	}
	return c.buf.Write(p)
}

// ── Arguments that come from the user ────────────────────────────────────────

// ValidateValue refuses a user-supplied value (a kube context, a namespace) that
// could be read as a flag by the scanner or that contains control characters.
func ValidateValue(label, v string) error {
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("%s %q starts with '-' and would be read as a scanner flag", label, v)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

var plainVersion = regexp.MustCompile(`^[A-Za-z0-9 ._+()/,:-]{1,80}$`)

// plainVersionLine — a version line is kept only if it looks like one. The text
// comes from the scanner binary itself; whatever else a (substituted or broken)
// binary prints must not be copied into the report as if it were a version.
func plainVersionLine(s string) string {
	if plainVersion.MatchString(s) {
		return s
	}
	return "unparsed"
}
