// Package orchestrator wires the full TATAR-Kuber pipeline:
// raw scanner output -> normalize -> dedup -> blind-shot -> score -> ScanResult.
package orchestrator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/blindshot"
	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/dedup"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/risk"
	"github.com/ochmunkh/tatar-kuber/internal/rollup"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

const tatarVersion = "1.0.2"

// Pipeline — scanner-агностик цөм.
type Pipeline struct {
	reg      *canonical.Registry
	adapters []scanner.ScannerAdapter
	resolver *canonical.Resolver // сонголт: unmapped rule статистик авахад
}

// New — registry + adapter-уудаас pipeline үүсгэнэ.
func New(reg *canonical.Registry, adapters ...scanner.ScannerAdapter) *Pipeline {
	return &Pipeline{reg: reg, adapters: adapters}
}

// WithResolver — adapter-уудад тарьсан resolver-ийг pipeline-д мэдэгдэнэ;
// ингэснээр canonical зураглалгүй (хаягдсан) rule-ууд scanner_runs-д тоологдоно.
func (p *Pipeline) WithResolver(rs *canonical.Resolver) *Pipeline {
	p.resolver = rs
	return p
}

// Adapters — бүртгэлтэй adapter-уудыг буцаана (doctor/танилцах зорилгоор).
func (p *Pipeline) Adapters() []scanner.ScannerAdapter { return p.adapters }

// Meta — scan-ий тодорхойлолт.
type Meta struct {
	ClusterName string
	ScanMode    string               // local | remote
	Lang        string               // тайлангийн хэл: en (default) | mn
	Inventory   map[string]int       // cluster объектын тоо (сонголт)
	Runs        []finding.ScannerRun // Collect-оос ирсэн scanner явц (сонголт; Process баяжуулна)
	NoRollup    bool                 // true бол Pod -> controller зөөлтийг хийхгүй
}

// timeoutHinter — adapter өөрийн зөвлөмж timeout-оо илэрхийлж болно (сонголт).
// Scanner тус бүр өөр өөр удах тул (Trivy image scan удаан, Popeye богино)
// adapter энэ interface-ийг хэрэгжүүлбэл Run түүнийг хүндэтгэнэ.
type timeoutHinter interface {
	Timeout() time.Duration
}

// defaultAdapterTimeout — adapter зөвлөмжгүй, Target.Timeout-гүй үеийн нөөц хугацаа.
const defaultAdapterTimeout = 4 * time.Minute

// adapterTimeout — тухайн adapter-т ноогдох хугацаа:
// adapter-ийн зөвлөмж > Target.Timeout > default.
func adapterTimeout(a scanner.ScannerAdapter, t scanner.Target) time.Duration {
	if h, ok := a.(timeoutHinter); ok && h.Timeout() > 0 {
		return h.Timeout()
	}
	if t.Timeout > 0 {
		return t.Timeout
	}
	return defaultAdapterTimeout
}

// Run — Collect + Process (хуучин API, тест/CLI-д хялбар зам).
func (p *Pipeline) Run(ctx context.Context, t scanner.Target, m Meta) (finding.ScanResult, error) {
	raws, runs := p.Collect(ctx, t)
	m.Runs = runs
	return p.Process(raws, m)
}

// Collect — Available adapter бүрийг ЗЭРЭГ (concurrent) ажиллуулж raw цуглуулна.
// Онцлог:
//   - adapter бүр өөрийн goroutine + өөрийн context.WithTimeout (scanner тус бүр өөр).
//   - graceful degradation: нэг scanner унах/timeout болоход бусад нь ҮРГЭЛЖИЛНЭ.
//   - ГЭХДЭЭ ЧИМЭЭГҮЙ БИШ: adapter бүрийн явц (ok / unavailable / unsupported /
//     error / timeout, хугацаа, алдааны текст) ScannerRun болж буцна — тайланд орно.
//   - detrministik гаралт: үр дүнг adapter бүртгэлийн дарааллаар индексжүүлнэ.
func (p *Pipeline) Collect(ctx context.Context, t scanner.Target) ([]scanner.RawResult, []finding.ScannerRun) {
	raws := make([]scanner.RawResult, len(p.adapters))
	runs := make([]finding.ScannerRun, len(p.adapters))
	ok := make([]bool, len(p.adapters))

	var wg sync.WaitGroup
	for i, a := range p.adapters {
		runs[i] = finding.ScannerRun{Scanner: a.Name()}
		if !a.Supports(t.Mode) {
			runs[i].Status = "unsupported"
			runs[i].Error = "scanner does not support mode " + string(t.Mode)
			continue
		}
		if avail, _ := a.Available(); !avail {
			runs[i].Status = "unavailable"
			runs[i].Error = "binary not found in PATH or ~/.tatar-kuber/tools"
			continue
		}
		wg.Add(1)
		go func(i int, a scanner.ScannerAdapter) {
			defer wg.Done()
			// Хувилбарыг scan-аас ӨМНӨ, богино тусдаа context-оор авна
			// (scan timeout болсон ч хувилбар тайланд үлдэнэ).
			vctx, vcancel := context.WithTimeout(ctx, 30*time.Second)
			ver, _ := a.Version(vctx)
			vcancel()
			runs[i].Version = ver

			// Тус бүр өөрийн context — нэгнийх нь timeout бусдад нөлөөлөхгүй.
			actx, cancel := context.WithTimeout(ctx, adapterTimeout(a, t))
			defer cancel()

			started := time.Now()
			raw, err := a.Scan(actx, t)
			runs[i].DurationMS = time.Since(started).Milliseconds()
			if err != nil {
				runs[i].Status = "error"
				if actx.Err() == context.DeadlineExceeded {
					runs[i].Status = "timeout"
				}
				runs[i].Error = truncate(err.Error(), 500)
				return // graceful degradation: бусад adapter үргэлжилнэ
			}
			raw.Version = ver
			raw.Duration = time.Since(started)
			runs[i].Status = "ok"
			runs[i].RawBytes = len(raw.Data)
			raws[i] = raw
			ok[i] = true
		}(i, a)
	}
	wg.Wait()

	collected := make([]scanner.RawResult, 0, len(raws))
	for i := range raws {
		if ok[i] {
			collected = append(collected, raws[i])
		}
	}
	return collected, runs
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Process — цуглуулсан raw үр дүнгээс бүрэн ScanResult байгуулна.
// (Тест болон CLI хоёулаа энэ замыг ашиглана.)
func (p *Pipeline) Process(raws []scanner.RawResult, m Meta) (finding.ScanResult, error) {
	started := time.Now().UTC()

	byName := map[string]scanner.ScannerAdapter{}
	for _, a := range p.adapters {
		byName[a.Name()] = a
	}

	// scanner_runs: Collect-оос ирсэн бол баяжуулна, үгүй бол (offline ingest,
	// тест) raw бүрд "ingested" бичлэг үүсгэнэ.
	runIdx := map[string]int{}
	runs := append([]finding.ScannerRun(nil), m.Runs...)
	for i := range runs {
		runIdx[runs[i].Scanner] = i
	}
	runFor := func(name string) *finding.ScannerRun {
		if i, ok := runIdx[name]; ok {
			return &runs[i]
		}
		runs = append(runs, finding.ScannerRun{Scanner: name, Status: "ingested"})
		runIdx[name] = len(runs) - 1
		return &runs[len(runs)-1]
	}
	if p.resolver != nil {
		p.resolver.ResetUnmapped()
	}

	var all []finding.Finding
	versions := map[string]string{}
	for _, raw := range raws {
		a, ok := byName[raw.Scanner]
		if !ok {
			continue
		}
		versions[raw.Scanner] = raw.Version
		r := runFor(raw.Scanner)
		if r.Version == "" {
			r.Version = raw.Version
		}
		if r.RawBytes == 0 {
			r.RawBytes = len(raw.Data)
		}
		fs, err := a.Normalize(raw)
		if err != nil {
			// graceful degradation — гэхдээ ил: parse алдаа тайланд бичигдэнэ
			r.Status = "parse_error"
			r.Error = truncate(err.Error(), 500)
			continue
		}
		r.Findings = len(fs)
		if p.resolver != nil {
			r.UnmappedRules, r.UnmappedCount = p.resolver.Unmapped(raw.Scanner)
		}
		all = append(all, fs...)
	}

	// Pod хэмжээний finding-ийг эзэмшигч controller руу зөөнө (dedup-аас ӨМНӨ):
	// нэг pod template-ийн зөрчил Popeye-д pod, Trivy/Kubescape-д deployment
	// болж хоёр удаа тоологдож, эрсдэлийн оноог хөөрөгддөг.
	rolled, rl := all, rollup.Result{}
	if !m.NoRollup {
		rolled, rl = rollup.Apply(all)
	}
	deduped := dedup.Deduplicate(rolled, p.reg)
	shot := blindshot.Apply(deduped, p.reg)
	scored, score, band, breakdown := risk.ApplyScores(shot)
	sortBySeverity(scored) // Critical -> High -> Medium -> Low -> Info (тайланд эрэмбэ)

	lang := m.Lang
	if lang == "" {
		lang = "en"
	}
	applyLang(scored, p.reg, lang) // title/remediation-ыг сонгосон хэлээр

	res := finding.ScanResult{
		SchemaVersion: "1.0",
		Metadata: finding.Metadata{
			ScanID:          randID(),
			ClusterName:     m.ClusterName,
			ScanMode:        m.ScanMode,
			Lang:            lang,
			TatarVersion:    tatarVersion,
			ScannerVersions: versions,
			StartedAt:       started.Format(time.RFC3339),
			FinishedAt:      time.Now().UTC().Format(time.RFC3339),
		},
		Summary:  summarize(scored, score, band),
		Findings: scored,
	}
	bd := breakdown
	res.Summary.RiskBreakdown = &bd // оноог хэрхэн гаргасны explainable задаргаа
	res.Metadata.ResultHash = resultHash(scored)
	res.Metadata.Inventory = m.Inventory
	res.Metadata.ScannerRuns = runs
	if rl.Moved > 0 {
		res.Metadata.Rollup = &finding.RollupInfo{Moved: rl.Moved, Pods: rl.Pods}
	}
	return res, nil
}

// Problems — scanner_runs дотроос анхаарал татах (finding өгөөгүй/унасан) бичлэгүүд.
// CLI эдгээрийг stderr-т анхааруулга болгон хэвлэнэ — "0 finding" чимээгүй өнгөрөхгүй.
func Problems(runs []finding.ScannerRun) []string {
	var out []string
	for _, r := range runs {
		switch r.Status {
		case "ok", "ingested":
			if r.Findings == 0 {
				msg := r.Scanner + ": ажилласан ч 0 finding normalize хийгдсэнгүй"
				if r.UnmappedCount > 0 {
					msg += " (canonical зураглалгүй rule: " + joinMax(r.UnmappedRules, 5) + ")"
				}
				out = append(out, msg)
			}
		case "unsupported", "unavailable":
			// хэвийн — doctor харуулна
		default:
			out = append(out, r.Scanner+": "+r.Status+" — "+r.Error)
		}
	}
	return out
}

func joinMax(xs []string, n int) string {
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + ", …"
	}
	return strings.Join(xs, ", ")
}

// sortBySeverity — Critical эхэнд. Тэнцвэл risk_contribution их нь, дараа нь ID.
func sortBySeverity(fs []finding.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if finding.Rank(fs[i].Severity) != finding.Rank(fs[j].Severity) {
			return finding.Rank(fs[i].Severity) > finding.Rank(fs[j].Severity)
		}
		if fs[i].RiskContribution != fs[j].RiskContribution {
			return fs[i].RiskContribution > fs[j].RiskContribution
		}
		return fs[i].ID < fs[j].ID
	})
}

// applyLang — canonical registry-ийн сонгосон хэл дээрх title/remediation-аар
// finding-үүдийг дарж бичнэ (scanner-ийн текстээс илүү curated, тогтвортой).
func applyLang(fs []finding.Finding, reg *canonical.Registry, lang string) {
	for i := range fs {
		ctrl, ok := reg.Get(fs[i].CanonicalControl)
		if !ok {
			continue
		}
		if t := ctrl.Title.Get(lang); t != "" {
			fs[i].Title = t
		}
		if r := ctrl.Remediation.Get(lang); r != "" {
			fs[i].Remediation = r
		}
		if len(ctrl.Attack) > 0 {
			fs[i].Attack = ctrl.Attack // MITRE ATT&CK: сул тал → боломжтой болгох техник
		}
	}
}

func summarize(fs []finding.Finding, score int, band string) finding.Summary {
	counts := map[finding.Severity]int{
		finding.SeverityCritical: 0, finding.SeverityHigh: 0, finding.SeverityMedium: 0,
		finding.SeverityLow: 0, finding.SeverityInfo: 0,
	}
	blind := 0
	for _, f := range fs {
		counts[f.Severity]++
		if f.BlindShot {
			blind++
		}
	}
	return finding.Summary{
		Counts:        counts,
		BlindShot:     blind,
		RiskScore:     score,
		RiskBand:      band,
		TotalFindings: len(fs),
	}
}

// randID — санамсаргүй scan_id (гадаад хамааралгүй).
func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// resultHash — findings-ийн detrministik hash (id+severity, эрэмбэлсэн).
// Нотолгоо (immutability) ба scan хоорондын diff-д ашиглагдана.
func resultHash(fs []finding.Finding) string {
	lines := make([]string, len(fs))
	for i, f := range fs {
		lines[i] = f.ID + ":" + string(f.Severity)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte("\n"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
