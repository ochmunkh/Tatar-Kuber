package orchestrator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// fakeAdapter — Run-ий зэрэгцээ ажиллагаа, timeout, graceful degrade-ийг
// шалгах хиймэл adapter. Context-ийг хүндэтгэнэ (timeout шалгахад чухал).
type fakeAdapter struct {
	name    string
	mode    scanner.Mode  // "" бол бүх горимыг дэмжинэ
	sleep   time.Duration // Scan хэр удах
	failErr error         // тэг биш бол Scan алдаа буцаана
	timeout time.Duration // 0 бол timeout зөвлөмжгүй
	ctrl    string        // Normalize-ийн canonical control
	res     string        // Normalize-ийн resource
	started *int32        // Scan дуудагдсан тоо (сонголт)
}

func (f *fakeAdapter) Name() string                            { return f.name }
func (f *fakeAdapter) Available() (bool, error)                { return true, nil }
func (f *fakeAdapter) Version(context.Context) (string, error) { return "test-1.0", nil }
func (f *fakeAdapter) Supports(m scanner.Mode) bool            { return f.mode == "" || f.mode == m }
func (f *fakeAdapter) Timeout() time.Duration                  { return f.timeout }

func (f *fakeAdapter) Scan(ctx context.Context, _ scanner.Target) (scanner.RawResult, error) {
	if f.started != nil {
		atomic.AddInt32(f.started, 1)
	}
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return scanner.RawResult{}, ctx.Err() // timeout → graceful degrade
		}
	}
	if f.failErr != nil {
		return scanner.RawResult{}, f.failErr
	}
	return scanner.RawResult{Scanner: f.name, Format: "json", Data: []byte("{}")}, nil
}

func (f *fakeAdapter) Normalize(scanner.RawResult) ([]finding.Finding, error) {
	return []finding.Finding{{
		CanonicalControl: f.ctrl,
		Resource:         f.res,
		Namespace:        "default",
		Severity:         finding.SeverityHigh,
		OriginalSeverity: finding.SeverityHigh,
		Type:             finding.TypeMisconfig,
		FoundBy:          []string{f.name},
		Status:           finding.StatusOpen,
	}}, nil
}

func testRegistry(t *testing.T) *canonical.Registry {
	t.Helper()
	reg, err := canonical.Load("../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func hasResource(res finding.ScanResult, resource string) bool {
	for _, f := range res.Findings {
		if f.Resource == resource {
			return true
		}
	}
	return false
}

// Нэг adapter унахад бусад нь үлдэх ёстой (graceful degradation).
func TestRun_GracefulDegrade_OneFailure(t *testing.T) {
	reg := testRegistry(t)
	p := New(reg,
		&fakeAdapter{name: "good-a", ctrl: "TATAR-TEST-001", res: "deployment/a"},
		&fakeAdapter{name: "bad", ctrl: "TATAR-TEST-002", res: "deployment/b", failErr: errors.New("boom")},
		&fakeAdapter{name: "good-c", ctrl: "TATAR-TEST-003", res: "deployment/c"},
	)

	res, err := p.Run(context.Background(), scanner.Target{Mode: scanner.ModeRemote}, Meta{ScanMode: "remote"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasResource(res, "deployment/a") || !hasResource(res, "deployment/c") {
		t.Errorf("унасан adapter бусдыг унагасан: findings=%+v", res.Findings)
	}
	if hasResource(res, "deployment/b") {
		t.Error("унасан adapter-ийн (bad) finding гарч ирсэн байна")
	}
	if res.Summary.TotalFindings != 2 {
		t.Errorf("total=%d, want 2 (good-a + good-c)", res.Summary.TotalFindings)
	}
}

// Бүх adapter унахад алдаа/panic-гүй хоосон үр дүн.
func TestRun_AllFail(t *testing.T) {
	reg := testRegistry(t)
	p := New(reg,
		&fakeAdapter{name: "x", ctrl: "TATAR-TEST-001", res: "deployment/x", failErr: errors.New("e1")},
		&fakeAdapter{name: "y", ctrl: "TATAR-TEST-002", res: "deployment/y", failErr: errors.New("e2")},
	)
	res, err := p.Run(context.Background(), scanner.Target{Mode: scanner.ModeRemote}, Meta{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Summary.TotalFindings != 0 {
		t.Errorf("total=%d, want 0", res.Summary.TotalFindings)
	}
}

// Adapter-ууд ЗЭРЭГ ажиллах ёстой: нийт хугацаа дарааллын нийлбэрээс их бага.
func TestRun_Concurrent(t *testing.T) {
	reg := testRegistry(t)
	const per = 150 * time.Millisecond
	p := New(reg,
		&fakeAdapter{name: "s1", sleep: per, ctrl: "TATAR-TEST-001", res: "deployment/1"},
		&fakeAdapter{name: "s2", sleep: per, ctrl: "TATAR-TEST-002", res: "deployment/2"},
		&fakeAdapter{name: "s3", sleep: per, ctrl: "TATAR-TEST-003", res: "deployment/3"},
		&fakeAdapter{name: "s4", sleep: per, ctrl: "TATAR-TEST-004", res: "deployment/4"},
	)

	start := time.Now()
	res, err := p.Run(context.Background(), scanner.Target{Mode: scanner.ModeRemote}, Meta{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Summary.TotalFindings != 4 {
		t.Errorf("total=%d, want 4", res.Summary.TotalFindings)
	}
	// Дараалсан бол ~600ms. Зэрэгцээ бол ~150ms. Уужим босго: 400ms.
	if elapsed >= 400*time.Millisecond {
		t.Errorf("elapsed=%v — adapter-ууд зэрэг ажиллаагүй бололтой (want < 400ms)", elapsed)
	}
}

// Per-scanner timeout: удаан adapter өөрийн timeout-оор унаж, бусад нь үлдэнэ.
func TestRun_PerScannerTimeout(t *testing.T) {
	reg := testRegistry(t)
	p := New(reg,
		// timeout=30ms, sleep=300ms → өөрийн timeout-оор унана.
		&fakeAdapter{name: "slow", sleep: 300 * time.Millisecond, timeout: 30 * time.Millisecond, ctrl: "TATAR-TEST-001", res: "deployment/slow"},
		// хурдан, timeout-гүй → үлдэнэ.
		&fakeAdapter{name: "fast", sleep: 10 * time.Millisecond, ctrl: "TATAR-TEST-002", res: "deployment/fast"},
	)

	start := time.Now()
	res, err := p.Run(context.Background(), scanner.Target{Mode: scanner.ModeRemote}, Meta{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasResource(res, "deployment/slow") {
		t.Error("timeout болсон slow adapter-ийн finding үлдсэн байна")
	}
	if !hasResource(res, "deployment/fast") {
		t.Error("fast adapter-ийн finding алга (timeout бусдыг унагасан)")
	}
	// slow-ийн 300ms-ийг хүлээгээгүй — 30ms timeout-оор таслагдсан.
	if elapsed >= 250*time.Millisecond {
		t.Errorf("elapsed=%v — per-scanner timeout ажиллаагүй бололтой", elapsed)
	}
}

// Гаралт detrministik: ижил adapter-ууд → ижил result_hash (зэрэгцээ ч эрэмбэ тогтвортой).
func TestRun_Deterministic(t *testing.T) {
	reg := testRegistry(t)
	newPipe := func() *Pipeline {
		return New(reg,
			&fakeAdapter{name: "s1", ctrl: "TATAR-TEST-003", res: "deployment/z"},
			&fakeAdapter{name: "s2", ctrl: "TATAR-TEST-001", res: "deployment/a"},
			&fakeAdapter{name: "s3", ctrl: "TATAR-TEST-002", res: "deployment/m"},
		)
	}
	var prev string
	for i := 0; i < 5; i++ {
		res, err := newPipe().Run(context.Background(), scanner.Target{Mode: scanner.ModeRemote}, Meta{})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if prev != "" && res.Metadata.ResultHash != prev {
			t.Fatalf("result_hash detrministik биш: %s vs %s", prev, res.Metadata.ResultHash)
		}
		prev = res.Metadata.ResultHash
	}
}

// Available()=false adapter огт ажиллахгүй байх.
func TestRun_SkipsUnavailable(t *testing.T) {
	reg := testRegistry(t)
	var scanned int32
	p := New(reg,
		&unavailableAdapter{fakeAdapter{name: "off", ctrl: "TATAR-TEST-001", res: "deployment/off", started: &scanned}},
		&fakeAdapter{name: "on", ctrl: "TATAR-TEST-002", res: "deployment/on"},
	)
	res, err := p.Run(context.Background(), scanner.Target{Mode: scanner.ModeRemote}, Meta{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt32(&scanned) != 0 {
		t.Error("Available()=false adapter-ийн Scan дуудагдсан байна")
	}
	if hasResource(res, "deployment/off") {
		t.Error("боломжгүй adapter-ийн finding гарч ирсэн")
	}
	if !hasResource(res, "deployment/on") {
		t.Error("боломжтой adapter-ийн finding алга")
	}
}

type unavailableAdapter struct{ fakeAdapter }

func (u *unavailableAdapter) Available() (bool, error) { return false, nil }

// Унасан/timeout/unsupported adapter бүр scanner_runs-д ИЛ бичигдэх ёстой —
// graceful degradation нь чимээгүй байж болохгүй (v1.0.0-д Trivy 0 finding өгч
// байсныг хэн ч анзаараагүй шалтгаан).
func TestRun_ScannerRunsAreReported(t *testing.T) {
	reg := testRegistry(t)
	p := New(reg,
		&fakeAdapter{name: "good", ctrl: "TATAR-TEST-001", res: "deployment/a"},
		&fakeAdapter{name: "bad", ctrl: "TATAR-TEST-002", res: "deployment/b", failErr: errors.New("boom")},
		&fakeAdapter{name: "slow", ctrl: "TATAR-TEST-003", res: "deployment/c", sleep: 2 * time.Second, timeout: 50 * time.Millisecond},
		&fakeAdapter{name: "local-only", mode: scanner.ModeLocal, ctrl: "TATAR-TEST-004", res: "deployment/d"},
	)
	res, err := p.Run(context.Background(), scanner.Target{Mode: scanner.ModeRemote}, Meta{ScanMode: "remote"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := map[string]finding.ScannerRun{}
	for _, r := range res.Metadata.ScannerRuns {
		got[r.Scanner] = r
	}
	if len(got) != 4 {
		t.Fatalf("scanner_runs=%d, want 4 (adapter бүр нэг бичлэг)", len(got))
	}
	if r := got["good"]; r.Status != "ok" || r.Findings != 1 || r.Version != "test-1.0" {
		t.Errorf("good: %+v", r)
	}
	if r := got["bad"]; r.Status != "error" || r.Error == "" {
		t.Errorf("bad: %+v (status=error + error text байх ёстой)", r)
	}
	if r := got["slow"]; r.Status != "timeout" {
		t.Errorf("slow: %+v (status=timeout байх ёстой)", r)
	}
	if r := got["local-only"]; r.Status != "unsupported" {
		t.Errorf("local-only: %+v (status=unsupported байх ёстой)", r)
	}
	probs := Problems(res.Metadata.ScannerRuns)
	if len(probs) != 2 { // bad + slow; good ok, unsupported хэвийн
		t.Errorf("Problems=%v, want 2", probs)
	}
}

// Offline ingest (Process) — raw бүрд "ingested" бичлэг; 0 finding бол Problems анхааруулна.
func TestProcess_IngestedRunsAndEmptyWarning(t *testing.T) {
	reg := testRegistry(t)
	p := New(reg, &fakeAdapter{name: "z", ctrl: "TATAR-TEST-001", res: "deployment/z"})
	res, _ := p.Process([]scanner.RawResult{{Scanner: "z", Data: []byte("{}"), Version: "9.9"}}, Meta{})
	if len(res.Metadata.ScannerRuns) != 1 || res.Metadata.ScannerRuns[0].Status != "ingested" || res.Metadata.ScannerRuns[0].Version != "9.9" {
		t.Fatalf("runs=%+v", res.Metadata.ScannerRuns)
	}
	empty := []finding.ScannerRun{{Scanner: "trivy", Status: "ok", Findings: 0, UnmappedCount: 3, UnmappedRules: []string{"AVD-X-1"}}}
	if ps := Problems(empty); len(ps) != 1 {
		t.Errorf("0 finding scanner анхааруулга өгөх ёстой: %v", ps)
	}
}
