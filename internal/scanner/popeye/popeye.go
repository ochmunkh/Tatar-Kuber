// Package popeye — Popeye ScannerAdapter (runtime hygiene: dead service, unused, broken ref).
package popeye

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
	"github.com/ochmunkh/tatar-kuber/internal/normalizer"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
	"github.com/ochmunkh/tatar-kuber/internal/scanner/toolexec"
)

type Scanner struct {
	resolver *canonical.Resolver
	now      func() string
	scopeNS  map[string]bool // олон namespace-тэй live scan-д Normalize-ийн шүүлтүүр (nil = бүгд)
}

func New(resolver *canonical.Resolver) *Scanner {
	return &Scanner{resolver: resolver, now: func() string { return time.Now().UTC().Format(time.RFC3339) }}
}

func (s *Scanner) Name() string { return "popeye" }

func (s *Scanner) Available() (bool, error) { return toolexec.Available("popeye") }

func (s *Scanner) Version(ctx context.Context) (string, error) {
	return toolexec.Version(ctx, "popeye", "version")
}

func (s *Scanner) Supports(mode scanner.Mode) bool { return mode == scanner.ModeRemote } // live cluster only

// Timeout — runtime hygiene шалгалт хурдан тул богино хугацаа.
func (s *Scanner) Timeout() time.Duration { return 90 * time.Second }

// Scan — Live Mode B: "popeye -o json" ажиллуулж stdout-ийн JSON-ыг буцаана.
func (s *Scanner) Scan(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	if t.Mode != scanner.ModeRemote {
		return scanner.RawResult{Scanner: "popeye"}, fmt.Errorf("popeye: зөвхөн live cluster (Mode B)")
	}
	args := []string{"-o", "json"}
	if t.Context != "" {
		args = append(args, "--context", t.Context)
	}
	// Popeye нэг л namespace (-n) дэмждэг. Олон namespace өгвөл бүх cluster-ийг
	// чимээгүй scan хийхийн оронд Normalize дээр хамрах хүрээгээр шүүнэ (доор).
	if len(t.Namespaces) == 1 {
		args = append(args, "-n", t.Namespaces[0])
	} else if len(t.Namespaces) > 1 {
		s.scopeNS = map[string]bool{}
		for _, ns := range t.Namespaces {
			s.scopeNS[ns] = true
		}
	}
	var env []string
	if t.Kubeconfig != "" {
		args = append(args, "--kubeconfig", t.Kubeconfig)
		env = append(env, "KUBECONFIG="+t.Kubeconfig)
	}
	res, err := toolexec.Run(ctx, "popeye", args, env...)
	if len(res.Stdout) == 0 {
		if err != nil {
			return scanner.RawResult{Scanner: "popeye"}, err
		}
		return scanner.RawResult{Scanner: "popeye"}, fmt.Errorf("popeye: хоосон гаралт (stderr: %s)", strings.TrimSpace(string(res.Stderr)))
	}
	return scanner.RawResult{Scanner: "popeye", Format: "json", Data: res.Stdout, ExitCode: res.ExitCode}, nil
}

// ---- Popeye JSON бүтэц (popeye -o json) ----
//
// Popeye нь схемээ хувилбар хооронд СОЛЬСОН:
//   - <=0.21: popeye.sanitizers[].sanitizer + issues
//   - 0.22+:  popeye.sections[].linter (+ gvr) + issues
//
// Хоёуланг дэмжинэ: sections байвал түүнийг, үгүй бол sanitizers-ыг уншина —
// ингэснээр хэрэглэгчийн суулгасан popeye-ийн хувилбараас хамаарахгүй.

type popIssue struct {
	Level   int    `json:"level"`
	Message string `json:"message"`
	Group   string `json:"group"`
	GVR     string `json:"gvr"`
}

type popGroup struct {
	Linter    string                `json:"linter"`    // 0.22+
	Sanitizer string                `json:"sanitizer"` // <=0.21
	GVR       string                `json:"gvr"`       // 0.22+ (ж: apps/v1/deployments)
	Issues    map[string][]popIssue `json:"issues"`
}

// kind — бүлгийн K8s kind (ганц тоо, жижиг үсэг). linter/sanitizer нэр (олон тоо)
// эсвэл gvr-ийн сүүлийн хэсгээс гарна.
func (g popGroup) kind() string {
	name := g.Linter
	if name == "" {
		name = g.Sanitizer
	}
	if name == "" && g.GVR != "" {
		parts := strings.Split(g.GVR, "/")
		name = parts[len(parts)-1]
	}
	return singular(strings.ToLower(name))
}

type popReport struct {
	Popeye struct {
		Sections   []popGroup `json:"sections"`   // 0.22+
		Sanitizers []popGroup `json:"sanitizers"` // <=0.21
	} `json:"popeye"`
}

// groups — хувилбараас хамааралгүйгээр бүлгүүдийг буцаана.
func (r popReport) groups() []popGroup {
	if len(r.Popeye.Sections) > 0 {
		return r.Popeye.Sections
	}
	return r.Popeye.Sanitizers
}

var popCode = regexp.MustCompile(`\[(POP-\d+)\]`)

// levelName — Popeye-ийн lint level-ийн хүний уншиж болох нэр (нотолгоонд).
//
// ЧУХАЛ: Popeye-ийн level нь LINTER-ийн зэрэглэл (info/warn/error), АЮУЛГҮЙ
// БАЙДЛЫН severity БИШ. Тиймээс үүнийг finding-ийн severity болгож
// хөрвүүлэхээ БОЛИВ — canonical control-ийн curated default_severity дийлнэ
// (registry бол бүтээгдэхүүний гол хөрөнгө; линтерийн log-level түүнийг дарах
// нь аудитын тайланг гуйвуулна). Ж: dead service нь popeye-д level=3 (error)
// боловч TATAR-OPS-003 нь зориудаар INFO; missing probe нь level=2 боловч
// TATAR-OPS-001 нь LOW. Level нь evidence дотор ил үлдэнэ.
func levelName(l int) string {
	switch l {
	case 3:
		return "error"
	case 2:
		return "warning"
	case 1:
		return "info"
	default:
		return "ok"
	}
}

// Normalize — Popeye raw JSON -> []finding.Finding.
func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	var rep popReport
	if err := json.Unmarshal(raw.Data, &rep); err != nil {
		return nil, fmt.Errorf("popeye JSON parse: %w", err)
	}
	var out []finding.Finding
	for _, san := range rep.groups() {
		kind := san.kind() // services -> service, ingresses -> ingress
		for resKey, issues := range san.Issues {
			ns, name := splitResKey(resKey)
			if s.scopeNS != nil && ns != "" && !s.scopeNS[ns] {
				continue // хамрах хүрээнээс гадуурх namespace
			}
			resource := kind + "/" + name
			for _, iss := range issues {
				m := popCode.FindStringSubmatch(iss.Message)
				if len(m) < 2 {
					continue // POP код олдсонгүй
				}
				code := m[1]
				// group нь контейнерын нэр эсвэл "__root__" (объектын хэмжээнд).
				group := iss.Group
				if group == "__root__" {
					group = ""
				}
				ctx := canonical.ResolverContext{ResourceKind: kind, Namespace: ns, Detail: group}
				detail := strings.TrimSpace(popCode.ReplaceAllString(iss.Message, ""))
				evs := []finding.Evidence{{Scanner: "popeye", Path: group, Detail: detail, Value: "popeye " + levelName(iss.Level)}}
				// Severity ЗОРИУДААР дамжуулаагүй — canonical default_severity дийлнэ (дээрх levelName-ийг үз).
				meta := normalizer.Meta{Resource: resource, Namespace: ns, Evidence: evs}
				if f, ok := normalizer.Build(s.resolver, "popeye", code, ctx, meta, s.now); ok {
					out = append(out, f)
				}
			}
		}
	}
	return out, nil
}

// singular — Popeye sanitizer нэр (олон тоо) -> K8s kind (ганц тоо, жижиг үсэг).
// "ingresses" -> "ingress", "networkpolicies" -> "networkpolicy", "services" -> "service".
func singular(p string) string {
	switch {
	case strings.HasSuffix(p, "ies"):
		return strings.TrimSuffix(p, "ies") + "y"
	case strings.HasSuffix(p, "sses"): // ingresses, storageclasses
		return strings.TrimSuffix(p, "es")
	case strings.HasSuffix(p, "s"):
		return strings.TrimSuffix(p, "s")
	}
	return p
}

// splitResKey — "namespace/name" эсвэл "name" -> (ns, name).
func splitResKey(k string) (ns, name string) {
	if i := strings.Index(k, "/"); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "", k
}
