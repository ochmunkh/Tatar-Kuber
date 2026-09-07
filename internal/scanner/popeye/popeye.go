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

// ---- Popeye JSON бүтэц (popeye --out json) ----

type popReport struct {
	Popeye struct {
		Sanitizers []struct {
			Sanitizer string `json:"sanitizer"`
			Issues    map[string][]struct {
				Level   int    `json:"level"`
				Message string `json:"message"`
			} `json:"issues"`
		} `json:"sanitizers"`
	} `json:"popeye"`
}

var popCode = regexp.MustCompile(`\[(POP-\d+)\]`)

// levelSeverity — Popeye level -> TATAR severity (Doc #4 §2).
func levelSeverity(l int) string {
	switch l {
	case 3:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 1:
		return "LOW"
	default:
		return "INFO"
	}
}

// Normalize — Popeye raw JSON -> []finding.Finding.
func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	var rep popReport
	if err := json.Unmarshal(raw.Data, &rep); err != nil {
		return nil, fmt.Errorf("popeye JSON parse: %w", err)
	}
	var out []finding.Finding
	for _, san := range rep.Popeye.Sanitizers {
		kind := singular(san.Sanitizer) // services -> service, ingresses -> ingress
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
				ctx := canonical.ResolverContext{ResourceKind: kind, Namespace: ns, Severity: levelSeverity(iss.Level)}
				detail := strings.TrimSpace(popCode.ReplaceAllString(iss.Message, ""))
				evs := []finding.Evidence{{Scanner: "popeye", Detail: detail}}
				meta := normalizer.Meta{Resource: resource, Namespace: ns, Evidence: evs, Severity: levelSeverity(iss.Level)}
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
