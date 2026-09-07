// Package kubescape — Kubescape ScannerAdapter (NSA/MITRE/RBAC, primary posture engine).
package kubescape

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
}

func New(resolver *canonical.Resolver) *Scanner {
	return &Scanner{resolver: resolver, now: func() string { return time.Now().UTC().Format(time.RFC3339) }}
}

func (s *Scanner) Name() string { return "kubescape" }

func (s *Scanner) Available() (bool, error) { return toolexec.Available("kubescape") }

func (s *Scanner) Version(ctx context.Context) (string, error) {
	return toolexec.Version(ctx, "kubescape", "version")
}

func (s *Scanner) Supports(mode scanner.Mode) bool { return true } // local + remote

// Timeout — cluster-wide posture scan дунд зэрэг удана.
func (s *Scanner) Timeout() time.Duration { return 4 * time.Minute }

// Scan — Live Mode B: "kubescape scan --format json --output <tmp>" ажиллуулж,
// файлын JSON гаралтыг уншиж буцаана.
func (s *Scanner) Scan(ctx context.Context, t scanner.Target) (scanner.RawResult, error) {
	if t.Mode != scanner.ModeRemote {
		return scanner.RawResult{Scanner: "kubescape"}, fmt.Errorf("kubescape live: зөвхөн remote (Mode B) дэмжигдэнэ")
	}
	// Гаралтыг тусдаа ХАВТАСТ бичүүлнэ: --kube-contexts (fleet mode) үед kubescape
	// нэрийг өөрөө сольдог (`scan.json` -> `scan.<context>.json`) тул тогтсон
	// файлын нэрээр уншиж болохгүй — хавтас доторх JSON-ыг хайж уншина.
	tmpDir, err := os.MkdirTemp("", "tatar-kubescape-*")
	if err != nil {
		return scanner.RawResult{Scanner: "kubescape"}, err
	}
	defer os.RemoveAll(tmpDir)
	tmpPath := filepath.Join(tmpDir, "scan.json")

	args := []string{"scan", "--format", "json", "--output", tmpPath}
	if len(t.Namespaces) > 0 {
		args = append(args, "--include-namespaces", strings.Join(t.Namespaces, ","))
	}
	// Хэрэглэгчийн заасан context-ыг ЗААВАЛ дамжуулна — эс бөгөөс kubescape
	// kubeconfig-ийн одоогийн context-ыг (өөр cluster байж болзошгүй) scan хийнэ.
	// Тэмдэглэл: kubescape-ийн флаг нь ОЛОН тоо (--kube-contexts, StringSlice);
	// нэг context өгвөл яг түүнийг scan хийнэ.
	if t.Context != "" {
		args = append(args, "--kube-contexts", t.Context)
	}
	var env []string
	if t.Kubeconfig != "" {
		env = append(env, "KUBECONFIG="+t.Kubeconfig)
	}
	res, runErr := toolexec.Run(ctx, "kubescape", args, env...)

	data := readOutput(tmpDir)
	if len(data) == 0 {
		if runErr != nil {
			return scanner.RawResult{Scanner: "kubescape"}, runErr
		}
		return scanner.RawResult{Scanner: "kubescape"}, fmt.Errorf("kubescape: хоосон гаралт (stderr: %s)", strings.TrimSpace(string(res.Stderr)))
	}
	return scanner.RawResult{Scanner: "kubescape", Format: "json", Data: data, ExitCode: res.ExitCode}, nil
}

// readOutput — tmpDir доторх хамгийн том JSON файлыг уншина. Fleet mode-д
// kubescape `scan.<context>.json` гэж бичдэг тул нэрээр таамаглахгүй, хайна.
func readOutput(dir string) []byte {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var best []byte
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil && len(b) > len(best) {
			best = b
		}
	}
	return best
}

// ---- Kubescape JSON бүтэц (kubescape scan --format json) ----

type ksReport struct {
	Results []struct {
		ResourceID string `json:"resourceID"`
		Controls   []struct {
			ControlID string `json:"controlID"`
			Name      string `json:"name"`
			Status    struct {
				Status string `json:"status"`
			} `json:"status"`
			Rules []struct {
				Paths []struct {
					FailedPath string `json:"failedPath"`
					FixPath    struct {
						Path  string `json:"path"`
						Value string `json:"value"`
					} `json:"fixPath"`
				} `json:"paths"`
			} `json:"rules"`
		} `json:"controls"`
	} `json:"results"`
	Resources []struct {
		ResourceID string `json:"resourceID"`
		Object     struct {
			Kind string `json:"kind"`
			// Name — RBAC subject (Group/User/ServiceAccount) объектууд нэрээ ДЭЭД
			// түвшний "name" талбарт өгдөг, metadata.name-д БИШ. v1.0.1 хүртэл
			// зөвхөн metadata.name уншиж байсан тул тэдгээр finding нь "group/",
			// "user/" гэж хоосон нэртэй гарч, dedup түлхүүр (control|resource|ns)
			// давхцаж ӨӨР ӨӨР subject-ууд НЭГ finding болж нийлж байв.
			Name           string          `json:"name"`
			APIGroup       string          `json:"apiGroup"`
			Metadata       objectMetadata  `json:"metadata"`
			RelatedObjects []relatedObject `json:"relatedObjects"`
		} `json:"object"`
	} `json:"resources"`
}

type objectMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// relatedObject — RBAC subject-ийн хамаарах binding/role (нотолгоонд).
type relatedObject struct {
	Kind     string         `json:"kind"`
	Metadata objectMetadata `json:"metadata"`
	RoleRef  struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
}

// Normalize — Kubescape raw JSON -> []finding.Finding.
func (s *Scanner) Normalize(raw scanner.RawResult) ([]finding.Finding, error) {
	var rep ksReport
	if err := json.Unmarshal(raw.Data, &rep); err != nil {
		return nil, fmt.Errorf("kubescape JSON parse: %w", err)
	}
	// resourceID -> object. Нэрийг metadata.name-аас, байхгүй бол дээд түвшний
	// name-аас авна (RBAC subject-ууд), эцэст нь resourceID-ийн сүүлийн хэсгээс.
	type objInfo struct {
		Kind, Name, NS string
		Related        []relatedObject
	}
	objs := map[string]objInfo{}
	for _, r := range rep.Resources {
		name := r.Object.Metadata.Name
		if name == "" {
			name = r.Object.Name
		}
		if name == "" {
			// Хамгийн сүүлийн нөөц: resourceID-ийн "/"-аар хуваасан сүүлийн хэсэг.
			if i := strings.LastIndex(r.ResourceID, "/"); i >= 0 && i+1 < len(r.ResourceID) {
				name = r.ResourceID[i+1:]
			}
		}
		objs[r.ResourceID] = objInfo{r.Object.Kind, name, r.Object.Metadata.Namespace, r.Object.RelatedObjects}
	}

	var out []finding.Finding
	for _, res := range rep.Results {
		o := objs[res.ResourceID]
		resource := strings.ToLower(o.Kind) + "/" + o.Name
		for _, c := range res.Controls {
			if c.Status.Status != "failed" {
				continue // зөвхөн унасан control-ыг finding болгоно
			}
			var evs []finding.Evidence
			for _, rule := range c.Rules {
				for _, pth := range rule.Paths {
					e := finding.Evidence{Scanner: "kubescape"}
					if pth.FixPath.Path != "" {
						e.Path = pth.FixPath.Path
						if pth.FixPath.Value != "" {
							e.Value = "зөвлөмж: " + pth.FixPath.Value
						}
					} else if pth.FailedPath != "" {
						e.Path = pth.FailedPath
					}
					if e.Path != "" {
						evs = append(evs, e)
					}
				}
			}
			// RBAC subject-ийн хамаарах binding/role-ыг нотолгоонд нэмнэ — аудитад
			// "ямар group ямар role-той холбогдсон" нь зайлшгүй мэдээлэл.
			for _, ro := range o.Related {
				if ro.RoleRef.Name == "" {
					continue
				}
				evs = append(evs, finding.Evidence{
					Scanner: "kubescape",
					Path:    strings.ToLower(ro.Kind) + "/" + ro.Metadata.Name,
					Value:   strings.ToLower(ro.RoleRef.Kind) + "/" + ro.RoleRef.Name,
					Detail:  "bound role",
				})
			}
			ctx := canonical.ResolverContext{ResourceKind: o.Kind, Namespace: o.NS}
			meta := normalizer.Meta{Resource: resource, Namespace: o.NS, Title: c.Name, Evidence: evs}
			if f, ok := normalizer.Build(s.resolver, "kubescape", c.ControlID, ctx, meta, s.now); ok {
				out = append(out, f)
			}
		}
	}
	return out, nil
}
