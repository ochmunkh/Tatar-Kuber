package popeye

import (
	"os"
	"sort"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// Popeye-ийн ХОЁР схемийг (0.22+ "sections" ба <=0.21 "sanitizers") хоёуланг
// уншиж, ижил canonical control-уудыг гаргах ёстой. 0.22-д схем сольсныг
// анзаараагүйгээс live scan-д popeye 0 finding өгч байсан.
func TestNormalize_BothSchemas(t *testing.T) {
	reg, err := canonical.Load("../../../schema/canonical-controls.yaml")
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	want := []string{"TATAR-CON-010", "TATAR-IMG-003", "TATAR-OPS-001", "TATAR-OPS-003", "TATAR-OPS-004", "TATAR-RBAC-005"}

	for _, fx := range []struct{ name, path string }{
		{"0.22 sections", "../../../testdata/popeye/scan.json"},
		{"legacy sanitizers", "../../../testdata/popeye/scan-legacy.json"},
	} {
		data, err := os.ReadFile(fx.path)
		if err != nil {
			t.Fatalf("%s fixture: %v", fx.name, err)
		}
		s := New(reg.NewResolver())
		findings, err := s.Normalize(scanner.RawResult{Scanner: "popeye", Format: "json", Data: data})
		if err != nil {
			t.Fatalf("%s Normalize: %v", fx.name, err)
		}
		got := []string{}
		for _, f := range findings {
			got = append(got, f.CanonicalControl)
			if len(f.FoundBy) != 1 || f.FoundBy[0] != "popeye" {
				t.Errorf("%s: found_by=%v, want [popeye]", fx.name, f.FoundBy)
			}
			if f.Namespace != "production" {
				t.Errorf("%s: namespace=%q, want production (ns/name түлхүүр)", fx.name, f.Namespace)
			}
		}
		sort.Strings(got)
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", fx.name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s [%d] %s, want %s", fx.name, i, got[i], want[i])
			}
		}
	}
}

// kind нь linter/sanitizer нэр эсвэл gvr-ээс гарч, resource "kind/name" болно.
func TestKindFromLinterAndGVR(t *testing.T) {
	cases := []struct {
		g    popGroup
		want string
	}{
		{popGroup{Linter: "deployments", GVR: "apps/v1/deployments"}, "deployment"},
		{popGroup{Sanitizer: "services"}, "service"},
		{popGroup{GVR: "networking.k8s.io/v1/ingresses"}, "ingress"},
		{popGroup{GVR: "networking.k8s.io/v1/networkpolicies"}, "networkpolicy"},
	}
	for _, c := range cases {
		if got := c.g.kind(); got != c.want {
			t.Errorf("kind(%+v)=%q want %q", c.g, got, c.want)
		}
	}
}

func TestSingular(t *testing.T) {
	cases := map[string]string{"pods": "pod", "services": "service", "ingresses": "ingress",
		"networkpolicies": "networkpolicy", "storageclasses": "storageclass", "deployments": "deployment", "node": "node"}
	for in, want := range cases {
		if got := singular(in); got != want {
			t.Errorf("singular(%q)=%q want %q", in, got, want)
		}
	}
}
