package rollup

import (
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

func f(ctrl, res, ns string, foundBy ...string) finding.Finding {
	if len(foundBy) == 0 {
		foundBy = []string{"popeye"}
	}
	return finding.Finding{CanonicalControl: ctrl, Resource: res, Namespace: ns, FoundBy: foundBy}
}

// Pod-scoped finding нь ижил control+namespace-д controller байвал зөөгдөнө.
func TestRollup_MovesPodToOwner(t *testing.T) {
	in := []finding.Finding{
		f("TATAR-IMG-003", "deployment/api", "demo", "trivy"),
		f("TATAR-IMG-003", "pod/api-598c4dc6b8-ldjqq", "demo"),
	}
	out, r := Apply(in)
	if r.Moved != 1 {
		t.Fatalf("Moved=%d, want 1", r.Moved)
	}
	if out[1].Resource != "deployment/api" {
		t.Errorf("resource=%s, want deployment/api", out[1].Resource)
	}
	if out[1].ID == "" || out[1].ID == in[1].ID {
		t.Errorf("зөөсний дараа ID дахин үүсэх ёстой: %s", out[1].ID)
	}
	// Pod-ийн онцлог нотолгоонд үлдэх ёстой — юу ч нуугдахгүй.
	var kept bool
	for _, e := range out[1].Evidence {
		if e.Path == "pod/api-598c4dc6b8-ldjqq" && e.Detail == "rolled up to deployment/api" {
			kept = true
		}
	}
	if !kept {
		t.Errorf("зөөгдсөн pod нотолгоонд бичигдээгүй: %+v", out[1].Evidence)
	}
	if len(r.Pods) != 1 || r.Pods[0] != "api-598c4dc6b8-ldjqq" {
		t.Errorf("Pods=%v", r.Pods)
	}
}

// StatefulSet (ordinal) ба DaemonSet/Job (нэг хэш) хэлбэрүүд.
func TestRollup_SuffixShapes(t *testing.T) {
	cases := []struct {
		ctrl, pod string
		want      bool
	}{
		{"statefulset/db", "db-0", true},
		{"statefulset/db", "db-12", true},
		{"daemonset/agent", "agent-7d9f8", true},
		{"deployment/api", "api-598c4dc6b8-ldjqq", true},
		{"replicaset/api-598c4dc6b8", "api-598c4dc6b8-ldjqq", true},
		// Өөр deployment-ийн pod-ыг эзэмшихгүй: үлдэх хэсэг дагаварын хэв маягт таарахгүй.
		{"deployment/api", "api-gateway-598c4dc6b8-ldjqq", false},
		// Гараар нэрлэсэн pod — үүсгэсэн дагавар биш.
		{"deployment/api", "api-canary", false},
		// Ижил нэр — эзэмшил гэж үзэхгүй.
		{"deployment/api", "api", false},
	}
	for _, c := range cases {
		in := []finding.Finding{
			f("TATAR-CON-001", c.ctrl, "ns", "trivy"),
			f("TATAR-CON-001", "pod/"+c.pod, "ns"),
		}
		_, r := Apply(in)
		if (r.Moved == 1) != c.want {
			t.Errorf("%s <- pod/%s: зөөгдсөн=%v, хүлээсэн=%v", c.ctrl, c.pod, r.Moved == 1, c.want)
		}
	}
}

// Хамгийн урт нэртэй controller сонгогдоно (api vs api-gateway хоёулаа байхад).
func TestRollup_LongestOwnerWins(t *testing.T) {
	in := []finding.Finding{
		f("TATAR-CON-001", "deployment/api", "ns", "trivy"),
		f("TATAR-CON-001", "deployment/api-gateway", "ns", "trivy"),
		f("TATAR-CON-001", "pod/api-gateway-598c4dc6b8-ldjqq", "ns"),
	}
	out, r := Apply(in)
	if r.Moved != 1 || out[2].Resource != "deployment/api-gateway" {
		t.Errorf("resource=%s moved=%d, want deployment/api-gateway", out[2].Resource, r.Moved)
	}
}

// Controller байхгүй бол Pod finding ХЭВЭЭР үлдэнэ — объект зохиохгүй.
func TestRollup_NoOwnerNoChange(t *testing.T) {
	in := []finding.Finding{
		f("TATAR-NET-001", "pod/orphan-598c4dc6b8-ldjqq", "demo"),
	}
	out, r := Apply(in)
	if r.Moved != 0 || out[0].Resource != "pod/orphan-598c4dc6b8-ldjqq" {
		t.Errorf("controller байхгүй үед зөөх ёсгүй: %s moved=%d", out[0].Resource, r.Moved)
	}
}

// Namespace зөрвөл зөөхгүй.
func TestRollup_NamespaceIsolation(t *testing.T) {
	in := []finding.Finding{
		f("TATAR-CON-001", "deployment/api", "prod", "trivy"),
		f("TATAR-CON-001", "pod/api-598c4dc6b8-ldjqq", "staging"),
	}
	_, r := Apply(in)
	if r.Moved != 0 {
		t.Errorf("өөр namespace-д зөөх ёсгүй, moved=%d", r.Moved)
	}
}

// Өөр canonical control-д зөөхгүй (тухайн control-д controller finding байх ёстой).
func TestRollup_ControlIsolation(t *testing.T) {
	in := []finding.Finding{
		f("TATAR-CON-001", "deployment/api", "demo", "trivy"),
		f("TATAR-NET-001", "pod/api-598c4dc6b8-ldjqq", "demo"),
	}
	_, r := Apply(in)
	if r.Moved != 0 {
		t.Errorf("өөр control-д зөөх ёсгүй, moved=%d", r.Moved)
	}
}
