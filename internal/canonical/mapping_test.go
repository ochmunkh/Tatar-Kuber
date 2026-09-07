package canonical

import "testing"

const regPath = "../../schema/canonical-controls.yaml"

// Registry ачаалагдаж, ID/collision дүрмүүд хангагдаж байгааг шалгана.
func TestRegistryLoads(t *testing.T) {
	r, err := Load(regPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Controls) < 30 {
		t.Errorf("controls=%d, 30-аас доошгүй байх ёстой", len(r.Controls))
	}
}

// 1:1 rule-ууд яг нэг canonical руу зурагдана.
func TestResolveSingle(t *testing.T) {
	r, _ := Load(regPath)
	cases := []struct {
		scanner, rule, want string
	}{
		{"trivy", "AVD-KSV0017", "TATAR-CON-001"}, // privileged
		{"kubescape", "C-0057", "TATAR-CON-001"},
		{"checkov", "CKV_K8S_16", "TATAR-CON-001"},
		{"checkov", "CKV_K8S_20", "TATAR-CON-003"}, // allowPrivilegeEscalation (NET-004 БИШ!)
		{"checkov", "CKV_K8S_22", "TATAR-CON-009"}, // readonly fs (IMG-004 БИШ!)
		{"kubescape", "C-0035", "TATAR-RBAC-001"},  // cluster-admin
	}
	for _, c := range cases {
		ids, ok := r.Resolve(c.scanner, c.rule)
		if !ok || len(ids) != 1 || ids[0] != c.want {
			t.Errorf("Resolve(%s,%s)=%v, want [%s]", c.scanner, c.rule, ids, c.want)
		}
	}
}

// Олон-candidate rule-уудыг ResolverContext-оор дискриминаци хийнэ.
func TestResolveMulti(t *testing.T) {
	r, _ := Load(regPath)
	rs := r.NewResolver()

	// CVE severity-ээр
	if id, _ := rs.ResolveOne("trivy", "CVE-*", ResolverContext{Severity: "CRITICAL"}); id != "TATAR-IMG-001" {
		t.Errorf("CVE CRITICAL -> %s, want TATAR-IMG-001", id)
	}
	if id, _ := rs.ResolveOne("trivy", "CVE-*", ResolverContext{Severity: "HIGH"}); id != "TATAR-IMG-002" {
		t.Errorf("CVE HIGH -> %s, want TATAR-IMG-002", id)
	}
	// probe төрлөөр
	if id, _ := rs.ResolveOne("kubescape", "C-0018", ResolverContext{Detail: "liveness"}); id != "TATAR-OPS-002" {
		t.Errorf("C-0018 liveness -> %s, want TATAR-OPS-002", id)
	}
	// secret байршлаар
	if id, _ := rs.ResolveOne("trivy", "secret", ResolverContext{Detail: "image"}); id != "TATAR-SEC-002" {
		t.Errorf("secret image -> %s, want TATAR-SEC-002", id)
	}
}

// Тодорхойгүй rule нь олдохгүй.
func TestResolveUnknown(t *testing.T) {
	r, _ := Load(regPath)
	if _, ok := r.Resolve("trivy", "DOES-NOT-EXIST"); ok {
		t.Error("байхгүй rule ok=true буцаалаа")
	}
}

// Бодит Trivy гаралт "AVD-KSV-0017" (зураастай) — registry-д "AVD-KSV0017" гэж
// бичсэн ч заавал таарах ёстой. v1.0.0-д энэ зөрүү live Mode B-д Trivy-ийн бүх
// finding-ийг чимээгүй алдуулж байсан.
func TestNormalizeRuleID(t *testing.T) {
	cases := map[string]string{
		"AVD-KSV-0017": "KSV17", "AVD-KSV0017": "KSV17", "KSV017": "KSV17", "KSV-0017": "KSV17",
		"C-0057": "C57", "POP-106": "POP106", "CKV_K8S_16": "CKV_K8S_16", "CVE-*": "CVE-*", "secret": "SECRET",
	}
	for in, want := range cases {
		if got := NormalizeRuleID("trivy", in); got != want {
			t.Errorf("NormalizeRuleID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveRealTrivyAVDID(t *testing.T) {
	reg, err := Load(regPath)
	if err != nil {
		t.Fatal(err)
	}
	ids, ok := reg.Resolve("trivy", "AVD-KSV-0017")
	if !ok || len(ids) != 1 || ids[0] != "TATAR-CON-001" {
		t.Fatalf("real Trivy AVDID must resolve to TATAR-CON-001, got %v %v", ids, ok)
	}
	if _, ok := reg.Resolve("trivy", "KSV-0017"); !ok {
		t.Fatalf("trivy short ID KSV-0017 must resolve")
	}
}

// Popeye-ийн POP код бүрийн УТГА хувилбар хооронд өөрчлөгддөг (0.22-д POP-101
// нь ":latest", POP-106 нь "resources requests/limits" — 0.21-д өөр байсан).
// v1.0.0-д зураглалын 10-аас 7 нь зөрж, аудитад БУРУУ control тайлагнах эрсдэл
// байсан (ж: "unnamed port" -> "Missing CPU/memory limits"). Энэ тест нь код бүрийн
// утгыг эх сурвалжтай (popeye internal/issues/assets/codes.yaml) хамт бэхэлнэ.
func TestPopeyeMappingsMatchUpstreamMeaning(t *testing.T) {
	reg, err := Load(regPath)
	if err != nil {
		t.Fatal(err)
	}
	// code -> {upstream дахь утга, хүлээгдэх canonical control}
	want := []struct{ code, meaning, control string }{
		{"POP-100", `Untagged docker image in use`, "TATAR-IMG-003"},
		{"POP-101", `Image tagged "latest" in use`, "TATAR-IMG-003"},
		{"POP-102", `No probes defined`, "TATAR-OPS-001"},
		{"POP-103", `No liveness probe`, "TATAR-OPS-002"},
		{"POP-106", `No resources requests/limits defined`, "TATAR-CON-010"},
		{"POP-107", `No resource limits defined`, "TATAR-CON-010"},
		{"POP-300", `Uses "default" ServiceAccount`, "TATAR-RBAC-005"},
		{"POP-302", `Pod could be running as root user`, "TATAR-CON-002"},
		{"POP-303", `ServiceAccount is automounting APIServer credentials`, "TATAR-SEC-003"},
		{"POP-306", `Container could be running as root user`, "TATAR-CON-002"},
		{"POP-400", `Used? Unable to locate resource reference`, "TATAR-OPS-004"},
		{"POP-401", `Key used? Unable to locate key reference`, "TATAR-OPS-004"},
		{"POP-1100", `No pods match service selector`, "TATAR-OPS-003"},
		{"POP-1110", `Match EP has no subsets`, "TATAR-OPS-003"},
		{"POP-1204", `Pod is not secured by a network policy`, "TATAR-NET-001"},
	}

	for _, w := range want {
		ids, ok := reg.Resolve("popeye", w.code)
		if !ok || len(ids) != 1 {
			t.Errorf("%s (%s): зураглал олдсонгүй/олон (%v)", w.code, w.meaning, ids)
			continue
		}
		if ids[0] != w.control {
			t.Errorf("%s (%s) -> %s, хүлээсэн %s", w.code, w.meaning, ids[0], w.control)
		}
	}

	// Зураглагдсан POP код бүр дээрх жагсаалтад БАЙХ ёстой — шинэ код нэмэхэд
	// утгыг нь эх сурвалжаас батлаж, энэ тестэд бүртгэхийг албадана.
	known := map[string]bool{}
	for _, w := range want {
		known[w.code] = true
	}
	for _, c := range reg.Controls {
		for _, code := range c.Mappings["popeye"] {
			if !known[code] {
				t.Errorf("%s: %s зураглагдсан ч утга батлагдаагүй — popeye codes.yaml-аас шалгаж тестэд нэм", c.ID, code)
			}
		}
	}
}
