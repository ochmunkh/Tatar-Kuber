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

// Checkov-ийн CKV ID-ууд ч мөн адил: ID нь тогтвортой боловч тухайн ID ЯГ ЮУ
// шалгадаг нь registry-д бичсэн canonical control-той таарах ёстой. v1.0.1-ийн
// аудитаар 18 зураглалын 2 нь зөрсөн:
//
//	CKV_K8S_43 = "Image should use digest" (ямар ч tag-тай image дээр гарна)
//	  -> IMG-003 ":latest tag" гэж зурагдсан. Зөв пиннэсэн nginx:1.25.3 ч
//	     ":latest ашиглаж байна" гэж тайлагдах false positive байв.
//	     ":latest"-ийн жинхэнэ шалгалт нь CKV_K8S_14.
//	CKV_K8S_27 = "Do not expose the docker daemon socket to containers"
//	  -> CON-007 "Host filesystem mounted (hostPath)" гэж зурагдсан. Checkov-д
//	     ерөнхий hostPath шалгалт БАЙХГҮЙ (Trivy/Kubescape хамардаг).
//
// Утгуудыг checkov 3.3-ийн бодит гаралт ба шалгалтын эх кодоос (жишээ:
// resource/k8s/ImageTagFixed.py) батлав.
func TestCheckovMappingsMatchUpstreamMeaning(t *testing.T) {
	reg, err := Load(regPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ code, meaning, control string }{
		{"CKV_K8S_8", `Liveness Probe Should be Configured`, "TATAR-OPS-002"},
		{"CKV_K8S_9", `Readiness Probe Should be Configured`, "TATAR-OPS-001"},
		{"CKV_K8S_10", `CPU requests should be set`, "TATAR-CON-010"},
		{"CKV_K8S_11", `CPU limits should be set`, "TATAR-CON-010"},
		{"CKV_K8S_12", `Memory requests should be set`, "TATAR-CON-010"},
		{"CKV_K8S_13", `Memory limits should be set`, "TATAR-CON-010"},
		{"CKV_K8S_14", `Image Tag should be fixed - not latest or blank`, "TATAR-IMG-003"},
		{"CKV_K8S_15", `Image Pull Policy should be Always`, "TATAR-OPS-005"},
		{"CKV_K8S_16", `Container should not be privileged`, "TATAR-CON-001"},
		{"CKV_K8S_17", `Containers should not share the host process ID namespace`, "TATAR-CON-005"},
		{"CKV_K8S_19", `Containers should not share the host network namespace`, "TATAR-CON-006"},
		{"CKV_K8S_20", `Containers should not run with allowPrivilegeEscalation`, "TATAR-CON-003"},
		{"CKV_K8S_22", `Use read-only filesystem for containers where possible`, "TATAR-CON-009"},
		{"CKV_K8S_23", `Minimize the admission of root containers`, "TATAR-CON-002"},
		{"CKV_K8S_25", `Minimize the admission of containers with added capability`, "TATAR-CON-004"},
		{"CKV_K8S_28", `Minimize the admission of containers with the NET_RAW capability`, "TATAR-CON-004"},
		{"CKV_K8S_29", `Apply security context to your pods and containers`, "TATAR-CON-008"},
		{"CKV_K8S_31", `Ensure that the seccomp profile is set to docker/default or runtime/default`, "TATAR-CON-011"},
		{"CKV_K8S_35", `Prefer using secrets as files over secrets as environment variables`, "TATAR-SEC-001"},
		{"CKV_K8S_37", `Minimize the admission of containers with capabilities assigned`, "TATAR-CON-004"},
		{"CKV_K8S_38", `Ensure that Service Account Tokens are only mounted where necessary`, "TATAR-SEC-003"},
		{"CKV_K8S_39", `Do not use the CAP_SYS_ADMIN linux capability`, "TATAR-CON-004"},
		{"CKV_K8S_49", `Minimize wildcard use in Roles and ClusterRoles`, "TATAR-RBAC-002"},
		{"CKV_K8S_155", `Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations`, "TATAR-RBAC-003"},
		{"CKV_K8S_156", `Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests`, "TATAR-RBAC-003"},
		{"CKV_K8S_157", `Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings`, "TATAR-RBAC-003"},
		{"CKV_K8S_158", `Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles`, "TATAR-RBAC-003"},
		{"CKV2_K8S_6", `Minimize the admission of pods which lack an associated NetworkPolicy`, "TATAR-NET-001"},
	}
	for _, w := range want {
		ids, ok := reg.Resolve("checkov", w.code)
		if !ok || len(ids) != 1 {
			t.Errorf("%s (%s): зураглал олдсонгүй/олон (%v)", w.code, w.meaning, ids)
			continue
		}
		if ids[0] != w.control {
			t.Errorf("%s (%s) -> %s, хүлээсэн %s", w.code, w.meaning, ids[0], w.control)
		}
	}
	// Буруу байсан хоёр ID дахин зурагдаж болохгүй.
	for _, bad := range []string{"CKV_K8S_43", "CKV_K8S_27"} {
		if ids, ok := reg.Resolve("checkov", bad); ok {
			t.Errorf("%s дахин зурагдсан (-> %v). 43=digest (:latest БИШ), 27=docker socket (hostPath БИШ) — v2-д тусдаа control", bad, ids)
		}
	}
	// Зураглагдсан CKV код бүр дээрх жагсаалтад байх ёстой.
	known := map[string]bool{}
	for _, w := range want {
		known[w.code] = true
	}
	for _, c := range reg.Controls {
		for _, code := range c.Mappings["checkov"] {
			if !known[code] {
				t.Errorf("%s: %s зураглагдсан ч утга батлагдаагүй — checkov-ийн бодит гаралт/эх кодоос шалгаж тестэд нэм", c.ID, code)
			}
		}
	}
}

// Trivy-ийн KSV кодууд. Аудитаар зурагдсан 11 нь БҮГД зөв байсан (Popeye 7/10,
// Checkov 2/18 буруу байсантай харьцуулахад цэвэр) — тэр байдлыг бэхэлж, шинээр
// батлагдсан 6 кодыг нэмэв. Утгуудыг `trivy config`-ийн бодит гаралтаас (trivy
// 0.74, Misconfigurations[].Title) авав.
func TestTrivyMappingsMatchUpstreamMeaning(t *testing.T) {
	reg, err := Load(regPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ code, meaning, control string }{
		{"KSV-0001", `Can elevate its own privileges`, "TATAR-CON-003"},
		{"KSV-0003", `Default capabilities: some containers do not drop all`, "TATAR-CON-004"},
		{"KSV-0004", `Default capabilities: some containers do not drop all`, "TATAR-CON-004"},
		{"KSV-0009", `Access to host network`, "TATAR-CON-006"},
		{"KSV-0010", `Access to host PID`, "TATAR-CON-005"},
		{"KSV-0011", `CPU not limited`, "TATAR-CON-010"},
		{"KSV-0012", `Runs as root user`, "TATAR-CON-002"},
		{"KSV-0013", `Image tag ":latest" used`, "TATAR-IMG-003"},
		{"KSV-0014", `Root file system is not read-only`, "TATAR-CON-009"},
		{"KSV-0015", `CPU requests not specified`, "TATAR-CON-010"},
		{"KSV-0016", `Memory requests not specified`, "TATAR-CON-010"},
		{"KSV-0017", `Privileged`, "TATAR-CON-001"},
		{"KSV-0018", `Memory not limited`, "TATAR-CON-010"},
		{"KSV-0030", `Runtime/Default Seccomp profile not set`, "TATAR-CON-011"},
		{"KSV-0104", `Seccomp policies disabled`, "TATAR-CON-011"},
		{"KSV-0106", `Container capabilities must only include NET_BIND_SERVICE`, "TATAR-CON-004"},
		{"KSV-0118", `Default security context configured`, "TATAR-CON-008"},
	}
	for _, w := range want {
		// Бодит Trivy "KSV-0017" (зураастай) гаргадаг, registry-д "AVD-KSV0017" —
		// NormalizeRuleID хоёуланг нэг түлхүүр болгодгийг мөн шалгаж байна.
		ids, ok := reg.Resolve("trivy", w.code)
		if !ok || len(ids) != 1 {
			t.Errorf("%s (%s): зураглал олдсонгүй/олон (%v)", w.code, w.meaning, ids)
			continue
		}
		if ids[0] != w.control {
			t.Errorf("%s (%s) -> %s, хүлээсэн %s", w.code, w.meaning, ids[0], w.control)
		}
	}
	// ЗОРИУДААР зураглаагүй: тохирох canonical control байхгүй (v2). Эдгээр нь
	// зурагдвал утга гуйвна — ж: "UID <= 10000" нь "root эрхээр ажиллах" БИШ.
	for _, code := range []string{"KSV-0020", "KSV-0021", "KSV-0110"} {
		if ids, ok := reg.Resolve("trivy", code); ok {
			t.Errorf("%s зурагдсан (-> %v) — 0020/0021 нь low UID/GID (root БИШ), 0110 нь default namespace; тусдаа control хэрэгтэй (v2)", code, ids)
		}
	}
}
