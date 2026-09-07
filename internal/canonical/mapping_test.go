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
	// C-0018 нь ЗӨВХӨН readiness (liveness нь C-0056) — multi-candidate биш болов.
	if id, _ := rs.ResolveOne("kubescape", "C-0018", ResolverContext{}); id != "TATAR-OPS-001" {
		t.Errorf("C-0018 -> %s, want TATAR-OPS-001", id)
	}
	if id, _ := rs.ResolveOne("kubescape", "C-0056", ResolverContext{}); id != "TATAR-OPS-002" {
		t.Errorf("C-0056 -> %s, want TATAR-OPS-002", id)
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

// Kubescape-ийн C-XXXX кодууд. Аудитаар 28 зураглалын 6 нь зөрсөн — түүний дотор
// ХОЁР ХОС сольж бичигдсэн байв:
//
//	C-0187 "Minimize wildcard use in Roles and ClusterRoles" -> RBAC-005 "Default
//	  service account" гэж зурагдсан; жинхэнэ гэр нь RBAC-002 (wildcard).
//	C-0272 "Workload with administrative roles" -> RBAC-002 (wildcard) гэж
//	  зурагдсан; жинхэнэ гэр нь RBAC-001 (admin/cluster-admin).
//	C-0078 "Images from allowed registry" -> IMG-001/IMG-002 (image CVE) гэж CVE
//	  severity-ээр зурагдсан. Kubescape image CVE scan ХИЙДЭГГҮЙ — жинхэнэ гэр нь
//	  IMG-004 (unapproved registry).
//	C-0079 нь "CVE-2022-0185-linux-kernel-container-escape" (тодорхой нэг CVE)
//	  байхад IMG-004 "unapproved registry" гэж зурагдсан.
//	C-0075 "Image pull policy on latest tag" -> IMG-003 ":latest tag" гэж
//	  зурагдсан; энэ нь imagePullPolicy-ийн шалгалт тул OPS-005.
//	C-0018 нь ЗӨВХӨН readiness probe; liveness нь тусдаа control C-0056. Гэтэл
//	  C-0018-ыг selector-оор OPS-001/OPS-002 хоёуланд зураглаж байв.
//
// Утгуудыг бодит kubescape 4.0 гаралт (results[].controls[].name) ба upstream-ийн
// control каталог (hub.armosec.io/docs/controls)-аас батлав.
func TestKubescapeMappingsMatchUpstreamMeaning(t *testing.T) {
	reg, err := Load(regPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ code, meaning, control string }{
		{"C-0002", `Prevent containers from allowing command execution`, "TATAR-RBAC-003"},
		{"C-0007", `Roles with delete capabilities`, "TATAR-RBAC-003"},
		{"C-0009", `Resource limits`, "TATAR-CON-010"},
		{"C-0012", `Applications credentials in configuration files`, "TATAR-SEC-001"},
		{"C-0013", `Non-root containers`, "TATAR-CON-002"},
		{"C-0015", `List Kubernetes secrets`, "TATAR-RBAC-003"},
		{"C-0016", `Allow privilege escalation`, "TATAR-CON-003"},
		{"C-0017", `Immutable container filesystem`, "TATAR-CON-009"},
		{"C-0018", `Configured readiness probe`, "TATAR-OPS-001"},
		{"C-0030", `Ingress and Egress blocked`, "TATAR-NET-002"},
		{"C-0031", `Delete Kubernetes events`, "TATAR-RBAC-003"},
		{"C-0034", `Automatic mapping of service account`, "TATAR-SEC-003"},
		{"C-0035", `Administrative Roles`, "TATAR-RBAC-001"},
		{"C-0037", `CoreDNS poisoning`, "TATAR-RBAC-003"},
		{"C-0038", `Host PID/IPC privileges`, "TATAR-CON-005"},
		{"C-0041", `HostNetwork access`, "TATAR-CON-006"},
		{"C-0045", `Writable hostPath mount`, "TATAR-CON-007"},
		{"C-0046", `Insecure capabilities`, "TATAR-CON-004"},
		{"C-0056", `Configured liveness probe`, "TATAR-OPS-002"},
		{"C-0057", `Privileged container`, "TATAR-CON-001"},
		{"C-0063", `Portforwarding privileges`, "TATAR-RBAC-003"},
		{"C-0075", `Image pull policy on latest tag`, "TATAR-OPS-005"},
		{"C-0078", `Images from allowed registry`, "TATAR-IMG-004"},
		{"C-0186", `Minimize access to secrets`, "TATAR-RBAC-003"},
		{"C-0187", `Minimize wildcard use in Roles and ClusterRoles`, "TATAR-RBAC-002"},
		{"C-0188", `Minimize access to create pods`, "TATAR-RBAC-003"},
		{"C-0210", `Ensure that the seccomp profile is set to docker/default`, "TATAR-CON-011"},
		{"C-0211", `Apply Security Context to Your Pods and Containers`, "TATAR-CON-008"},
		{"C-0256", `External facing`, "TATAR-NET-003"},
		{"C-0260", `Missing network policy`, "TATAR-NET-001"},
		{"C-0262", `Anonymous access enabled`, "TATAR-RBAC-004"},
		{"C-0267", `Workload with cluster takeover roles`, "TATAR-RBAC-001"},
		{"C-0270", `Ensure CPU limits are set`, "TATAR-CON-010"},
		{"C-0271", `Ensure memory limits are set`, "TATAR-CON-010"},
		{"C-0272", `Workload with administrative roles`, "TATAR-RBAC-001"},
	}
	for _, w := range want {
		ids, ok := reg.Resolve("kubescape", w.code)
		if !ok || len(ids) != 1 {
			t.Errorf("%s (%s): зураглал олдсонгүй/олон (%v)", w.code, w.meaning, ids)
			continue
		}
		if ids[0] != w.control {
			t.Errorf("%s (%s) -> %s, хүлээсэн %s", w.code, w.meaning, ids[0], w.control)
		}
	}
	// ЗОРИУДААР зураглаагүй — утга гуйвуулахгүйн тулд (v2-д тусдаа control):
	//   C-0079 тодорхой нэг CVE (CVE-2022-0185), ерөнхий control биш
	//   C-0055 "Linux hardening" хэт өргөн (seccomp+apparmor+selinux+capabilities)
	//   C-0054 "Cluster internal networking" namespace түвшний segmentation
	for _, code := range []string{"C-0079", "C-0055", "C-0054"} {
		if ids, ok := reg.Resolve("kubescape", code); ok {
			t.Errorf("%s зурагдсан (-> %v) — зориудаар зураглаагүй байх ёстой", code, ids)
		}
	}
	// Kubescape image CVE scan хийдэггүй (Trivy хийдэг) — IMG-001/002-д kubescape байх ёсгүй.
	for _, cid := range []string{"TATAR-IMG-001", "TATAR-IMG-002"} {
		c, _ := reg.Get(cid)
		if len(c.Mappings["kubescape"]) != 0 {
			t.Errorf("%s: kubescape=%v — kubescape image CVE scan хийдэггүй", cid, c.Mappings["kubescape"])
		}
	}
	// Зураглагдсан код бүр дээрх жагсаалтад байх ёстой.
	known := map[string]bool{}
	for _, w := range want {
		known[w.code] = true
	}
	for _, c := range reg.Controls {
		for _, code := range c.Mappings["kubescape"] {
			if !known[code] {
				t.Errorf("%s: %s зураглагдсан ч утга батлагдаагүй — kubescape каталогоос шалгаж тестэд нэм", c.ID, code)
			}
		}
	}
}
