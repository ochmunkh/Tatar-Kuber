package schema

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// ── Урагшаа нийцтэй байдал ───────────────────────────────────────────────────
//
// tatar-schema-v1.json нь НИЙТЛЭГДСЭН гэрээ: adopter нь scan-result.json-ыг
// baseline болгож commit хийдэг, `gate --baseline` түүнийг сар, жилийн дараа
// уншина. Өчигдөр хүчинтэй байсан баримт өнөөдөр ч хүчинтэй байх ёстой.
//
// Энэ тест үүнийг барих ёстой ГАНЦ зүйлийг барина: `required`-ийн УРГАЛТ.
// Талбар нэмэх нь аюулгүй (хуучин уншигч нь үл тоомсорлоно) — харин түүнийг
// required болгох нь хуучин баримт бүрийг нэг мөрөөр хүчингүй болгоно, бас
// тэр нь санамсаргүй хийхэд хамгийн амархан нь.
//
// Тест унавал хоёр л зам бий: талбарыг сонголттой болгох, эсвэл v2 гаргах
// (pkg/schema/VERSIONING.md-г үз). Энд жагсаалтыг шинэчлээд өнгөрөх нь
// гуравдахь зам БИШ — энэ тестийн бүх утга тэр шийдвэрийг хүн гаргахад л бий.

// requiredV1 — 2026-10-18-ны байдлаар v1 ЯМАР талбаруудыг шаарддаг.
// Эрэмбэ хамаагүй; энд нэмэх нь эвддэг өөрчлөлт.
var requiredV1 = map[string][]string{
	"": {"schema_version", "metadata", "summary", "findings"},
	"metadata": {"scan_id", "cluster_name", "scan_mode", "tatar_version",
		"scanner_versions", "started_at", "finished_at", "result_hash"},
	"summary": {"counts", "blind_shot", "risk_score", "risk_band", "total_findings"},
	"finding": {"id", "canonical_control", "resource", "type", "category", "severity",
		"title", "description", "remediation", "found_by", "confidence", "blind_shot",
		"status", "first_seen", "last_seen"},
}

func TestSchema_RequiredFieldsAreFrozen(t *testing.T) {
	s := load(t)
	got := map[string][]string{"": s.Required}
	for name, def := range s.Defs {
		if len(def.Required) > 0 {
			got[name] = def.Required
		}
	}

	for name, want := range requiredV1 {
		have, ok := got[name]
		if !ok {
			t.Errorf("%s: required жагсаалт алга болсон — хэрэв зориуд бол энэ тестийг дагуулж засна",
				defName(name))
			continue
		}
		added, removed := diffSets(want, have)
		if len(added) > 0 {
			t.Errorf("%s: required-д НЭМЭГДСЭН: %s\n"+
				"  Энэ нь ЭВДДЭГ өөрчлөлт: өмнө нь хүчинтэй байсан scan-result.json бүр хүчингүй болно\n"+
				"  (adopter-ийн commit хийсэн baseline, `gate --baseline` уншдаг файлууд).\n"+
				"  Талбарыг сонголттой болгох, эсвэл v2 гаргах — pkg/schema/VERSIONING.md",
				defName(name), strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			t.Errorf("%s: required-ээс ХАСАГДСАН: %s\n"+
				"  Энэ нь уншигчдад аюулгүй ч гэрээг сулруулж байна — зориуд бол requiredV1-г засна",
				defName(name), strings.Join(removed, ", "))
		}
	}
	for name := range got {
		if _, ok := requiredV1[name]; !ok {
			t.Errorf("%s: шинэ required жагсаалт гарч ирэв (%s) — энэ нь шинэ заавал биелэх \n"+
				"  шаардлага, VERSIONING.md-ийн дагуу шийдвэр шаардана",
				defName(name), strings.Join(got[name], ", "))
		}
	}
}

// Заавал биш талбаргүй, ЗӨВХӨН required талбартай баримт нь Go бүтэц рүү
// уншигдаж, утгаа хадгалах ёстой. "Хамгийн багадаа ийм байж болно" гэдгийг
// жишээгээр тогтоосон нь тайлбараар бичсэнээс найдвартай.
func TestSchema_MinimalDocumentStillParses(t *testing.T) {
	const minimal = `{
	  "schema_version": "1.0",
	  "metadata": {
	    "scan_id": "abc", "cluster_name": "c1", "scan_mode": "offline",
	    "tatar_version": "1.0.0", "scanner_versions": {},
	    "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z",
	    "result_hash": "sha256:0"
	  },
	  "summary": {
	    "counts": {}, "blind_shot": 0, "risk_score": 100,
	    "risk_band": "LOW", "total_findings": 1
	  },
	  "findings": [{
	    "id": "TK-000000000000", "canonical_control": "TATAR-CON-001",
	    "resource": "deployment/api", "type": "misconfiguration",
	    "category": "Container Security", "severity": "HIGH",
	    "title": "t", "description": "d", "remediation": "r",
	    "found_by": ["trivy"], "confidence": "HIGH", "blind_shot": false,
	    "status": "OPEN", "first_seen": "2026-01-01T00:00:00Z",
	    "last_seen": "2026-01-01T00:00:00Z"
	  }]
	}`
	var res finding.ScanResult
	if err := json.Unmarshal([]byte(minimal), &res); err != nil {
		t.Fatalf("зөвхөн required талбартай баримт уншигдсангүй: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.ID != "TK-000000000000" || f.CanonicalControl != "TATAR-CON-001" ||
		f.Severity != finding.SeverityHigh || f.Confidence != finding.ConfidenceHigh {
		t.Errorf("утга алдагдав: %+v", f)
	}
	// Шинэ сонголттой талбарууд хоосон байх нь ХЭВИЙН — хуучин баримтад
	// байхгүй, байхгүй нь алдаа биш.
	if f.ConfidenceReason != "" {
		t.Errorf("confidence_reason = %q, хуучин баримтад хоосон байх ёстой", f.ConfidenceReason)
	}
}

// Шинэ баримт нь хуучин уншигчийг эвдэхгүй: сонголттой талбарыг мэдэхгүй
// уншигч алгасаад, required хэсэг нь бүрэн хэвээр үлдэнэ.
func TestSchema_NewOptionalFieldsAreIgnorableByOldReaders(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/demo.json")
	if err != nil {
		t.Skipf("golden корпус алга: %v", err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	for _, k := range requiredV1[""] {
		if _, ok := generic[k]; !ok {
			t.Errorf("бодит гаралтад required талбар %q алга", k)
		}
	}
	var fs []map[string]json.RawMessage
	if err := json.Unmarshal(generic["findings"], &fs); err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("golden корпус олдворгүй")
	}
	for _, k := range requiredV1["finding"] {
		if _, ok := fs[0][k]; !ok {
			t.Errorf("бодит олдворт required талбар %q алга", k)
		}
	}
}

func defName(n string) string {
	if n == "" {
		return "root"
	}
	return n
}

func diffSets(want, have []string) (added, removed []string) {
	w, h := map[string]bool{}, map[string]bool{}
	for _, s := range want {
		w[s] = true
	}
	for _, s := range have {
		h[s] = true
	}
	for s := range h {
		if !w[s] {
			added = append(added, s)
		}
	}
	for s := range w {
		if !h[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}
