// Package schema нь Go код агуулдаггүй — зөвхөн нийтлэгдсэн JSON Schema-г
// барих тест агуулна.
//
// tatar-schema-v1.json нь scan-result.json-ы НИЙТЛЭГДСЭН гэрээ: adopter нь
// baseline болгож commit хийдэг, downstream хэрэгсэл нь parse хийдэг. Гэтэл
// өмнө нь түүнийг хаанаас ч заадаггүй, ямар ч тест барьдаггүй байсан тул
// Go бүтэц өөрчлөгдөхөд ЗӨВХӨН гараар (ж: f1ce143 "refresh pkg JSON schema")
// нөхөгддөг байв — "гэрээ бүрийг тест барина" гэсэн төслийн зарчимд нийцэхгүй.
//
// Энэ тест шинэ хамаарал нэмэхгүй (README-ийн "ганц шууд хамаарал" гэсэн
// мэдэгдэл хүчинтэй хэвээр): JSON Schema validator ашиглахгүй, харин Go
// бүтцийн `json:` тэгүүд ба схемийн `properties` ХОЁР ОЛОНЛОГИЙГ тулгана.
// Тиймээс талбар нэмэхэд/хасахад схем мартагдвал тест унана.
package schema

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

const schemaPath = "tatar-schema-v1.json"

// jsonSchema — шалгахад хэрэгтэй хэсэг нь л (бусад keyword-ыг хөндөхгүй).
type jsonSchema struct {
	ID         string                     `json:"$id"`
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
	Defs       map[string]jsonSchema      `json:"$defs"`
}

func load(t *testing.T) jsonSchema {
	t.Helper()
	b, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("%s уншигдсангүй: %v", schemaPath, err)
	}
	var s jsonSchema
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("%s нь хүчинтэй JSON биш: %v", schemaPath, err)
	}
	return s
}

// jsonTags — бүтцийн `json:` тэгүүдийн олонлог ("-" ба тэггүйг алгасна).
func jsonTags(t *testing.T, v interface{}) map[string]bool {
	t.Helper()
	rt := reflect.TypeOf(v)
	out := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		out[name] = true
	}
	return out
}

// TestSchemaMatchesGoStructs — схемийн `properties` ба Go бүтцийн талбарууд
// ЯГ тохирох ёстой. Аль нэг талд байгаад нөгөөд байхгүй бол зөрүү.
func TestSchemaMatchesGoStructs(t *testing.T) {
	s := load(t)
	if s.ID == "" {
		t.Error("$id хоосон — нийтлэгдсэн схемийг downstream заах боломжгүй")
	}

	cases := []struct {
		name  string
		props map[string]json.RawMessage
		want  map[string]bool
	}{
		{"ScanResult (root)", s.Properties, jsonTags(t, finding.ScanResult{})},
		{"metadata", s.Defs["metadata"].Properties, jsonTags(t, finding.Metadata{})},
		{"summary", s.Defs["summary"].Properties, jsonTags(t, finding.Summary{})},
		{"finding", s.Defs["finding"].Properties, jsonTags(t, finding.Finding{})},
	}

	for _, c := range cases {
		if len(c.props) == 0 {
			t.Errorf("%s: схемд properties алга", c.name)
			continue
		}
		var missing, extra []string
		for name := range c.want {
			if _, ok := c.props[name]; !ok {
				missing = append(missing, name)
			}
		}
		for name := range c.props {
			if !c.want[name] {
				extra = append(extra, name)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 {
			t.Errorf("%s: Go-д байгаа атлаа схемд АЛГА: %v\n"+
				"  -> %s-д property нэмнэ үү", c.name, missing, schemaPath)
		}
		if len(extra) > 0 {
			t.Errorf("%s: схемд байгаа атлаа Go-д АЛГА: %v\n"+
				"  -> талбар хасагдсан бол %s-ээс ч хасна уу", c.name, extra, schemaPath)
		}
	}
}

// TestSchemaRequiredAreKnownProperties — `required` дотор бичиглэлийн алдаа
// байвал ямар ч validator түүнийг "хэзээ ч биелэхгүй" болгож, схем чимээгүй
// хэрэгсэхгүй болно.
func TestSchemaRequiredAreKnownProperties(t *testing.T) {
	s := load(t)
	check := func(name string, sub jsonSchema) {
		for _, req := range sub.Required {
			if _, ok := sub.Properties[req]; !ok {
				t.Errorf("%s: required '%s' нь properties-д байхгүй", name, req)
			}
		}
	}
	check("root", s)
	for name, sub := range s.Defs {
		check("$defs/"+name, sub)
	}
}
