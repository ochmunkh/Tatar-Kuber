package canonical

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ── Хоёр хэлт README-ийн зөрүүг машинаар барих ───────────────────────────────
//
// README нь НЭГ бүтээгдэхүүнийг хоёр хэлээр тайлбарладаг тул тоо, флаг, хэсэг
// бүр нь хоёр хувьтай. Git-ийн түүх үүнийг гараар нөхсөн commit-уудаар дүүрэн
// (1a592cd "хуучирсан баримт ба монгол хэллэгийг цэвэрлэв", 9c7106a
// "CONTRIBUTING 12->14 packages"), бас `go test ./...`-ийн багцын тоо
// README-д 17, CONTRIBUTING-д 15 гэж ЗӨРСӨН байв — хэн ч анзаараагүй.
//
// Төслийн зарчим нь "гэрээ бүрийг тест барина": docs/coverage.md-г
// coverage_test.go, docs/releases/-ийг .github/workflows/release-notes.yml
// барьдаг. Хоёр хэлт README нь хамгийн их хөдөлдөг, хамгийн их давхардалтай,
// гэтэл ямар ч шалгалтгүй байсан баримт. Энэ тест гурван ОБЬЕКТИВ зүйлийг л
// шалгана — хэллэгийн чанар, хэсгийн урт зэрэг нь зохиогчийн эрх.
//
// Санаатайгаар ХИЙХГҮЙ зүйл: "хоёр хэсэгт ижил тоонууд байх" гэсэн шалгалт.
// Англи хэсэг нь badge-ийн хувилбар, огноо, зураглалын аудитын дүнг дангаараа
// агуулдаг тул тэр шалгалт эмзэг (brittle) бөгөөд хуурамч алдаа гаргана.

const (
	readmePath       = "../../README.md"
	contributingPath = "../../CONTRIBUTING.md"
	moduleRoot       = "../.."

	// mnMarker — хоёр хэсгийн зааг.
	mnMarker = "## Монгол хэл дээр"
)

func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s уншигдсангүй: %v", path, err)
	}
	return string(b)
}

// splitHalves — README-г англи / монгол хоёр хэсэгт хуваана.
func splitHalves(t *testing.T) (en, mn string) {
	t.Helper()
	src := readDoc(t, readmePath)
	i := strings.Index(src, mnMarker)
	if i < 0 {
		t.Fatalf("%s: '%s' зааг олдсонгүй — монгол хэсэг нь БҮТЭЭГДЭХҮҮНИЙ шийдвэр, устгагдах ёсгүй",
			readmePath, mnMarker)
	}
	return src[:i], src[i:]
}

// countTestPackages — модулийн мод дотор `*_test.go` агуулсан хавтасны тоо.
//
// `go list`-ийг ЗОРИУДААР дуудахгүй: тест нь сүлжээ/кэшгүй sandbox-д ч ажиллах
// ёстой, мөн дэд процесс ажиллуулах нь энэ шалгалтад шаардлагагүй.
func countTestPackages(t *testing.T) int {
	t.Helper()
	dirs := map[string]bool{}
	err := filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), "_test.go") {
			dirs[filepath.Dir(path)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("модулийн модыг уншиж чадсангүй: %v", err)
	}
	return len(dirs)
}

// TestREADMEPackageCount — "N packages" гэсэн тоо БҮГД бодит багцын тоотой
// тэнцэх ёстой (README badge, README EN/MN Build, CONTRIBUTING хоёр газар).
func TestREADMEPackageCount(t *testing.T) {
	want := countTestPackages(t)
	if want == 0 {
		t.Fatal("*_test.go агуулсан хавтас олдсонгүй — walk буруу байна")
	}

	// badge: tests-18%20packages%20green | текст: "# 18 packages" / "# 18 багц"
	badge := regexp.MustCompile(`tests-(\d+)%20packages%20green`)
	prose := regexp.MustCompile(`#\s*(\d+)\s+(?:packages|багц)`)

	for _, path := range []string{readmePath, contributingPath} {
		src := readDoc(t, path)
		found := 0
		for _, re := range []*regexp.Regexp{badge, prose} {
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				found++
				if m[1] != strconv.Itoa(want) {
					t.Errorf("%s: %q гэж бичсэн боловч бодит нь %d багц\n"+
						"  тест нэмэх/хасахад хоёр хэсэг БОЛОН CONTRIBUTING-ийг дагуулж шинэчилнэ",
						path, m[0], want)
				}
			}
		}
		if found == 0 {
			t.Errorf("%s: багцын тоо олдсонгүй — бичиглэл өөрчлөгдсөн бол энэ тестийн "+
				"regexp-ийг дагуулж шинэчилнэ (эс бөгөөс шалгалт чимээгүй унтарна)", path)
		}
	}
}

// flagToken — `--flag`. Монгол хэсэгт флагт нөхцөл шилжих дагавар хэлбэрээр
// (`--raw-dir-ээр`) залгагддаг тул төгсгөлийн зураасыг хална.
var flagToken = regexp.MustCompile(`--[A-Za-z][A-Za-z0-9-]*`)

func flagSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range flagToken.FindAllString(s, -1) {
		out[strings.TrimRight(m, "-")] = true
	}
	return out
}

// TestREADMEFlagParity — хоёр хэсэг НЭГ ижил флагийн олонлогийг баримтжуулах
// ёстой. Нэг хэл дээр л бичигдсэн флаг бол тэр хэлний уншигчийн чадвар нь
// БУУРСАН гэсэн үг (орчуулгын нарийн ажил биш).
//
// Тоог БИШ, олонлогийг шалгана: англи хэсэг нь монголд байхгүй хэсгүүд
// (`## CI/CD gate`, `## Contributing`, `## License`) агуулдаг тул нэг флаг тэнд
// илүү давтагдана. Давтамжийг шаардвал хоёр хэлт бүтэн дахин бичихийг
// шаардана — энэ тестийн зорилго тэр биш.
func TestREADMEFlagParity(t *testing.T) {
	en, mn := splitHalves(t)
	e, m := flagSet(en), flagSet(mn)

	report := func(from, to string, only map[string]bool, other map[string]bool) {
		var miss []string
		for f := range only {
			if !other[f] {
				miss = append(miss, f)
			}
		}
		sort.Strings(miss)
		if len(miss) > 0 {
			t.Errorf("%s хэсэгт баримтжуулсан флаг %s хэсэгт АЛГА: %v", from, to, miss)
		}
	}
	report("Англи", "монгол", e, m)
	report("Монгол", "англи", m, e)
}

// enToMN — англи хэсгийн гарчиг -> монгол хэсгийн гарчиг. Шинэ хэсэг нэмэхэд
// энд бүртгэгдэх ёстой, эс бөгөөс тест унана — нэг хэл дээр л нэмэгдсэн хэсэг
// PR дээр баригдана.
var enToMN = map[string]string{
	"Deduplication in action (`3 findings → 1`)": "Давхардлыг арилгах жишээ (`3 finding → 1`)",
	"Design principles":                          "Гол зарчим",
	"Scanner stack":                              "Scanner-ууд",
	"Features":                                   "Онцлог",
	"Scope & positioning":                        "Хамрах хүрээ (Scope)",
	"Install":                                    "Суулгах",
	"Quick start (offline, no cluster, no scanner install)": "Түргэн эхлэл (offline — cluster ба scanner суулгах шаардлагагүй)",
	"Architecture": "Архитектур",
	"Build":        "Build",
	"CLI":          "CLI командууд",
	"Live Mode B — granting read-only access": "Live Mode B — read-only хандалт олгох",
	"Exit codes": "Exit code",
	"Adopting the gate on an existing cluster": "Байгаа кластерт gate нэвтрүүлэх",
	"Documentation": "Баримт бичиг",
	"Status":        "Төлөв",
	"Security":      "Аюулгүй байдал",
	"Contact":       "Холбоо барих",
}

// enOnlyHeadings / mnOnlyHeadings — ӨНӨӨДРИЙН мэдэгдэж байгаа тэнцвэргүй
// хэсгүүд. Эдгээрийг хоёр хэл дээр болгох эсэх нь ЗОХИОГЧИЙН бүтээгдэхүүний
// шийдвэр, тестийн зүйл биш — тиймээс энд ил бүртгэж, тестийг ОДОО ажиллуулах
// боломжтой болгож байна. Зорилго нь ДАРААГИЙН тэнцвэргүй хэсгийг барих.
var enOnlyHeadings = map[string]bool{
	"Report — one issue, every scanner, both languages": true,
	"CI/CD gate":   true,
	"Contributing": true,
	"License":      true,
}

var mnOnlyHeadings = map[string]bool{
	"Туршилтын лаборатори": true,
	// Монгол хэсгийн өөрийн гарчиг (зааг).
	"Монгол хэл дээр": true,
}

var headingLine = regexp.MustCompile(`^#{2,3}\s+(.*)$`)

// headings — markdown гарчгууд. ``` блок дотор `# ...` нь shell тайлбар тул
// тоолохгүй.
func headings(half string) []string {
	var out []string
	fence := false
	for _, l := range strings.Split(half, "\n") {
		if strings.HasPrefix(l, "```") {
			fence = !fence
			continue
		}
		if fence {
			continue
		}
		if m := headingLine.FindStringSubmatch(l); m != nil {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return out
}

// TestREADMEHeadingParity — нэг хэл дээр нэмэгдсэн хэсэг нөгөөд мирорлогдох
// эсвэл дээрх зөрүүний жагсаалтад ил бүртгэгдэх ёстой.
func TestREADMEHeadingParity(t *testing.T) {
	enHalf, mnHalf := splitHalves(t)
	enHeads, mnHeads := headings(enHalf), headings(mnHalf)

	mnPresent := map[string]bool{}
	for _, h := range mnHeads {
		mnPresent[h] = true
	}

	for _, h := range enHeads {
		want, mapped := enToMN[h]
		switch {
		case enOnlyHeadings[h]:
			// Ил бүртгэгдсэн зөрүү — зөвшөөрөгдөнө.
		case !mapped:
			t.Errorf("англи хэсгийн '%s' гарчиг enToMN-д бүртгэгдээгүй\n"+
				"  -> монгол хэсэгт мирор нэмж enToMN-д бүртгэнэ, эсвэл зориуд англи "+
				"дээр л байх бол enOnlyHeadings-д бүртгэнэ", h)
		case !mnPresent[want]:
			t.Errorf("англи '%s' -> монгол '%s' гэж бүртгэгдсэн боловч монгол хэсэгт тэр гарчиг АЛГА", h, want)
		}
	}

	mnMapped := map[string]bool{}
	for _, v := range enToMN {
		mnMapped[v] = true
	}
	for _, h := range mnHeads {
		if !mnMapped[h] && !mnOnlyHeadings[h] {
			t.Errorf("монгол хэсгийн '%s' гарчиг англи хэсэгт хамааралгүй\n"+
				"  -> англи мирор нэмж enToMN-д бүртгэнэ, эсвэл mnOnlyHeadings-д бүртгэнэ", h)
		}
	}
}
