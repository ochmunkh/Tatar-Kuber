package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ── Мессежийн каталогийн бүрэн байдал ────────────────────────────────────────
//
// Хоёр хэлт гаралтын чимээгүй эвдрэл нь ҮРГЭЛЖ нэг л хэлбэртэй: код нэг хэлээр
// нэмэгдэж, нөгөө нь хоцорно. README-гийн хоёр хэсгийг readme_test.go барьдаг
// шиг binary-ийн хоёр хэлийг энэ тест барина. Нэг ч алхам гараар шалгахгүй.

var (
	msgCall  = regexp.MustCompile(`\bmsg\(\s*"([^"]+)"`)
	langCall = regexp.MustCompile(`\baddLangFlag\([^,]+,\s*"([^"]+)"\s*\)`)
)

// sourceIDs — багцын (тестээс бусад) эх кодод дуудагдсан мессежийн ID-ууд.
func sourceIDs(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("багцын хавтас уншигдсангүй: %v", err)
	}
	ids := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, re := range []*regexp.Regexp{msgCall, langCall} {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				ids[m[1]] = true
			}
		}
	}
	if len(ids) == 0 {
		t.Fatal("эх кодоос нэг ч msg(\"...\") олдсонгүй — regexp хуучирсан байна")
	}
	return ids
}

// TestCatalogHasEveryLanguage — бичлэг бүр en-тэй, мөн mn-тэй байх ёстой.
// mn нь ЗӨВХӨН awaitingMN-д ил бүртгэгдсэн үед дутаж болно: орчуулгын цоорхой
// нь код дотор ил, тоологдохуйц байх ёстой, нуугдах ёсгүй.
func TestCatalogHasEveryLanguage(t *testing.T) {
	known := map[string]bool{}
	for _, l := range uiLangs {
		known[l] = true
	}
	for id, txt := range catalog {
		for lang := range txt {
			if !known[lang] {
				t.Errorf("%s: '%s' хэл uiLangs-д алга", id, lang)
			}
		}
		if strings.TrimSpace(txt["en"]) == "" {
			t.Errorf("%s: en бичвэр дутуу — en бол default БӨГӨӨД бусад хэлний унах цэг", id)
		}
		switch mn := strings.TrimSpace(txt["mn"]); {
		case mn == "" && !awaitingMN[id]:
			t.Errorf("%s: mn бичвэр дутуу\n"+
				"  -> монголоор бичиж нэмнэ, эсвэл хараахан бичигдээгүй бол awaitingMN-д бүртгэнэ", id)
		case mn != "" && awaitingMN[id]:
			t.Errorf("%s: mn бичвэр бий атлаа awaitingMN-д үлдсэн — жагсаалтаас хасна", id)
		}
	}
	for id := range awaitingMN {
		if _, ok := catalog[id]; !ok {
			t.Errorf("awaitingMN-д '%s' байгаа ч каталогт тийм ID алга", id)
		}
	}
}

// TestCatalogMatchesSource — дуудагдсан ID бүр каталогт байх ба каталогийн
// бичлэг бүр дуудагдсан байх ёстой. Эхнийх нь ажиллах үед ID нь өөрөө хэвлэгдэх
// (харагдах алдаа) байдлаас, хоёр дахь нь хуучирсан бичвэр хуримтлагдахаас
// хамгаална.
func TestCatalogMatchesSource(t *testing.T) {
	used := sourceIDs(t)

	var missing, unused []string
	for id := range used {
		if _, ok := catalog[id]; !ok {
			missing = append(missing, id)
		}
	}
	for id := range catalog {
		if !used[id] {
			unused = append(unused, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(unused)

	if len(missing) > 0 {
		t.Errorf("кодод дуудагдсан ч каталогт байхгүй ID: %v", missing)
	}
	if len(unused) > 0 {
		t.Errorf("каталогт байгаа ч хаана ч дуудагдаагүй ID: %v\n"+
			"  -> хэрэглээгүй бичвэр устгана (эс бөгөөс орчуулгын ачаа утгагүй өснө)", unused)
	}
}

// TestMissingMNFallsBackToEnglish — mn дутуу бичвэр нь ХООСОН МӨР биш, англи
// хувилбараараа гарах ёстой. Хоосон мөр нь хамгийн муу үр дүн: хэрэглэгч
// анхааруулга огт байхгүй гэж ойлгоно.
func TestMissingMNFallsBackToEnglish(t *testing.T) {
	restore := uiLang
	defer func() { uiLang = restore }()

	uiLang = "mn"
	for id := range awaitingMN {
		got := msg(id)
		if got == "" {
			t.Errorf("%s: mn дутуу үед хоосон мөр буцлаа", id)
		}
		if got != catalog[id]["en"] {
			t.Errorf("%s: mn дутуу үед en рүү унах ёстой, got %q", id, got)
		}
	}
}

// TestSetLangPrecedence — --lang > $TATAR_LANG > en, танигдаагүй утга нь
// хэрэглээний алдаа (exit 3). Сүүлийнх нь `report --lang de`-ийн өнөөгийн
// гэрээ — README-ийн exit code хүснэгтэд бичигдсэн тул зөрчигдөж болохгүй.
func TestSetLangPrecedence(t *testing.T) {
	restore := uiLang
	defer func() { uiLang = restore }()

	for _, tc := range []struct {
		name     string
		env      string
		args     []string
		want     string
		explicit bool
		code     int
	}{
		{name: "default", want: "en"},
		{name: "env", env: "mn", want: "mn", explicit: true},
		{name: "флаг", args: []string{"--lang", "mn"}, want: "mn", explicit: true},
		{name: "флаг=", args: []string{"--lang=mn"}, want: "mn", explicit: true},
		{name: "нэг зураас", args: []string{"-lang", "mn"}, want: "mn", explicit: true},
		{name: "флаг нь env-ийг дарна", env: "mn", args: []string{"--lang", "en"}, want: "en", explicit: true},
		{name: "-- дараах", args: []string{"--", "--lang", "mn"}, want: "en"},
		{name: "танигдаагүй", args: []string{"--lang", "de"}, want: "en", code: 3},
		{name: "танигдаагүй env", env: "de", want: "en", code: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TATAR_LANG", tc.env)
			explicit, code := setLang(tc.args)
			if code != tc.code {
				t.Errorf("exit=%d, want %d", code, tc.code)
			}
			if explicit != tc.explicit {
				t.Errorf("explicit=%v, want %v", explicit, tc.explicit)
			}
			if uiLang != tc.want {
				t.Errorf("uiLang=%q, want %q", uiLang, tc.want)
			}
		})
	}
}

// TestEveryCommandAcceptsLang — `--lang` бүх командад ижил ажиллах ёстой:
// нэг нь хүлээж авдаг, нөгөө нь "flag provided but not defined" гээд exit 2
// буцаадаг бол хэрэглэгч тэр ялгааг цээжлэх шаардлагагүй.
func TestEveryCommandAcceptsLang(t *testing.T) {
	restore := uiLang
	defer func() { uiLang = restore }()

	out := t.TempDir()
	if code := cmdScan([]string{"--raw-dir", "../../examples/demo", "--lang", "mn", "-o", out}); code != 0 {
		t.Fatalf("scan --lang mn exit=%d", code)
	}
	res := filepath.Join(out, "scan-result.json")

	expected := writeExpectedPass(t, out)

	for _, tc := range []struct {
		name string
		run  func(lang string) int
	}{
		{"scan", func(l string) int {
			return cmdScan([]string{"--raw-dir", "../../examples/demo", "--lang", l, "-o", filepath.Join(out, l)})
		}},
		{"report", func(l string) int {
			return cmdReport([]string{"--input", res, "--format", "json", "--lang", l, "--out", filepath.Join(out, "r-"+l+".json")})
		}},
		{"gate", func(l string) int {
			return cmdGate([]string{"--input", res, "--policy", filepath.Join(out, "none.yaml"), "--lang", l})
		}},
		{"diff", func(l string) int { return cmdDiff([]string{"--old", res, "--new", res, "--lang", l}) }},
		{"doctor", func(l string) int { return cmdDoctor([]string{"--lang", l}) }},
		// `--dry-run` нь сүлжээнд хүрэхгүй; `--scanner trivy` нь дөрвөн
		// платформ дэмждэг тул тест ажиллуулагч машинаас хамаарахгүй.
		{"update", func(l string) int {
			return cmdUpdate([]string{"--scanner", "trivy", "--dry-run", "--home", filepath.Join(out, "home"), "--lang", l})
		}},
		{"verify-lab", func(l string) int {
			return cmdVerifyLab([]string{"--input", res, "--expected", expected, "--lang", l})
		}},
	} {
		// Хүчинтэй хэл нь ХЭЗЭЭ Ч хэрэглээний алдаа болохгүй. (Тухайн командын
		// 0/1 нь бодлого, суусан scanner-аас хамаарах тул тэр биш, 3 биш гэдгийг
		// шалгана.) Хэрэв команд --lang-ыг огт танихгүй бол flag.ExitOnError нь
		// процессыг exit 2-оор унагаах тул тест бүхэлдээ зогсоно — тэр ч мөн
		// адил барих зорилготой.
		for _, lang := range uiLangs {
			if code := tc.run(lang); code == 3 {
				t.Errorf("%s --lang %s: exit=3 — хүчинтэй хэл татгалзагдав", tc.name, lang)
			}
		}
		// Танигдаагүй хэл нь команд БҮРТ ижилхэн exit 3.
		if code := tc.run("de"); code != 3 {
			t.Errorf("%s --lang de: exit=%d, want 3", tc.name, code)
		}
	}
}
