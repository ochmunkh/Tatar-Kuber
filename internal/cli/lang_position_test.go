package cli

import (
	"os"
	"reflect"
	"testing"
)

// Глобал `--lang` нь КОМАНДЫН ӨМНӨ бичигдэж болно. setLang нь утгыг уншдаг ч
// аргументаас ХАСдаггүй байсан тул os.Args[1] нь "--lang" хэвээр үлдэж,
// Execute-ийн switch түүнийг команд гэж үзэн exit 3 буцаадаг байв —
// `--lang en|mn` гэж тусламжийн бичвэрт ерөнхий флаг гэж бичсэн хэрнээ.
func TestStripLeadingLang(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"хос хэлбэр", []string{"--lang", "mn", "--help"}, []string{"--help"}},
		{"тэнцүү хэлбэр", []string{"--lang=mn", "--help"}, []string{"--help"}},
		{"нэг зураас", []string{"-lang", "mn", "version"}, []string{"version"}},
		{"нэг зураас тэнцүү", []string{"-lang=mn", "version"}, []string{"version"}},
		{"утгагүй", []string{"--lang"}, []string{}},
		{"давхар", []string{"--lang", "mn", "--lang=en", "doctor"}, []string{"doctor"}},
		{"флаггүй", []string{"report", "--lang", "mn"}, []string{"report", "--lang", "mn"}},
		{"командын дараах нь хөндөгдөхгүй", []string{"scan", "--lang=mn"}, []string{"scan", "--lang=mn"}},
		{"хоосон", []string{}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripLeadingLang(c.in)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("stripLeadingLang(%q) = %q, хүлээсэн %q", c.in, got, c.want)
			}
		})
	}
}

// Execute нь команд сонгохоосоо өмнө глобал --lang-ийг хасаж байгаа эсэх.
// `version` нь гаднын файл шаарддаггүй цорын ганц команд тул үүгээр шалгав.
func TestExecuteAcceptsGlobalLangBeforeCommand(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig; setLang(nil) }()

	for _, args := range [][]string{
		{"tatar-kuber", "--lang", "mn", "version"},
		{"tatar-kuber", "--lang=mn", "version"},
		{"tatar-kuber", "-lang", "en", "version"},
		{"tatar-kuber", "version"},
	} {
		os.Args = args
		if code := Execute(); code != 0 {
			t.Errorf("Execute(%q) = %d, хүлээсэн 0", args, code)
		}
	}

	// Танигдаагүй хэл нь хаана бичигдсэнээс үл хамааран хэрэглээний алдаа (3).
	os.Args = []string{"tatar-kuber", "--lang", "de", "version"}
	if code := Execute(); code != 3 {
		t.Errorf("Execute(--lang de version) = %d, хүлээсэн 3", code)
	}
}

// Дараах хоёр бичиглэл ИЖИЛ хэлээр хэвлэх ёстой:
//
//	tatar-kuber --lang mn <cmd>
//	tatar-kuber <cmd> --lang mn
//
// Өмнө нь эхнийх нь АНГЛИАР хэвлэдэг байв. Execute хэлийг уншаад аргументаас
// хасдаг; команд бүр дараа нь setLang(args)-ыг дахин дууддаг (`report --lang de`
// нь хаана ч бичигдсэн хэрэглээний алдаа байхын тулд), тэр хоёр дахь дуудлага нь
// эхлээд uiLang-ыг default руу БУЦААГААД, хасагдсан флагийг олохгүй байсан.
//
// lang_position_test.go-гийн бусад тест нь dispatch талыг л (--lang нь команд
// гэж андуурагдахгүй) шалгадаг. Энэ нь ГАРАЛТЫН талыг шалгана.
func TestGlobalLangReachesTheCommandOutput(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig; setLang(nil) }()

	// Execute-ийн хийдгийг яг давтана: хэлээ уншиж, командын нэр олохын тулд
	// глобал флагийг хасаад, команд руу дамжуулахдаа буцааж наана. Дараа нь
	// команд өөрөө setLang-ыг дахин дуудахыг дуурайлгана.
	run := func(args ...string) string {
		os.Args = append([]string{"tatar-kuber"}, args...)
		if _, code := setLang(os.Args[1:]); code != 0 {
			t.Fatalf("setLang(%q) = %d", args, code)
		}
		rest := stripLeadingLang(os.Args[1:])
		lead := os.Args[1 : len(os.Args)-len(rest)]
		cmdArgs := append(append([]string{}, lead...), rest[1:]...)
		if _, code := setLang(cmdArgs); code != 0 {
			t.Fatalf("setLang(%q) = %d", cmdArgs, code)
		}
		return uiLang
	}

	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"глобал --lang mn", []string{"--lang", "mn", "doctor"}, "mn"},
		{"глобал --lang=mn", []string{"--lang=mn", "doctor"}, "mn"},
		{"командын --lang mn", []string{"doctor", "--lang", "mn"}, "mn"},
		{"глобал --lang en", []string{"--lang", "en", "doctor"}, "en"},
		{"флаггүй", []string{"doctor"}, "en"},
		{"командынх глобалыг дарна", []string{"--lang", "mn", "doctor", "--lang", "en"}, "en"},
	} {
		if got := run(c.args...); got != c.want {
			t.Errorf("%s: %q -> uiLang=%q, хүлээсэн %q", c.name, c.args, got, c.want)
		}
	}
}
