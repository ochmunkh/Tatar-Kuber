package canonical

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// README нь гаргасан хамгийн сүүлийн хувилбарыг хэлэх ёстой.
//
// Хоёр удаа хазсан тул тест болов. Эхний удаа binary өөрөө 1.0.3-dev дээр
// 14 commit сууж байсныг TestDevVersionIsAheadOfLastRelease барьдаг болсон;
// хоёр дахь удаа README нь v1.0.5 гарсны дараа ч v1.0.3 гэж хэлсээр байв —
// badge дээр, build жишээн дээр, статусын мөрөнд, хоёр хэлэнд.
//
// Аюулгүй байдлын хэрэгслийн баримт кодтойгоо таарахгүй байх нь зүгээр нэг
// эмх замбараагүй байдал биш: уншигч тэрийг л үнэн гэж үзнэ.
//
// docs/releases/-ийг эх сурвалж болгож байгаа нь санаатай — release note нь
// нийтлэгдсэн хувилбартайгаа өдөр бүр тулгагддаг (release-notes.yml), тул
// энэ тест гинжин хэлхээний нэг л үзүүрт холбогдоно.
func TestREADMEMentionsTheCurrentRelease(t *testing.T) {
	latest := latestRelease(t)

	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(data)

	// Хуучин хувилбар дурдагдаж болно (түүхийн тэмдэглэл), гэхдээ ДООРХ
	// гурван газарт ОДООГИЙН хувилбар байх ёстой.
	checks := []struct{ what, want string }{
		{"release badge", "badge/release-v" + latest},
		{"build жишээ", "./scripts/build.sh " + latest},
		{"статусын мөр", "**v" + latest + "**"},
	}
	for _, c := range checks {
		if !strings.Contains(readme, c.want) {
			t.Errorf("README: %s нь %q-г агуулахгүй байна.\n"+
				"  Хамгийн сүүлд гарсан хувилбар: v%s (docs/releases/-ээс)\n"+
				"  Release гаргасны дараа README-г дагуулж шинэчилнэ — хоёр хэлэнд ч мөн адил.",
				c.what, c.want, latest)
		}
	}

	// Хоёр хэл: build жишээ ба статусын мөр хоёулаа хоёр удаа гарна.
	for _, pair := range []string{"./scripts/build.sh " + latest, "**v" + latest + "**"} {
		if n := strings.Count(readme, pair); n < 2 {
			t.Errorf("README: %q нь %d удаа гарлаа, хоёр хэлэнд тус бүр нэг удаа (2) байх ёстой",
				pair, n)
		}
	}
}

// latestRelease — docs/releases/ доторх хамгийн өндөр vX.Y.Z.
func latestRelease(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("..", "..", "docs", "releases"))
	if err != nil {
		t.Fatalf("docs/releases уншиж чадсангүй: %v", err)
	}
	re := regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)\.md$`)
	var vs [][3]int
	for _, e := range entries {
		if m := re.FindStringSubmatch(e.Name()); m != nil {
			var v [3]int
			for i := 0; i < 3; i++ {
				v[i], _ = strconv.Atoi(m[i+1])
			}
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		t.Fatal("docs/releases дотор нэг ч vX.Y.Z.md алга — энэ тест юу ч хамгаалахгүй болно")
	}
	sort.Slice(vs, func(i, j int) bool {
		for k := 0; k < 3; k++ {
			if vs[i][k] != vs[j][k] {
				return vs[i][k] < vs[j][k]
			}
		}
		return false
	})
	v := vs[len(vs)-1]
	return strconv.Itoa(v[0]) + "." + strconv.Itoa(v[1]) + "." + strconv.Itoa(v[2])
}
