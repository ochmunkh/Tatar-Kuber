package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ochmunkh/tatar-kuber/internal/orchestrator"
)

// Хувилбар ХОЁР газар амьдардаг бөгөөд тэдгээр нь ӨӨР ӨӨР замаар тавигддаг:
//
//   - cli.Version          — release-д goreleaser ldflags-аар оруулна
//     (-X .../internal/cli.Version={{ .Version }})
//   - orchestrator.Version — const, ldflags ХҮРДЭГГҮЙ; гараар шинэчилнэ
//
// Тиймээс release гаргахдаа const-ыг мартвал: `tatar-kuber version` нь 1.0.3
// гэж хэлэх атлаа scan-result.json-ийн metadata.tatar_version ба SARIF-ийн
// driver.version нь 1.0.2 хэвээр үлдэнэ. Аудитын хэрэгсэл өөрийн гарал үүслийг
// худал хэлэх нь чимээгүй бөгөөд хамгийн хортой алдааны төрөл. Энэ тест яг
// тэрийг барина.
func TestVersionsAgree(t *testing.T) {
	cliVer := semverCore(Version)
	if cliVer != orchestrator.Version {
		t.Fatalf("хувилбар зөрөв: cli.Version=%q (цөм: %q) != orchestrator.Version=%q\n"+
			"release гаргахдаа ХОЁУЛАНГ нь шинэчилнэ: internal/cli/root.go ба internal/orchestrator/orchestrator.go",
			Version, cliVer, orchestrator.Version)
	}
	if strings.Count(orchestrator.Version, ".") != 2 || strings.ContainsAny(orchestrator.Version, "-+v") {
		t.Errorf("orchestrator.Version=%q нь x.y.z хэлбэртэй, угтвар/дагаваргүй байх ёстой", orchestrator.Version)
	}
}

// semverCore — "1.0.3-dev" -> "1.0.3"; "1.0.3" -> "1.0.3".
func semverCore(v string) string {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i]
	}
	return v
}

// Хоёр хувилбар таарч байгаад л болохгүй: ХААНА байгаа нь бас чухал.
//
// v1.0.3 гарсны дараа master нь `1.0.3-dev` дээр 14 commit үлдсэн. Тэр модоос
// build хийсэн хүн "1.0.3" гэж уншина — гэтэл энэ нь v1.0.3 БИШ. Тайлан бүрийн
// metadata.tatar_version мөн адил худал болно. Аудитын артефакт дээр гарал
// үүслийн алдаа нь буруу олдвороос ч аюултай: улаан болдоггүй.
//
// Дүрэм: master нь ҮРГЭЛЖ хамгийн сүүлд гарсан хувилбараас ӨМНӨ явна.
// Release гаргах commit нь release note-оо нэмэхийн ЗЭРЭГЦЭЭ дараагийн
// `-dev` рүү шилжүүлэх ёстой; тэгэхгүй бол энэ тест унана.
func TestDevVersionIsAheadOfLastRelease(t *testing.T) {
	dir := filepath.Join("..", "..", "docs", "releases")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("docs/releases уншиж чадсангүй: %v", err)
	}
	re := regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)\.md$`)
	var latest [3]int
	var latestName string
	for _, e := range entries {
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		var v [3]int
		for i := 0; i < 3; i++ {
			v[i], _ = strconv.Atoi(m[i+1])
		}
		if latestName == "" || less(latest, v) {
			latest, latestName = v, e.Name()
		}
	}
	if latestName == "" {
		t.Fatal("docs/releases дотор нэг ч vX.Y.Z.md алга — энэ тест юу ч хамгаалахгүй болно")
	}

	cur, ok := parseSemver(semverCore(Version))
	if !ok {
		t.Fatalf("cli.Version=%q нь x.y.z хэлбэрт буухгүй байна", Version)
	}
	if !less(latest, cur) {
		t.Fatalf("master нь гарсан хувилбараас хойш явж байна: cli.Version=%q, "+
			"гэтэл %s аль хэдийн гарсан.\n"+
			"Энэ модоос build хийсэн хүн %s гэж уншина — тэр нь %s БИШ.\n"+
			"internal/cli/root.go ба internal/orchestrator/orchestrator.go хоёрыг "+
			"дараагийн хувилбар руу шилжүүл.",
			Version, strings.TrimSuffix(latestName, ".md"),
			semverCore(Version), strings.TrimSuffix(latestName, ".md"))
	}
}

func parseSemver(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// less — a < b семантик хувилбарын харьцуулалт.
func less(a, b [3]int) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
