package cli

import (
	"flag"
	"fmt"
	"sort"

	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// cmdTop — "69 олдвор байна, хаанаас эхлэх вэ?" гэсэн асуултын хариу.
//
// ЯАГААД ЭНЭ КОМАНД: scan-result.json нь юу буруу байгааг бүрэн хэлдэг ч
// ЯМАР ДАРААЛЛААР засахыг хэлдэггүй. Хэрэглэгч эхний өдөр жагсаалтыг хараад
// хаанаас ч эхлэхгүй байх нь gate-ийг унтраах хамгийн түгээмэл шалтгаан.
//
// Шинэ оноо ЗОХИОГООГҮЙ. Хоёр хүснэгт хоёулаа файл дотор аль хэдийн байгаа
// зүйлийг тоолно, мөн тоолох дүрмээ хэвлэнэ — тайлбаргүй эрэмбэ нь
// тайлбаргүй оноотой адил муу.
//
//	resource — нэг ажлын ачааллыг засахад хэдэн олдвор арилах вэ
//	control  — нэг зөрчил хэдэн ажлын ачаалалд давтагдаж байна вэ
//
// Энэ хоёр нь өөр хоёр асуулт: эхнийх "хамгийн муу нь хэн бэ", хоёр дахь нь
// "нэг удаа засахад хамгийн их үр дүн өгөх нь юу вэ" (template, policy,
// base image). Хоёулаа хэрэгтэй, нэг нь нөгөөгөө орлохгүй.
//
//	exit 0 — хэвлэв, exit 2 — файл уншиж чадсангүй.
func cmdTop(args []string) int {
	if _, code := setLang(args); code != 0 {
		return code
	}
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	input := fs.String("input", "scan-result.json", msg("flag.input"))
	limit := fs.Int("limit", 10, msg("flag.top.limit"))
	addLangFlag(fs, "flag.lang")
	_ = fs.Parse(args)

	res, code := loadScan(*input)
	if code != 0 {
		return code
	}
	if len(res.Findings) == 0 {
		fmt.Println(msg("top.empty"))
		return 0
	}

	fmt.Print(msg("top.header", len(res.Findings)))
	printTopResources(res.Findings, *limit)
	printTopControls(res.Findings, *limit)
	return 0
}

// bucket — нэг түлхүүрийн доорх олдворуудын хураангуй.
type bucket struct {
	key       string
	extra     string // namespace эсвэл severity
	findings  int
	weight    int // severity rank-уудын нийлбэр
	worst     finding.Severity
	resources map[string]bool
}

func (b bucket) resourceCount() int { return len(b.resources) }

func collect(fs []finding.Finding, keyOf func(finding.Finding) (string, string)) []bucket {
	idx := map[string]*bucket{}
	for _, f := range fs {
		k, extra := keyOf(f)
		b, ok := idx[k]
		if !ok {
			b = &bucket{key: k, extra: extra, resources: map[string]bool{}}
			idx[k] = b
		}
		b.findings++
		b.weight += finding.Rank(f.Severity)
		if finding.Rank(f.Severity) > finding.Rank(b.worst) {
			b.worst = f.Severity
		}
		b.resources[f.Namespace+"/"+f.Resource] = true
	}
	out := make([]bucket, 0, len(idx))
	for _, b := range idx {
		out = append(out, *b)
	}
	return out
}

func printTopResources(fs []finding.Finding, limit int) {
	bs := collect(fs, func(f finding.Finding) (string, string) { return f.Resource, f.Namespace })
	// Жин нь эхлээд: 1 CRITICAL (5) нь 2 LOW (4) -ээс дээш. Тэнцвэл олдворын
	// тоо, дараа нь нэр — эрэмбэ детерминистик байх ёстой.
	sort.Slice(bs, func(i, j int) bool {
		if bs[i].weight != bs[j].weight {
			return bs[i].weight > bs[j].weight
		}
		if bs[i].findings != bs[j].findings {
			return bs[i].findings > bs[j].findings
		}
		return bs[i].key < bs[j].key
	})
	fmt.Print(msg("top.resources.header"))
	fmt.Printf("  %-38s %-14s %8s  %-9s %6s\n", msg("top.col.resource"), msg("top.col.namespace"),
		msg("top.col.findings"), msg("top.col.worst"), msg("top.col.weight"))
	fmt.Println("  " + dash(38) + " " + dash(14) + " " + dash(8) + "  " + dash(9) + " " + dash(6))
	for i, b := range bs {
		if i >= limit {
			fmt.Print(msg("top.more", len(bs)-limit))
			break
		}
		fmt.Printf("  %-38s %-14s %8d  %-9s %6d\n", trunc(b.key, 38), trunc(b.extra, 14), b.findings, b.worst, b.weight)
	}
}

func printTopControls(fs []finding.Finding, limit int) {
	bs := collect(fs, func(f finding.Finding) (string, string) {
		return f.CanonicalControl, string(f.Severity)
	})
	// Энд хамрах хүрээ нь эхлээд: олон resource-д давтагдсан нэг зөрчил бол
	// template эсвэл policy-гийн асуудал — нэг удаа засахад бүгд арилна.
	sort.Slice(bs, func(i, j int) bool {
		if bs[i].resourceCount() != bs[j].resourceCount() {
			return bs[i].resourceCount() > bs[j].resourceCount()
		}
		if finding.Rank(bs[i].worst) != finding.Rank(bs[j].worst) {
			return finding.Rank(bs[i].worst) > finding.Rank(bs[j].worst)
		}
		return bs[i].key < bs[j].key
	})
	fmt.Print(msg("top.controls.header"))
	fmt.Printf("  %-20s %-10s %10s %9s\n", msg("top.col.control"), msg("top.col.worst"),
		msg("top.col.resources"), msg("top.col.findings"))
	fmt.Println("  " + dash(20) + " " + dash(10) + " " + dash(10) + " " + dash(9))
	for i, b := range bs {
		if i >= limit {
			fmt.Print(msg("top.more", len(bs)-limit))
			break
		}
		fmt.Printf("  %-20s %-10s %10d %9d\n", b.key, b.worst, b.resourceCount(), b.findings)
	}
}

// trunc — баганын өргөнд багтаана. Урт нэрийг таслахдаа ТӨГСГӨЛИЙГ нь
// үлдээнэ: resource-ийн нэрийн ялгаатай хэсэг ихэвчлэн сүүлд байдаг.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return "…" + s[len(s)-(n-1):]
}
