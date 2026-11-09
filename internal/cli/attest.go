package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/attest"
	"github.com/ochmunkh/tatar-kuber/internal/canonical"
	"github.com/ochmunkh/tatar-kuber/internal/finding"
)

// cmdAttest — гараар батлах механизм.
//
// ЯАГААД: `docs/coverage.md` нь ямар ч scanner rule зурагдаагүй control-ыг
// нэрээр нь ил гаргадаг. Тэр жагсаалт бол ЗАРЛАГДСАН цоорхой — ил зарласан нь
// шударга, гэхдээ хаагдсан гэсэн үг биш. Энэ команд бол түүнийг хаах цорын
// ганц зам.
//
//	attest create  — шалгагддаггүй control-уудын загвар YAML гаргана
//	attest apply   — бөглөсөн файлыг шалгаад scan үр дүнд нэгтгэнэ
//
// Findings-д ГАР ХҮРЭХГҮЙ: attestation нь тусдаа `attestations[]` болж орно.
// Тиймээс `metadata.result_hash` (зөвхөн findings-ээс тооцогддог) хүчинтэй
// хэвээр үлдэнэ — гараар бичсэн хариулт scanner-ийн нотолгоог чимээгүй
// өөрчилж чадахгүй байх ёстой.
func cmdAttest(args []string) int {
	if _, code := setLang(args); code != 0 {
		return code
	}
	sub, rest := firstNonFlag(args)
	switch sub {
	case "create":
		return attestCreate(rest)
	case "apply":
		return attestApply(rest)
	case "":
		errln(msg("attest.subcommand.missing"))
		return 3
	default:
		errln(msg("attest.subcommand.unknown", sub))
		return 3
	}
}

// firstNonFlag — эхний туг биш аргументыг (дэд команд) олж, үлдсэнийг буцаана.
// Глобал `--lang mn attest apply` нь `attest --lang mn apply` болж ирдэг тул
// дэд команд нь эхний байранд байх баталгаагүй.
func firstNonFlag(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 0 && a[0] == '-' {
			// `--lang mn` хэлбэрийн хосыг алгасна (`--lang=mn` нь нэг үг).
			if (a == "--lang" || a == "-lang") && i+1 < len(args) {
				i++
			}
			continue
		}
		out := append([]string{}, args[:i]...)
		return a, append(out, args[i+1:]...)
	}
	return "", args
}

func attestCreate(args []string) int {
	fs := flag.NewFlagSet("attest create", flag.ExitOnError)
	out := fs.String("out", "attestations.yaml", msg("flag.attest.out"))
	registry := fs.String("registry", "", msg("flag.registry"))
	all := fs.Bool("all", false, msg("flag.attest.all"))
	cluster := fs.String("cluster", "", msg("flag.attest.cluster"))
	addLangFlag(fs, "flag.lang")
	_ = fs.Parse(args)

	reg, code := openRegistry(*registry)
	if code != 0 {
		return code
	}

	controls := attestableControls(reg, *all)
	now := time.Now()
	labels := attest.Labels{
		Header:     msg("attest.template.header"),
		Generated:  msg("attest.template.generated"),
		Decision:   msg("attest.template.decision"),
		Rationale:  msg("attest.template.rationale"),
		AttestedBy: msg("attest.template.by"),
		Expires:    msg("attest.template.expires"),
		Evidence:   msg("attest.template.evidence"),
		Scope:      msg("attest.template.scope"),
		NoGaps:     msg("attest.template.nogaps"),
		Severity:   msg("attest.template.severity"),
	}
	body := attest.Template(labels, controls, *cluster,
		now.Format(attest.DateLayout),
		now.AddDate(1, 0, 0).Format(attest.DateLayout))

	if dir := filepath.Dir(*out); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			errln(err)
			return 2
		}
	}
	if err := os.WriteFile(*out, body, 0o600); err != nil {
		errln(err)
		return 2
	}
	fmt.Println(msg("attest.created", *out, len(controls)))
	if len(controls) == 0 && !*all {
		fmt.Println(msg("attest.nogaps"))
	}
	return 0
}

func attestApply(args []string) int {
	fs := flag.NewFlagSet("attest apply", flag.ExitOnError)
	input := fs.String("input", "scan-result.json", msg("flag.input"))
	file := fs.String("attestations", "attestations.yaml", msg("flag.attest.file"))
	outDir := fs.String("out-dir", "", msg("flag.attest.outdir"))
	registry := fs.String("registry", "", msg("flag.registry"))
	addLangFlag(fs, "flag.lang")
	_ = fs.Parse(args)

	res, code := loadScan(*input)
	if code != 0 {
		return code
	}
	f, err := attest.Load(*file)
	if err != nil {
		errln(err)
		return 2
	}

	reg, code := openRegistry(*registry)
	if code != 0 {
		return code
	}
	known := map[string]attest.Control{}
	for _, c := range reg.Controls {
		known[c.ID] = attest.Control{
			ID:       c.ID,
			Title:    c.Title.Get(uiLang),
			Severity: finding.NormalizeSeverity(c.DefaultSeverity),
		}
	}

	// Шалгалт нь ХАТУУ: алдаатай attestation-ыг хэсэгчлэн хэрэглэхгүй. Хагас
	// хэрэгжсэн баталгаажуулалт нь аль control хамгаалагдсаныг хэн ч хэлж
	// чадахгүй төлөв үүсгэнэ.
	if errs := attest.Validate(f, known); len(errs) > 0 {
		for _, e := range errs {
			errln(e)
		}
		errln(msg("attest.invalid", len(errs)))
		return 2
	}

	now := time.Now()
	attest.Apply(&res, f, known, now)

	// Хугацаа дууссаныг ЭНД хэлнэ: apply нь "болов" гэж хэвлээд дараа нь gate
	// дээр гэнэт цоорхой нээгдэх нь гэнэтийн байх ёсгүй.
	for _, a := range res.Attestations {
		if a.Status == finding.AttestExpired {
			warnln(msg("attest.expired", a.Control, a.Expires))
		}
	}

	dir := *outDir
	if dir == "" {
		dir = filepath.Dir(*input)
	}
	if c := writeResult(res, dir); c != 0 {
		return c
	}
	s := res.Summary.Attested
	fmt.Println(msg("attest.applied", s.Compliant, s.NonCompliant, s.NotApplicable, s.Expired))
	if s.NonCompliant > 0 {
		fmt.Println(msg("attest.noncompliant.note", s.NonCompliant))
	}
	return 0
}

// attestableControls — загварт орох control-ууд. Default нь ЗӨВХӨН
// шалгагддаггүй нь: тэд л зарлагдсан цоорхой. --all нь идэвхтэй бүгдийг.
func attestableControls(reg *canonical.Registry, all bool) []attest.Control {
	var out []attest.Control
	for _, c := range reg.Controls {
		if c.Status == "deprecated" {
			continue
		}
		mapped := 0
		for _, rules := range c.Mappings {
			mapped += len(rules)
		}
		if !all && mapped > 0 {
			continue
		}
		out = append(out, attest.Control{
			ID:       c.ID,
			Title:    c.Title.Get(uiLang),
			Severity: finding.NormalizeSeverity(c.DefaultSeverity),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// openRegistry — бүртгэлийг шийдэж ачаална (алдааны кодтой).
func openRegistry(flagPath string) (*canonical.Registry, int) {
	path, err := resolveRegistry(flagPath)
	if err != nil {
		errln(err)
		return nil, 2
	}
	reg, err := loadRegistry(path)
	if err != nil {
		errln(err)
		return nil, 2
	}
	return reg, 0
}
