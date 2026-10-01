package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/canonical"
)

// ── CLI-ийн мессежийн каталог ────────────────────────────────────────────────
//
// v1.0.3 хүртэл binary-ийн БҮХ гаралт монголоор хатуу бичигдсэн байв: тайлан нь
// `--lang en|mn` -ээр хоёр хэлээр гардаг атлаа тэр тайланг гаргасан хэрэгсэл
// өөрөө нэг л хэлээр ярьдаг байсан. Одоо ГАРАЛТЫН ХЭЛ БҮХ КОМАНДАД НЭГДСЭН:
// default нь АНГЛИ, `--lang mn` (эсвэл $TATAR_LANG=mn) нь монгол руу сэлгэнэ.
// Монгол гаралт БҮРЭН хэвээр — доорх mn бичвэрүүд нь өмнөх кодын яг тэр мөрүүд.
//
// Бичвэр бүр НЭГ газар, ID-аар: флагийн if/else тарааж эхэлмэгц хоёр хэл
// чимээгүй зөрдөг (тайлангийн labelsEN/labelsMN аль хэдийн үүнийг харуулсан).
// Хэлний сонголтыг canonical.I18n хийнэ — registry-ийн title/remediation яг
// үүгээр л сонгогддог тул хоёр дахь, зэрэгцээ механизм үүсэхгүй: mn байхгүй бол
// ЧИМЭЭГҮЙ хоосон мөр биш, en рүү унана.
//
// Шинэ бичвэр нэмэхэд: энд ID-тайгаа бүртгэж, msg-ээр ID-аар нь дуудна.
// messages_test.go нь (1) дуудагдсан ID бүр каталогт байгаа, (2) каталогийн
// бичлэг бүр en-тэй, (3) mn нь зөвхөн awaitingMN-д ил бүртгэгдсэн үед дутуу
// байж болно, (4) хэрэглэгдэхээ больсон ID үлдээгүй гэдгийг шалгана.

// uiLangs — CLI-ийн гаралт дэмждэг хэлүүд (эрэмбэ нь алдааны мөрөнд гарна).
// Эхнийх нь default.
var uiLangs = []string{"en", "mn"}

// uiLang — одоогийн гаралтын хэл. Команд бүр эхлэхдээ setLang-ээр тавьдаг тул
// дуудлагын дараалалаас хамаарахгүй (тест команд бүрийг шууд дууддаг).
var uiLang = uiLangs[0]

// msg — ID-аар бичвэр авч, шаардвал форматлана. ID нь каталогт байхгүй бол
// (энэ нь тестээр баригдана) хоосон мөр биш, ID-г нь буцаана — алдаа нүдэнд
// харагдах ёстой, нуугдах ёсгүй.
func msg(id string, a ...any) string {
	txt, ok := catalog[id]
	if !ok {
		return id
	}
	s := txt.Get(uiLang)
	if len(a) == 0 {
		return s
	}
	return fmt.Sprintf(s, a...)
}

// errln / warnln — орчуулсан угтвартай нэг мөр stderr-т.
func errln(a ...any)  { fmt.Fprintln(os.Stderr, append([]any{msg("label.error")}, a...)...) }
func warnln(a ...any) { fmt.Fprintln(os.Stderr, append([]any{msg("label.warn")}, a...)...) }

// setLang — CLI-ийн гаралтын хэлийг тогтооно.
// Дараалал: --lang флаг > $TATAR_LANG > en. Энэ нь resolveRegistry-ийн
// (--registry > $TATAR_REGISTRY > default) дараалалтай санаатайгаар ижил.
//
// Флагийг flag.FlagSet-ЭЭС ӨМНӨ уншина: флаг бүрийн тайлбар (`--help`) өөрөө
// орчуулагдсан байх ёстой тул FlagSet угсрах мөчид хэл аль хэдийн мэдэгдсэн
// байх шаардлагатай. Тиймээс энэ нь жижиг, зориудаар хялбар уншигч: `--lang mn`,
// `--lang=mn`, нэг зураастай хувилбаруудыг таних ба `--`-ийн дараахыг хардаггүй
// (Go-ийн parser ч тэнд зогсдог). Утга нь дараагийн аргумент байх тул
// `--cluster --lang mn` гэх мэт гажиг бичиглэлийг андуурч болзошгүй — тэр нь
// аль ч тохиолдолд буруу дуудлага.
//
// explicit — хэрэглэгч хэлээ ТОДОРХОЙ зааж өгсөн эсэх (флаг эсвэл орчны
// хувьсагчаар). `report` үүгээр л "тайлангийн хэлийг сэлгэх үү, эсвэл scan-д
// сонгосон хэлээр нь үлдээх үү" гэдгээ шийддэг.
//
// Танигдаагүй хэл нь ХЭРЭГЛЭЭНИЙ алдаа (exit 3) — `report --lang de` өмнө нь
// яг ингэж хариулдаг байсан гэрээг хэвээр үлдээв.
func setLang(args []string) (explicit bool, code int) {
	uiLang = uiLangs[0]

	val := ""
	if env := strings.TrimSpace(os.Getenv("TATAR_LANG")); env != "" {
		val, explicit = env, true
	}
	if v, ok := langFromArgs(args); ok {
		val, explicit = v, true
	}
	if !explicit {
		return false, 0
	}
	if !knownLang(val) {
		// Хэл нь өөрөө танигдаагүй тул энэ мөр default (англи) хэлээр гарна.
		errln(msg("err.lang.unknown", val, strings.Join(uiLangs, ", ")))
		return false, 3
	}
	uiLang = val
	return true, 0
}

// stripLeadingLang — команд сонгогдохоос ӨМНӨ бичигдсэн глобал `--lang` хосыг
// аргументаас хасна. setLang нь утгыг УНШдаг ч хасдаггүй байсан тул
// `tatar-kuber --lang mn --help` нь os.Args[1] == "--lang" болж "тодорхойгүй
// команд" гэж exit 3 буцаадаг байв — тусламжийн бичвэр болон дээрх тайлбар
// хоёулаа ажиллана гэж амласан хэрнээ.
//
// ЗӨВХӨН эхэнд байгаа хосыг хасна: `report --lang mn` дэх флагийг тухайн
// командын өөрийн FlagSet боловсруулах ёстой тул хөндөхгүй.
func stripLeadingLang(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--lang" || a == "-lang":
			if len(args) > 1 {
				args = args[2:] // `--lang mn`
			} else {
				args = args[1:] // утгагүй — flag сан нь дараа нь гомдоллоно
			}
		case strings.HasPrefix(a, "--lang=") || strings.HasPrefix(a, "-lang="):
			args = args[1:] // `--lang=mn`
		default:
			return args
		}
	}
	return args
}

func knownLang(v string) bool {
	for _, l := range uiLangs {
		if l == v {
			return true
		}
	}
	return false
}

// langFromArgs — args дотроос --lang-ийн утгыг олно. Утгагүй `--lang` (мөрийн
// сүүлд) нь ЭНД биш, flag parser-т баригдана (exit 2) — exit code-ийн гэрээг
// өөрчлөхгүйн тулд зориуд орхив.
//
// Давтагдсан бол СҮҮЛЧИЙНХ нь хүчинтэй, Go-ийн flag сангийнхтай ижил. Энэ нь
// `tatar-kuber --lang mn doctor --lang en` дээр л мэдэгддэг: Execute глобал
// флагийг командын аргументын өмнө буцааж наадаг тул хоёулаа жагсаалтад орно.
// Эхнийхийг нь авбал setLang "mn" гэж хэлэх атал командын өөрийн FlagSet "en"
// гэж уншиж, нэг дуудлага дотор хоёр өөр хариулт үүснэ.
func langFromArgs(args []string) (string, bool) {
	found, ok := "", false
	for i, a := range args {
		if a == "--" {
			return found, ok
		}
		name, val, hasVal := strings.Cut(a, "=")
		if name != "-lang" && name != "--lang" {
			continue
		}
		if hasVal {
			found, ok = val, true
			continue
		}
		if i+1 < len(args) {
			found, ok = args[i+1], true
			continue
		}
		// Утгагүй, мөрийн сүүлд — flag parser-т үлдээнэ.
		return found, ok
	}
	return found, ok
}

// addLangFlag — --lang-ыг FlagSet-д бүртгэнэ: `--help`-д харагдах ба parser
// татгалзахгүйн тулд. Утгыг нь setLang аль хэдийн уншсан.
func addLangFlag(fs *flag.FlagSet, helpID string) {
	fs.String("lang", "", msg(helpID))
}

// awaitingMN — монгол хувилбар нь ХАРААХАН БИЧИГДЭЭГҮЙ бичвэрүүд.
//
// ОДООГООР ХООСОН: `update` (v2)-ийн бичвэрүүд ба `verify-lab`-ийн оношийн
// мөрүүд монголоор бичигдэж, жагсаалтаас хасагдав. Жагсаалтыг устгаагүй —
// энэ нь ДАРААГИЙН бичвэрт зориулсан хавх: `TestCatalogHasEveryLanguage` нь
// mn дутуу ID-г ЗААВАЛ энд бүртгэхийг шаардаж, бүртгэлтэй атлаа mn-тэй болсон
// ID-г мөн адил барина. Тиймээс орчуулгын цоорхой код дотор ил, тоологдохуйц
// хэвээр үлдэнэ. Орчуулгыг машинаар ХИЙХГҮЙ — mn дутуу үед гаралт хоосон мөр
// биш, en рүү унана.
//
// Утга нь орчуулах зүйлгүй (зөвхөн баганын зэрэгцүүлэлт, `url`, `sha256`)
// мөрүүд нь en/mn ижил бичигдсэн тул энд хэзээ ч ОРООГҮЙ.
var awaitingMN = map[string]bool{}

// catalog — CLI-ийн бүх хэрэглэгчид харагдах бичвэр. mn нь энэ өөрчлөлтөөс
// өмнөх кодын яг тэр мөрүүд (утга нь хөндөгдөөгүй), en нь шинээр нэмэгдсэн.
var catalog = map[string]canonical.I18n{
	// ── Ерөнхий угтвар ─────────────────────────────────────────────────────
	"label.error": {"en": "error:", "mn": "алдаа:"},
	"label.warn":  {"en": "warning:", "mn": "анхаар:"},

	// ── root ───────────────────────────────────────────────────────────────
	"usage": {"en": usageEN, "mn": usageMN},
	"err.command.unknown": {
		"en": "unknown command: %s",
		"mn": "тодорхойгүй команд: %s",
	},
	"err.lang.unknown": {
		"en": "unknown language '%s' (available: %s)",
		"mn": "'%s' хэл танигдсангүй (байгаа: %s)",
	},
	// ── Флагийн тайлбар ────────────────────────────────────────────────────
	"flag.lang": {
		"en": "output language: en | mn (default: en; $TATAR_LANG is honoured too)",
		"mn": "гаралтын хэл: en | mn (default: en; $TATAR_LANG-ыг ч хүлээж авна)",
	},
	"flag.report.lang": {
		"en": "output language: en | mn (default: en; without it the report itself keeps the language chosen at scan time)",
		"mn": "гаралтын хэл: en | mn (default: en; өгөөгүй бол тайлан өөрөө scan-д сонгосон хэлээрээ үлдэнэ)",
	},
	"flag.input": {
		"en": "path to scan-result.json",
		"mn": "scan-result.json зам",
	},
	"flag.registry": {
		"en": "path to canonical-controls.yaml",
		"mn": "canonical-controls.yaml зам",
	},

	"flag.scan.file": {
		"en": "local manifest/Helm path (Mode A)",
		"mn": "local manifest/Helm зам (Mode A)",
	},
	"flag.scan.kubeconfig": {
		"en": "kubeconfig file (Mode B)",
		"mn": "kubeconfig файл (Mode B)",
	},
	"flag.scan.context": {
		"en": "kubeconfig context (Mode B)",
		"mn": "kubeconfig context (Mode B)",
	},
	"flag.scan.namespace": {
		"en": "namespaces to limit to (comma-separated, Mode B)",
		"mn": "хязгаарлах namespace-ууд (таслалаар, Mode B)",
	},
	"flag.scan.rawdir": {
		"en": "directory of collected raw scanner JSON (offline ingest)",
		"mn": "цуглуулсан scanner raw JSON-уудын хавтас (offline ingest)",
	},
	"flag.scan.cluster": {
		"en": "cluster/target name (shown in the report)",
		"mn": "cluster/target нэр (тайланд)",
	},
	"flag.scan.outdir": {
		"en": "output DIRECTORY (long name: --out-dir)",
		"mn": "гаралтын ХАВТАС (бүтэн нэр: --out-dir)",
	},
	"flag.scan.outdir.long": {
		"en": "output DIRECTORY (long name of -o)",
		"mn": "гаралтын ХАВТАС (-o-ийн бүтэн нэр)",
	},
	"flag.scan.noraw": {
		"en": "do NOT keep the scanners' raw output under <out>/raw/ on a live scan (default: kept — evidence)",
		"mn": "live scan-д scanner-уудын түүхий гаралтыг <out>/raw/ дотор ХАДГАЛАХГҮЙ (default: хадгална — нотолгоо)",
	},
	"flag.scan.norollup": {
		"en": "do NOT move Pod-scoped findings to their owning controller (default: moved — one misconfiguration counted once)",
		"mn": "Pod хэмжээний finding-ийг эзэмшигч controller руу ЗӨӨХГҮЙ (default: зөөнө — нэг зөрчил нэг удаа тоологдоно)",
	},

	"flag.report.format": {
		"en": "format: json|sarif|html (long name: --format)",
		"mn": "формат: json|sarif|html (бүтэн нэр: --format)",
	},
	"flag.report.format.long": {
		"en": "format: json|sarif|html (long name of -o)",
		"mn": "формат: json|sarif|html (-o-ийн бүтэн нэр)",
	},
	"flag.report.out": {
		"en": "output file (default: stdout; report.html for html)",
		"mn": "гаралтын файл (default: stdout, html бол report.html)",
	},
	"flag.report.failon": {
		"en": "exit 1 if a finding at or above this severity exists: critical|high|medium|low (case-insensitive)",
		"mn": "энэ severity-с дээш finding байвал exit 1: critical|high|medium|low (үсгийн том/жижигт үл хамаарна)",
	},
	"flag.report.registry": {
		"en": "path to canonical-controls.yaml (used with --lang; default: embedded)",
		"mn": "canonical-controls.yaml зам (--lang-тай хамт; default: шигтгэсэн)",
	},

	"flag.gate.policy": {
		"en": "policy file",
		"mn": "бодлогын файл",
	},
	"flag.gate.failon": {
		"en": "severity threshold (overrides the file): critical|high|medium|low (case-insensitive)",
		"mn": "severity босго (файлыг дарна): critical|high|medium|low (үсгийн том/жижигт үл хамаарна)",
	},
	"flag.gate.minscore": {
		"en": "minimum cluster score (overrides the file; 0 = ignored)",
		"mn": "cluster score доод хязгаар (файлыг дарна; 0 = хэрэгсэхгүй)",
	},
	"flag.gate.baseline": {
		"en": "previous scan-result.json — fail only on NEW and WORSENED findings",
		"mn": "өмнөх scan-result.json — зөвхөн ШИНЭ ба ДОРДСОН олдворт унана",
	},

	"flag.diff.old": {
		"en": "previous scan-result.json (required)",
		"mn": "өмнөх scan-result.json (заавал)",
	},
	"flag.diff.new": {
		"en": "new scan-result.json (required)",
		"mn": "шинэ scan-result.json (заавал)",
	},
	"flag.diff.format": {
		"en": "output: text|json (long name: --format)",
		"mn": "гаралт: text|json (бүтэн нэр: --format)",
	},
	"flag.diff.format.long": {
		"en": "output: text|json (long name of -o)",
		"mn": "гаралт: text|json (-o-ийн бүтэн нэр)",
	},
	"flag.diff.failonnew": {
		"en": "exit 1 if a NEW finding is at or above this severity: critical|high|medium|low",
		"mn": "шинэ finding энэ severity-с дээш байвал exit 1: critical|high|medium|low",
	},
	"flag.diff.all": {
		"en": "print unchanged findings too",
		"mn": "өөрчлөгдөөгүй finding-үүдийг ч хэвлэх",
	},

	"flag.verify.expected": {
		"en": "path to expected-findings.json",
		"mn": "expected-findings.json зам",
	},

	"flag.update.scanner": {
		"en": "scanners to update (comma-separated; default: all)",
		"mn": "шинэчлэх scanner-ууд (таслалаар; default: бүгд)",
	},
	"flag.update.dryrun": {
		"en": "print what WOULD be downloaded and stop — nothing is downloaded, nothing is written",
		"mn": "юу татагдах БАЙСНЫГ хэвлээд зогсоно — юу ч татагдахгүй, юу ч бичигдэхгүй",
	},
	"flag.update.check": {
		"en": "compare the pinned versions with tools.lock.yaml and stop — nothing is downloaded, nothing is written",
		"mn": "пиннэсэн хувилбаруудыг tools.lock.yaml-тай тулгаад зогсоно — юу ч татагдахгүй, юу ч бичигдэхгүй",
	},
	"flag.update.home": {
		"en": "directory holding tools.lock.yaml and tools/ (default: ~/.tatar-kuber; $TATAR_HOME is honoured too)",
		"mn": "tools.lock.yaml ба tools/ хадгалагдах хавтас (default: ~/.tatar-kuber; $TATAR_HOME-ыг ч хүлээж авна)",
	},

	// ── util / pipeline ────────────────────────────────────────────────────
	"warn.threshold.unrecognised": {
		"en": "%s='%s' not recognised — ignored",
		"mn": "%s='%s' танигдсангүй — хэрэгсэхгүй",
	},
	"err.rawdir.empty": {
		"en": "no scanner raw JSON found in %s",
		"mn": "%s дотор scanner raw JSON олдсонгүй",
	},

	// ── scan ───────────────────────────────────────────────────────────────
	"scan.input.required": {
		"en": "scan: one of -f, --kubeconfig/--context or --raw-dir is required",
		"mn": "scan: -f, --kubeconfig/--context эсвэл --raw-dir шаардлагатай",
	},
	"scan.outdir.is.format": {
		"en": "scan -o/--out-dir expects an output DIRECTORY, not a format ('%s').\n" +
			"       A format belongs to the report: tatar-kuber %s --format %s\n" +
			"       If you really do want a directory named '%s': -o ./%s\n",
		"mn": "scan -o/--out-dir нь ГАРАЛТЫН ХАВТАС хүлээдэг, формат биш ('%s').\n" +
			"       Формат нь тайлангийн зүйл: tatar-kuber %s --format %s\n" +
			"       Үнэхээр '%s' нэртэй хавтас хэрэгтэй бол: -o ./%s\n",
	},
	"warn.raw.save.failed": {
		"en": "could not save the raw output:",
		"mn": "raw хадгалж чадсангүй:",
	},
	"warn.no.scanner.ran": {
		"en": "no scanner ran (check that the scanner binaries are installed with `tatar-kuber doctor`). Offline mode: --raw-dir",
		"mn": "ямар ч scanner ажиллаагүй (scanner binary суулгасан эсэхээ `tatar-kuber doctor`-оор шалгана уу). Offline горим: --raw-dir",
	},
	"warn.scanner.no.findings": {
		"en": "%s: ran but normalised 0 findings",
		"mn": "%s: ажилласан ч 0 finding normalize хийгдсэнгүй",
	},
	"warn.scanner.unmapped": {
		"en": " (rules with no canonical mapping: %s)",
		"mn": " (canonical зураглалгүй rule: %s)",
	},
	"scan.rollup": {
		"en": "rollup: %d pod-scoped findings moved to their owning controller (%d pods) — one misconfiguration is counted once; disable with --no-rollup\n",
		"mn": "rollup: %d pod-хэмжээний finding эзэмшигч controller руу зөөгдлөө (%d pod) — нэг зөрчил нэг удаа тоологдоно; болиулах: --no-rollup\n",
	},
	"scan.wrote": {
		"en": "scan-result.json written: %s",
		"mn": "scan-result.json бичигдлээ: %s",
	},

	// ── report ─────────────────────────────────────────────────────────────
	"report.parse.failed": {
		"en": "scan-result.json parse error:",
		"mn": "scan-result.json parse алдаа:",
	},
	"report.format.unknown": {
		"en": "unknown format:",
		"mn": "тодорхойгүй формат:",
	},
	"report.render.failed": {
		"en": "render error:",
		"mn": "render алдаа:",
	},
	"report.wrote": {
		"en": "report written: %s",
		"mn": "тайлан бичигдлээ: %s",
	},
	"report.lang.missing": {
		"en": "the registry has no '%s' (available: %s)",
		"mn": "registry-д '%s' хэл алга (байгаа: %s)",
	},
	"report.untranslatable": {
		"en": "%d findings are not in the registry — their titles stay in the scanner's own wording",
		"mn": "%d finding registry-д алга — гарчиг нь scanner-ийн эх хэлээрээ үлдэв",
	},

	// ── gate ───────────────────────────────────────────────────────────────
	"gate.parse.failed": {
		"en": "scan-result.json parse:",
		"mn": "scan-result.json parse:",
	},
	"gate.failon.unrecognised": {
		"en": "fail_on='%s' not recognised (critical|high|medium|low) — treated as 'high'",
		"mn": "fail_on='%s' танигдсангүй (critical|high|medium|low) — 'high' гэж үзнэ",
	},
	"gate.suppression.expires.invalid": {
		"en": "suppression '%s' has a malformed expires (%s) — it must be YYYY-MM-DD",
		"mn": "suppression '%s' expires формат буруу (%s) — YYYY-MM-DD байх ёстой",
	},
	"gate.suppression.expired": {
		"en": "suppression '%s' has expired (%s) — not re-enabled",
		"mn": "suppression '%s' хугацаа дууссан (%s) — дахин идэвхжсэнгүй",
	},
	"gate.suppression.unknown": {
		"en": "suppression '%s' points at a control that is NOT in the canonical registry — it may be a typo",
		"mn": "suppression '%s' canonical registry-д БАЙХГҮЙ control руу заасан — бичиглэлийн алдаа байж магадгүй",
	},
	"gate.suppression.unused": {
		"en": "suppression '%s' matched no finding — the issue may be fixed or the resource renamed (delete the stale rule)",
		"mn": "suppression '%s' ямар ч олдворт тохироогүй — асуудал зассан эсвэл resource дахин нэрлэгдсэн байж магадгүй (хуучирсан дүрмийг устгана уу)",
	},
	"gate.violations": {
		"en": "%d findings over the threshold:\n",
		"mn": "Босго давсан %d олдвор:\n",
	},
	"gate.passed": {
		"en": "✓ GATE PASSED",
		"mn": "✓ GATE PASSED",
	},
	"gate.failed": {
		"en": "✗ GATE FAILED —",
		"mn": "✗ GATE FAILED —",
	},
	"gate.reason.threshold": {
		"en": "%d findings at '%s' or above",
		"mn": "%d олдвор '%s' болон дээш түвшинд байна",
	},
	"gate.reason.minscore": {
		"en": "cluster score %d < required %d",
		"mn": "cluster score %d < шаардлагатай %d",
	},
	"gate.baseline.warn": {
		"en": "baseline — %s",
		"mn": "baseline — %s",
	},
	"gate.baseline.untrusted": {
		"en": "the baseline cannot be trusted (%s) — IGNORED, every finding counts",
		"mn": "baseline итгэх боломжгүй (%s) — ХЭРЭГСЭХГҮЙ, бүх олдворыг тооцно",
	},
	"gate.baseline.ignored": {
		"en": "(baseline ignored)",
		"mn": "(baseline хэрэгсэгдсэнгүй)",
	},
	"gate.baseline.note": {
		"en": "baseline: %d pre-existing findings not counted, new+worsened %d",
		"mn": "baseline: %d өмнөх олдвор тооцоогүй, шинэ+дордсон %d",
	},

	// ── diff ───────────────────────────────────────────────────────────────
	"diff.old.new.required": {
		"en": "--old and --new are required",
		"mn": "--old ба --new заавал",
	},
	"diff.parse": {
		"en": "%s parse: %v",
		"mn": "%s parse: %v",
	},
	"diff.header":    {"en": "TATAR-Kuber diff", "mn": "TATAR-Kuber diff"},
	"diff.score":     {"en": "Risk score", "mn": "Эрсдэлийн оноо"},
	"diff.findings":  {"en": "Findings", "mn": "Finding"},
	"diff.changes":   {"en": "Changes", "mn": "Өөрчлөлт"},
	"diff.scanners":  {"en": "Scanner coverage", "mn": "Scanner хамрах хүрээ"},
	"diff.warnings":  {"en": "Warnings", "mn": "Анхааруулга"},
	"diff.new":       {"en": "new", "mn": "шинэ"},
	"diff.fixed":     {"en": "fixed", "mn": "зассан"},
	"diff.worsened":  {"en": "worsened", "mn": "дордсон"},
	"diff.improved":  {"en": "improved", "mn": "сайжирсан"},
	"diff.unchanged": {"en": "unchanged", "mn": "хэвээр"},
	"diff.nochange":  {"en": "No changes.", "mn": "Өөрчлөлт алга."},
	"diff.identical": {
		"en": "identical result_hash — nothing moved.",
		"mn": "result_hash ижил — өгөгдөл огт хөдөлсөнгүй.",
	},
	"diff.regressed": {"en": "COVERAGE REGRESSED", "mn": "ХАМРАХ ХҮРЭЭ БУУРСАН"},
	"diff.failnew": {
		"en": "new finding at or above threshold",
		"mn": "шинэ finding нь босгоос өндөр",
	},
	"diff.legend": {
		"en": "+ new  ↑ worsened  − fixed  ↓ improved",
		"mn": "+ шинэ  ↑ дордсон  − зассан  ↓ сайжирсан",
	},

	// ── doctor ─────────────────────────────────────────────────────────────
	"doctor.header": {
		"en": "TATAR-Kuber doctor — scanner readiness\n\n",
		"mn": "TATAR-Kuber doctor — scanner бэлэн байдал\n\n",
	},
	"doctor.col.installed": {"en": "INSTALLED", "mn": "СУУСАН"},
	"doctor.col.version":   {"en": "VERSION", "mn": "ХУВИЛБАР"},
	"doctor.col.mode":      {"en": "MODE", "mn": "ГОРИМ"},
	"doctor.yes":           {"en": "yes", "mn": "тийм"},
	"doctor.no":            {"en": "no", "mn": "үгүй"},
	"doctor.none": {
		"en": "No scanner is installed. You can still use offline mode: tatar-kuber scan --raw-dir ./raw",
		"mn": "Ямар ч scanner суугаагүй байна. Offline горим ашиглаж болно: tatar-kuber scan --raw-dir ./raw",
	},
	"doctor.ready": {
		"en": "%d scanners ready. Live scan: tatar-kuber scan --kubeconfig ~/.kube/config\n",
		"mn": "%d scanner бэлэн. Live scan: tatar-kuber scan --kubeconfig ~/.kube/config\n",
	},

	// ── update ─────────────────────────────────────────────────────────────
	//
	// Багана/зэрэгцүүлэлтийн хэлбэрийг `doctor` оруулсан тул түүнийг дагана
	// (мөн "INSTALLED" баганын нэр нь тэндээс ДАХИН ашиглагдана — нэг үгийг
	// хоёр удаа орчуулах шалтгаан алга).
	"update.dryrun.header": {
		"en": "update — dry run: nothing is downloaded, nothing is written\n\n",
		"mn": "update — dry run: юу ч татагдахгүй, юу ч бичигдэхгүй\n\n",
	},
	"update.plan.scanner": {"en": "  %-11s %-10s %s\n", "mn": "  %-11s %-10s %s\n"},
	"update.plan.url":     {"en": "    url     %s\n", "mn": "    url     %s\n"},
	"update.plan.sha":     {"en": "    sha256  %s\n", "mn": "    sha256  %s\n"},
	"update.plan.unpinned": {
		"en": "    sha256  NOT PINNED — update would refuse to install this scanner (pin it in %s)\n",
		"mn": "    sha256  ПИННЭЭГҮЙ — update энэ scanner-ыг суулгахаас татгалзана (%s дотор пиннэнэ)\n",
	},
	"update.check.header": {
		"en": "update --check — the pinned versions against %s\n\n",
		"mn": "update --check — пиннэсэн хувилбаруудыг %s-тай тулгав\n\n",
	},
	"update.col.pinned": {"en": "PINNED", "mn": "ПИННЭСЭН"},
	"update.check.line": {"en": "  %-11s %-10s %-10s %s\n", "mn": "  %-11s %-10s %-10s %s\n"},
	"update.check.uptodate": {
		"en": "up to date",
		"mn": "шинэчлэх шаардлагагүй",
	},
	"update.check.absent": {
		"en": "not installed by update",
		"mn": "update-ээр суугаагүй",
	},
	"update.check.changes": {
		"en": "would be replaced",
		"mn": "солигдоно",
	},
	"update.installed.header": {
		"en": "update: %d scanner(s) verified and installed into %s\n",
		"mn": "update: %d scanner баталгаажиж %s дотор суулаа\n",
	},
	"update.installed": {
		"en": "  %-11s %-10s installed: %s\n",
		"mn": "  %-11s %-10s суусан: %s\n",
	},
	// Стаб нь баталгаажуулсан гэж ХЭЛЖ БОЛОХГҮЙ — энэ мөр нь гарын үсэг
	// шалгагдаагүйг ил хэлнэ (tools.lock.yaml ч мөн адил бичнэ).
	"update.cosign.stub": {
		"en": "cosign signature verification is NOT implemented yet (planned for v2) — a scanner is accepted " +
			"on its pinned SHA256 alone, and tools.lock.yaml records cosign: unverified for it",
		"mn": "cosign гарын үсгийн шалгалт ХАРААХАН ХЭРЭГЖЭЭГҮЙ (v2-т төлөвлөсөн) — scanner нь зөвхөн " +
			"пиннэсэн SHA256-аараа хүлээн зөвшөөрөгдөж, tools.lock.yaml-д cosign: unverified гэж бичигдэнэ",
	},
	"update.lock.wrote": {
		"en": "tools.lock.yaml written: %s",
		"mn": "tools.lock.yaml бичигдлээ: %s",
	},
	"err.update.scanner.unknown": {
		"en": "unknown scanner '%s' (known: %s)",
		"mn": "'%s' scanner танигдсангүй (байгаа: %s)",
	},

	// ── verify-lab ─────────────────────────────────────────────────────────
	//
	// Эдгээр нь энэ репогийн CLI-д хамгийн удаан англиар үлдсэн мөрүүд байв.
	// `%-8s` нь severity-гийн багана тул хэвээр — зэрэгцүүлэлт нь гаралтыг
	// нүдээр гүйлгэж уншихад хэрэгтэй.
	"verify.parse.result": {
		"en": "scan-result.json parse:",
		"mn": "scan-result.json parse:",
	},
	"verify.parse.expected": {
		"en": "expected-findings.json parse:",
		"mn": "expected-findings.json parse:",
	},
	"verify.scenario": {"en": "verify-lab: %s\n", "mn": "verify-lab: %s\n"},
	"verify.controls": {
		"en": "  controls: expected %d, missing %d\n",
		"mn": "  control: хүлээгдэх %d, дутуу %d\n",
	},
	"verify.findings": {
		"en": "  findings: actual %d\n",
		"mn": "  finding: бодит %d\n",
	},
	"verify.missing.header": {
		"en": "  MISSING controls:\n",
		"mn": "  ДУТУУ control:\n",
	},
	"verify.total": {
		"en": "  total findings: expected %d, actual %d\n",
		"mn": "  нийт finding: хүлээгдэх %d, бодит %d\n",
	},
	"verify.min": {
		"en": "  findings %d < expected min %d\n",
		"mn": "  finding %d < хүлээгдэх доод хязгаар %d\n",
	},
	"verify.count": {
		"en": "  %-8s expected %d, actual %d  [%s]\n",
		"mn": "  %-8s хүлээгдэх %d, бодит %d  [%s]\n",
	},
	"verify.fail": {"en": "RESULT: FAIL", "mn": "RESULT: FAIL"},
	"verify.pass": {"en": "RESULT: PASS", "mn": "RESULT: PASS"},
}

const usageEN = `TATAR-Kuber — Kubernetes security posture assessment framework

Usage:
  tatar-kuber <command> [flags]

Commands:
  scan      Scan a cluster/manifest, or ingest collected raw output, into scan-result.json
  report    Render scan-result.json as a report (json|sarif|html); --lang also switches the report itself
  gate      Check scan-result.json against the .tatar-kuber.yaml policy and pass/fail CI (exit code)
  diff      Compare two scan-result.json files: what is new / fixed / worsened
  doctor    Which scanner binaries are installed, their versions and supported modes
  verify-lab Check a scan against expected-findings.json (regression)
  update    Download, verify and update the scanner binaries
  version   Print the version

Global flags (accepted by every command):
  --lang en|mn   Output language (default: en). $TATAR_LANG is honoured too.

Examples:
  tatar-kuber doctor
  tatar-kuber scan --kubeconfig ~/.kube/config --namespace prod --out-dir ./out   # Live Mode B
  tatar-kuber scan --raw-dir ./raw --cluster prod --out-dir ./out                 # Offline (Mode A)
  tatar-kuber report --input ./out/scan-result.json --format html --out report.html
  tatar-kuber report --input ./out/scan-result.json --format html --lang mn --out mn.html # one scan, either language
  tatar-kuber gate --input ./out/scan-result.json --fail-on high              # CI gate
  tatar-kuber diff --old ./prev/scan-result.json --new ./out/scan-result.json # Trending

Note: scan's --out-dir is a DIRECTORY, report/diff's --format is a FORMAT.
Both still accept the older -o spelling (existing CI keeps working).

Exit codes (they matter in CI):
  0  success / gate passed
  1  policy or threshold violation — gate, diff --fail-on-new,
     report --fail-on, verify-lab FAIL, doctor (no scanner installed)
  2  runtime error — input unreadable/malformed, or an unrecognised flag
     (Go's flag parser returns it before the command runs)
  3  usage error — unknown command, format or language, or a missing required flag
`

const usageMN = `TATAR-Kuber — Kubernetes security posture assessment framework

Ашиглах:
  tatar-kuber <command> [flags]

Commands:
  scan      Cluster/manifest шалгах эсвэл цуглуулсан raw-г нэгтгэж scan-result.json үүсгэнэ
  report    scan-result.json-оос тайлан (json|sarif|html) үүсгэнэ; --lang нь тайлангийн хэлийг ч сэлгэнэ
  gate      scan-result.json-ыг .tatar-kuber.yaml бодлоготой тулгаж CI-д pass/fail (exit code)
  diff      Хоёр scan-result.json-ыг тулгаж юу шинэ / зассан / дордсоныг харуулна
  doctor    Scanner binary-ууд суусан эсэх, хувилбар, горимыг шалгана
  verify-lab expected-findings.json-той тулгаж regression шалгана
  update    Scanner binary-уудыг татаж, баталгаажуулж шинэчилнэ
  version   Хувилбар харуулна

Ерөнхий флаг (бүх команд хүлээж авна):
  --lang en|mn   Гаралтын хэл (default: en). $TATAR_LANG-ыг ч хүлээж авна.

Жишээ:
  tatar-kuber doctor
  tatar-kuber scan --kubeconfig ~/.kube/config --namespace prod --out-dir ./out   # Live Mode B
  tatar-kuber scan --raw-dir ./raw --cluster prod --out-dir ./out                 # Offline (Mode A)
  tatar-kuber report --input ./out/scan-result.json --format html --out report.html
  tatar-kuber report --input ./out/scan-result.json --format html --lang mn --out mn.html # нэг scan, өөр хэл
  tatar-kuber gate --input ./out/scan-result.json --fail-on high              # CI gate
  tatar-kuber diff --old ./prev/scan-result.json --new ./out/scan-result.json # Trending

Тэмдэглэл: scan-ийн --out-dir нь ХАВТАС, report/diff-ийн --format нь ФОРМАТ.
Хоёул -o гэсэн хуучин бичиглэлээ хэвээр хүлээж авна (CI эвдрэхгүй).

Exit code (CI-д хамаарна):
  0  амжилттай / gate давсан
  1  бодлого эсвэл босго зөрчигдсөн — gate, diff --fail-on-new,
     report --fail-on, verify-lab FAIL, doctor (ямар ч scanner суугаагүй)
  2  ажиллагааны алдаа — оролт уншигдсангүй/эвдэрсэн, эсвэл танигдаагүй флаг
     (танигдаагүй флагийг Go-ийн flag parser команд ажиллахаас өмнө буцаана)
  3  хэрэглээний алдаа — команд, формат, хэл танигдсангүй, эсвэл заавал флаг дутуу
`
