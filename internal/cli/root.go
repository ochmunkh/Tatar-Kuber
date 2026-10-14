// Package cli implements the TATAR-Kuber command dispatch.
// Skeleton нь stdlib (flag)-ээр; production-д spf13/cobra руу шилжинэ.
package cli

import (
	"fmt"
	"os"
)

// Version — build-time-д тохируулагдана (-ldflags).
var Version = "1.0.3-dev"

// Execute — entrypoint.
func Execute() int {
	// Хэлийг эхлээд: usage болон "тодорхойгүй команд" хоёр нь команд сонгогдохоос
	// ӨМНӨ хэвлэгддэг тул `tatar-kuber --lang mn --help` ажиллах ёстой.
	if _, code := setLang(os.Args[1:]); code != 0 {
		return code
	}
	// Глобал `--lang` хосыг командын нэр ОЛОХЫН ТУЛД хасна — эс тэгвээс
	// os.Args[1] нь "--lang" хэвээр үлдэж, доорх switch түүнийг команд гэж үзнэ.
	rest := stripLeadingLang(os.Args[1:])
	// ...гэхдээ команд руу дамжуулахдаа БУЦААЖ НААНА. Команд бүр setLang-ыг
	// дахин дууддаг (`report --lang de` нь хаана ч бичигдсэн хэрэглээний алдаа
	// байхын тулд), тэр дуудлага эхлээд uiLang-ыг default руу буцаадаг. Флагийг
	// хасчихвал хоёр дахь дуудлага түүнийг олохгүй, `--lang mn doctor` нь
	// англиар хэвлэдэг байв — харин `doctor --lang mn` монголоор. `--lang`-ыг
	// команд бүр өөрийн FlagSet дээрээ бүртгүүлдэг тул наасан нь зүгээр.
	lead := os.Args[1 : len(os.Args)-len(rest)]
	args := append([]string{os.Args[0]}, rest...)
	if len(args) < 2 {
		fmt.Print(msg("usage"))
		return 3
	}
	cmdArgs := append(append([]string{}, lead...), args[2:]...)

	switch args[1] {
	case "scan":
		return cmdScan(cmdArgs)
	case "report":
		return cmdReport(cmdArgs)
	case "doctor":
		return cmdDoctor(cmdArgs)
	case "gate":
		return cmdGate(cmdArgs)
	case "diff":
		return cmdDiff(cmdArgs)
	case "verify-lab":
		return cmdVerifyLab(cmdArgs)
	case "update":
		return cmdUpdate(cmdArgs)
	case "version":
		fmt.Printf("TATAR-Kuber %s\n", Version)
		return 0
	case "-h", "--help", "help":
		fmt.Print(msg("usage"))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s\n\n", msg("err.command.unknown", os.Args[1]))
		fmt.Print(msg("usage"))
		return 3
	}
}
