// Package cli implements the TATAR-Kuber command dispatch.
// Skeleton нь stdlib (flag)-ээр; production-д spf13/cobra руу шилжинэ.
package cli

import (
	"fmt"
	"os"
)

// Version — build-time-д тохируулагдана (-ldflags).
var Version = "1.0.2-dev"

const usage = `TATAR-Kuber — Kubernetes security posture assessment framework

Ашиглах:
  tatar-kuber <command> [flags]

Commands:
  scan      Cluster/manifest шалгах эсвэл цуглуулсан raw-г нэгтгэж scan-result.json үүсгэнэ
  report    scan-result.json-оос тайлан (json|sarif|html) үүсгэнэ
  gate      scan-result.json-ыг .tatar-kuber.yaml бодлоготой тулгаж CI-д pass/fail (exit code)
  doctor    Scanner binary-ууд суусан эсэх, хувилбар, горимыг шалгана
  verify-lab expected-findings.json-той тулгаж regression шалгана
  update    (төлөвлөсөн, v2) Scanner binary-уудыг татаж, баталгаажуулж шинэчилнэ
  version   Хувилбар харуулна

Жишээ:
  tatar-kuber doctor
  tatar-kuber scan --kubeconfig ~/.kube/config --namespace prod -o ./out   # Live Mode B
  tatar-kuber scan --raw-dir ./raw --cluster prod -o ./out                 # Offline (Mode A)
  tatar-kuber report --input ./out/scan-result.json -o html --out report.html
  tatar-kuber gate --input ./out/scan-result.json --fail-on high              # CI gate
`

// Execute — entrypoint.
func Execute() int {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		return 3
	}
	switch os.Args[1] {
	case "scan":
		return cmdScan(os.Args[2:])
	case "report":
		return cmdReport(os.Args[2:])
	case "doctor":
		return cmdDoctor(os.Args[2:])
	case "gate":
		return cmdGate(os.Args[2:])
	case "verify-lab":
		return cmdVerifyLab(os.Args[2:])
	case "update":
		fmt.Fprintln(os.Stderr, "update: v1-д хэрэгжээгүй (төлөвлөгөө: download -> checksum/cosign баталгаажуулалт -> tools.lock.yaml). Одоогоор scanner-уудыг өөрөө суулгаж `tatar-kuber doctor`-оор шалгана уу.")
		return 2
	case "version":
		fmt.Printf("TATAR-Kuber %s\n", Version)
		return 0
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "тодорхойгүй команд: %s\n\n", os.Args[1])
		fmt.Print(usage)
		return 3
	}
}
