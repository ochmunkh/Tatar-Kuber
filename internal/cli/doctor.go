package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// cmdDoctor — Live Mode B-д шаардлагатай scanner binary-ууд суусан эсэхийг
// шалгаж, хувилбар болон дэмждэг горимыг харуулна.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	registry := fs.String("registry", "", "canonical-controls.yaml зам")
	_ = fs.Parse(args)

	regPath, err := resolveRegistry(*registry)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 3
	}
	p, err := buildPipeline(regPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "алдаа:", err)
		return 2
	}

	fmt.Print("TATAR-Kuber doctor — scanner бэлэн байдал\n\n")
	fmt.Printf("  %-11s %-9s %-12s %s\n", "SCANNER", "СУУСАН", "ХУВИЛБАР", "ГОРИМ")
	fmt.Println("  " + dash(11) + " " + dash(9) + " " + dash(12) + " " + dash(14))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	available := 0
	for _, a := range p.Adapters() {
		ok, _ := a.Available()
		status := "үгүй"
		ver := "-"
		if ok {
			available++
			status = "тийм"
			if v, err := a.Version(ctx); err == nil && v != "" {
				ver = v
			}
		}
		fmt.Printf("  %-11s %-9s %-12s %s\n", a.Name(), status, ver, modeStr(a))
	}

	fmt.Println()
	switch {
	case available == 0:
		fmt.Println("Ямар ч scanner суугаагүй байна. Offline горим ашиглаж болно: tatar-kuber scan --raw-dir ./raw")
		return 1
	default:
		fmt.Printf("%d scanner бэлэн. Live scan: tatar-kuber scan --kubeconfig ~/.kube/config\n", available)
		return 0
	}
}

func modeStr(a scanner.ScannerAdapter) string {
	local := a.Supports(scanner.ModeLocal)
	remote := a.Supports(scanner.ModeRemote)
	switch {
	case local && remote:
		return "local+remote"
	case remote:
		return "remote (live)"
	case local:
		return "local"
	default:
		return "-"
	}
}

func dash(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '-'
	}
	return string(b)
}
