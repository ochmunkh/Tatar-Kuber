package cli

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/ochmunkh/tatar-kuber/internal/scanner"
)

// cmdDoctor — Live Mode B-д шаардлагатай scanner binary-ууд суусан эсэхийг
// шалгаж, хувилбар болон дэмждэг горимыг харуулна.
func cmdDoctor(args []string) int {
	if _, code := setLang(args); code != 0 {
		return code
	}
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	registry := fs.String("registry", "", msg("flag.registry"))
	addLangFlag(fs, "flag.lang")
	_ = fs.Parse(args)

	regPath, err := resolveRegistry(*registry)
	if err != nil {
		errln(err)
		return 3
	}
	p, err := buildPipeline(regPath)
	if err != nil {
		errln(err)
		return 2
	}

	fmt.Print(msg("doctor.header"))
	fmt.Printf("  %-11s %-9s %-12s %s\n", "SCANNER", msg("doctor.col.installed"), msg("doctor.col.version"), msg("doctor.col.mode"))
	fmt.Println("  " + dash(11) + " " + dash(9) + " " + dash(12) + " " + dash(14))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	available := 0
	for _, a := range p.Adapters() {
		ok, _ := a.Available()
		status := msg("doctor.no")
		ver := "-"
		if ok {
			available++
			status = msg("doctor.yes")
			if v, err := a.Version(ctx); err == nil && v != "" {
				ver = v
			}
		}
		fmt.Printf("  %-11s %-9s %-12s %s\n", a.Name(), status, ver, modeStr(a))
	}

	fmt.Println()
	switch {
	case available == 0:
		fmt.Println(msg("doctor.none"))
		return 1
	default:
		fmt.Print(msg("doctor.ready", available))
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
