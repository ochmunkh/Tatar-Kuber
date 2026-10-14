package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// Aliased because golden_test.go declares a package-level `update` for its
	// -update flag, which an import of that name would collide with. The report
	// commands alias their imports the same way (htmlrep, jsonrep, sarifrep).
	updater "github.com/ochmunkh/tatar-kuber/internal/update"
)

// cmdUpdate — Scanner binary-уудыг татаж, баталгаажуулж шинэчилнэ (Doc #5 §5).
//
// The command layer stays thin, as it does for every other command: internal/
// update owns the download -> checksum -> signature -> install -> lock
// sequence, and this file only resolves flags and prints.
//
//	exit 0 — done (or --dry-run/--check printed), exit 2 — download or
//	verification failure (nothing installed), exit 3 — usage error.
func cmdUpdate(args []string) int {
	if _, code := setLang(args); code != 0 {
		return code
	}
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	scanners := fs.String("scanner", "", msg("flag.update.scanner"))
	dryRun := fs.Bool("dry-run", false, msg("flag.update.dryrun"))
	check := fs.Bool("check", false, msg("flag.update.check"))
	home := fs.String("home", "", msg("flag.update.home"))
	addLangFlag(fs, "flag.lang")
	_ = fs.Parse(args)

	h, err := resolveHome(*home)
	if err != nil {
		errln(err)
		return 2
	}
	opts := updater.Options{Home: h, Scanners: splitCSV(*scanners)}

	// --dry-run and --check are the same read-only resolve, printed two ways:
	// neither makes a request, and neither writes a file.
	if *dryRun || *check {
		plans, err := updater.Resolve(opts)
		if err != nil {
			return updateError(err)
		}
		if *dryRun {
			printDryRun(plans, updater.LockPath(h))
		} else {
			printCheck(plans, updater.LockPath(h))
		}
		return 0
	}

	results, err := updater.Apply(context.Background(), opts)
	if err != nil {
		return updateError(err)
	}

	fmt.Print(msg("update.installed.header", len(results), updater.ToolsDir(h)))
	unsigned := 0
	for _, r := range results {
		fmt.Print(msg("update.installed", r.Plan.Scanner, r.Plan.Version, r.BinPath))
		if !r.SigChecked {
			unsigned++
		}
	}
	fmt.Println(msg("update.lock.wrote", updater.LockPath(h)))
	// A verifier that checked nothing must never look like one that passed.
	if unsigned > 0 {
		warnln(msg("update.cosign.stub"))
	}
	return 0
}

// printDryRun — exactly what a real run would fetch, and nothing else happens.
func printDryRun(plans []updater.Plan, lockPath string) {
	fmt.Print(msg("update.dryrun.header"))
	for _, p := range plans {
		fmt.Print(msg("update.plan.scanner", p.Scanner, p.Version, p.Platform.String()))
		fmt.Print(msg("update.plan.url", p.URL))
		if p.Pinned() {
			fmt.Print(msg("update.plan.sha", p.SHA256))
		} else {
			fmt.Print(msg("update.plan.unpinned", lockPath))
		}
	}
	// A dry run describes what WOULD happen, and what would happen is that
	// nobody checks the signature.
	warnln(msg("update.cosign.stub"))
}

// printCheck — what is pinned against what tools.lock.yaml records as installed.
func printCheck(plans []updater.Plan, lockPath string) {
	fmt.Print(msg("update.check.header", lockPath))
	fmt.Printf("  %-11s %-10s %-10s\n", "SCANNER", msg("update.col.pinned"), msg("doctor.col.installed"))
	fmt.Println("  " + dash(11) + " " + dash(10) + " " + dash(10))
	for _, p := range plans {
		installed, state := p.Installed, msg("update.check.changes")
		switch {
		case installed == "":
			installed, state = "-", msg("update.check.absent")
		case installed == p.Version:
			state = msg("update.check.uptodate")
		}
		fmt.Print(msg("update.check.line", p.Scanner, p.Version, installed, state))
	}
}

// updateError — turn an update failure into the documented exit code. Only a
// scanner name the catalogue does not know is a usage error; everything else
// (refused pin, checksum mismatch, HTTP failure, unpacking) is a runtime
// failure that installed nothing.
func updateError(err error) int {
	var unknown *updater.UnknownScannerError
	if errors.As(err, &unknown) {
		errln(msg("err.update.scanner.unknown", unknown.Name, strings.Join(unknown.Known, ", ")))
		return 3
	}
	errln(err)
	return 2
}

// resolveHome — TATAR-Kuber-ийн home замыг олно.
// Дараалал: --home флаг > $TATAR_HOME > <user home>/.tatar-kuber.
func resolveHome(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := strings.TrimSpace(os.Getenv("TATAR_HOME")); env != "" {
		return env, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".tatar-kuber"), nil
}
