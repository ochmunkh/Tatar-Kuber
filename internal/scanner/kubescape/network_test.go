package kubescape

import (
	"slices"
	"testing"
)

// What Kubescape is allowed to do on the network is part of the product's
// claim, so the two switches that limit it are pinned.
func TestBaseArgs_NeverSubmitsResults(t *testing.T) {
	args := baseArgs("/tmp/out.json")
	if !slices.Contains(args, "--keep-local") {
		t.Fatalf("--keep-local missing: %v", args)
	}
	if args[0] != "scan" || !slices.Contains(args, "/tmp/out.json") {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestBaseEnv_SkipsTheUpdateCheck(t *testing.T) {
	if !slices.Contains(baseEnv(), "KS_SKIP_UPDATE_CHECK=true") {
		t.Fatalf("update check must be skipped: %v", baseEnv())
	}
}
