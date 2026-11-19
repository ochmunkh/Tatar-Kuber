package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ochmunkh/tatar-kuber/internal/safeio"
)

// rawManifestName — the integrity manifest saved beside the raw scanner output.
// The format is the one `sha256sum` writes and `sha256sum -c` reads, so the
// evidence can be re-checked with nothing but coreutils.
const rawManifestName = "SHA256SUMS"

// rawFiles — the files in a raw directory that the manifest covers.
var rawFiles = []string{"trivy.json", "kubescape.json", "checkov.json", "popeye.json", "versions.json", "inventory.json"}

func sumFile(path string) (string, error) {
	data, err := safeio.ReadFile(path, safeio.MaxScan)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// writeRawManifest records the SHA-256 of every raw file present in dir. The
// result_hash covers findings only; without this the raw scanner output the
// findings were derived from can be edited afterwards without a trace.
func writeRawManifest(dir string) error {
	var b strings.Builder
	for _, n := range rawFiles {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		sum, err := sumFile(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, n)
	}
	return os.WriteFile(filepath.Join(dir, rawManifestName), []byte(b.String()), 0o600)
}

// verifyRawManifest checks dir against its SHA256SUMS. No manifest means a
// hand-collected directory and is accepted; a manifest that disagrees with the
// files, or lists a file that is gone, is an error. Files that exist but are
// not listed are rejected too: they would be ingested without being covered.
func verifyRawManifest(dir string) error {
	f, err := os.Open(filepath.Join(dir, rawManifestName)) // #nosec G304 -- fixed name inside --raw-dir
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	listed := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return fmt.Errorf("%s: malformed line %q", rawManifestName, line)
		}
		name := parts[1]
		if filepath.Base(name) != name {
			return fmt.Errorf("%s: %q is not a plain file name", rawManifestName, name)
		}
		got, err := sumFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("%s lists %s but it cannot be read: %w", rawManifestName, name, err)
		}
		if got != strings.ToLower(parts[0]) {
			return fmt.Errorf("%s: %s was modified after the scan (expected %s…, found %s…)", rawManifestName, name, parts[0][:12], got[:12])
		}
		listed[name] = true
	}
	if err := sc.Err(); err != nil {
		return err
	}
	var extra []string
	for _, n := range rawFiles {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil && !listed[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		return fmt.Errorf("%s does not cover %s — added after the scan", rawManifestName, strings.Join(extra, ", "))
	}
	return nil
}
