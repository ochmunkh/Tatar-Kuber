package update

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Cosign status values recorded in the lock file. There is deliberately no
// third state: either a signature was checked and accepted, or it was not
// checked at all, and today it is never checked (see verify.go).
const (
	CosignVerified   = "verified"
	CosignUnverified = "unverified"
)

// LockEntry — one scanner's pin.
//
// sha256 is the checksum of the DOWNLOADED ARTEFACT (the archive, or the bare
// binary where the release publishes one), not of the extracted binary: the
// artefact is what upstream publishes a checksum for, so that is the only value
// a human can compare against a release page.
type LockEntry struct {
	Version string `yaml:"version"`
	SHA256  string `yaml:"sha256"`
	Cosign  string `yaml:"cosign"`

	// Installed — the version Apply actually put on disk, written ONLY by
	// Apply. Kept separate from Version because Version is a pin: a
	// hand-written tools.lock.yaml, or one shipped with the repo, names the
	// version that SHOULD be installed. Reading `installed` off `version` made
	// `update --check` report a scanner as installed and up to date when
	// nothing had ever been downloaded.
	Installed string `yaml:"installed,omitempty"`
}

// Lock — ~/.tatar-kuber/tools.lock.yaml, in the shape Doc #6 §7 documents.
//
// It is both input and output: `tatar-kuber update` installs the version the
// lock pins ("бүх scanner-ыг lock хувилбар руу", Doc #5 §5) and rewrites the
// file with what it actually installed. The file is per-machine, which is why
// one sha256 per tool is enough — it pins this platform's artefact.
type Lock struct {
	Tools map[string]LockEntry `yaml:"tools"`
}

// LockPath / ToolsDir — the two paths under ~/.tatar-kuber that update owns
// (Doc #5 §8).
func LockPath(home string) string { return filepath.Join(home, "tools.lock.yaml") }
func ToolsDir(home string) string { return filepath.Join(home, "tools") }

// LoadLock — read tools.lock.yaml. A missing file is not an error: it means
// nothing is pinned yet, and Resolve turns that into a refusal rather than a
// download.
func LoadLock(path string) (Lock, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from the user's own --home
	if err != nil {
		if os.IsNotExist(err) {
			return Lock{Tools: map[string]LockEntry{}}, nil
		}
		return Lock{}, err
	}
	var l Lock
	if err := yaml.Unmarshal(data, &l); err != nil {
		return Lock{}, fmt.Errorf("tools.lock.yaml parse (%s): %w", path, err)
	}
	if l.Tools == nil {
		l.Tools = map[string]LockEntry{}
	}
	return l, nil
}

// SaveLock — write tools.lock.yaml.
//
// Written by hand rather than through yaml.Marshal for two reasons: the header
// has to explain what `cosign: "unverified"` means (a marshaller cannot emit
// comments), and the key order has to be stable so that a lock file which did
// not change produces no diff.
func SaveLock(path string, l Lock) error {
	names := make([]string, 0, len(l.Tools))
	for n := range l.Tools {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("# tools.lock.yaml — written by `tatar-kuber update`.\n")
	b.WriteString("#\n")
	b.WriteString("# version / sha256 pin one scanner release. sha256 is the checksum of the\n")
	b.WriteString("# DOWNLOADED ARTEFACT (archive or bare binary) as the upstream project\n")
	b.WriteString("# publishes it, and `update` refuses to install a scanner that has none.\n")
	b.WriteString("#\n")
	b.WriteString("# cosign: \"" + CosignUnverified + "\" means the signature was NOT checked.\n")
	b.WriteString("# cosign verification is not implemented yet (planned for v2), so this file\n")
	b.WriteString("# never says \"" + CosignVerified + "\" today.\n")
	b.WriteString("#\n")
	b.WriteString("# installed: written ONLY by a successful `update`. version is what SHOULD\n")
	b.WriteString("# be installed; installed is what is. A pin with no installed line has never\n")
	b.WriteString("# been downloaded, and `update --check` says so rather than reporting it as\n")
	b.WriteString("# up to date.\n")
	b.WriteString("tools:\n")
	for _, n := range names {
		e := l.Tools[n]
		fmt.Fprintf(&b, "  %s:\n", n)
		fmt.Fprintf(&b, "    version: %q\n", e.Version)
		fmt.Fprintf(&b, "    sha256:  %q\n", e.SHA256)
		fmt.Fprintf(&b, "    cosign:  %q\n", e.Cosign)
		// Omitted rather than written empty: an absent line is how a pin that
		// has never been installed is represented, and writing installed: ""
		// would make the two states look different in the file but identical
		// once parsed.
		if e.Installed != "" {
			fmt.Fprintf(&b, "    installed: %q\n", e.Installed)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
