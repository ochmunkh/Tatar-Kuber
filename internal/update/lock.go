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
	Version string    `yaml:"version"`
	SHA256  SHA256Set `yaml:"sha256"`
	Cosign  string    `yaml:"cosign"`

	// Installed — the version Apply actually put on disk, written ONLY by
	// Apply. Kept separate from Version because Version is a pin: a
	// hand-written tools.lock.yaml, or one shipped with the repo, names the
	// version that SHOULD be installed. Reading `installed` off `version` made
	// `update --check` report a scanner as installed and up to date when
	// nothing had ever been downloaded.
	Installed string `yaml:"installed,omitempty"`
}

// SHA256Set — one scanner's checksums, keyed by platform ("linux/amd64").
//
// A release publishes a DIFFERENT artefact per platform, so a single checksum
// pins exactly one of them. The lock shipped with this repo is copied to every
// machine, and while it carried one value that value was true on linux/amd64
// and a MISMATCH everywhere else: a refusal that read as corruption rather
// than as "nobody pinned this platform".
//
// A bare string is still accepted, because that is what `update` wrote before
// this change. Such a file was produced by update ON the machine reading it,
// so the value is taken to belong to the current platform; the next successful
// update rewrites it in the keyed form and the ambiguity goes away.
type SHA256Set struct {
	ByPlatform map[string]string
	Legacy     string
}

func (s *SHA256Set) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		s.Legacy = n.Value
		return nil
	}
	return n.Decode(&s.ByPlatform)
}

// Get — the checksum pinned for this platform, or "" when none is.
func (s SHA256Set) Get(p Platform) string {
	if v, ok := s.ByPlatform[p.String()]; ok {
		return v
	}
	return s.Legacy
}

// Set — record a checksum for one platform, leaving the others alone. A lock
// that has pins for four platforms must not lose three of them because an
// install ran on the fourth.
func (s *SHA256Set) Set(p Platform, sum string) {
	if s.ByPlatform == nil {
		s.ByPlatform = map[string]string{}
	}
	s.ByPlatform[p.String()] = sum
	s.Legacy = ""
}

// platforms — pinned platforms, sorted, for a stable file.
func (s SHA256Set) platforms() []string {
	out := make([]string, 0, len(s.ByPlatform))
	for k := range s.ByPlatform {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Lock — ~/.tatar-kuber/tools.lock.yaml, in the shape Doc #6 §7 documents.
//
// It is both input and output: `tatar-kuber update` installs the version the
// lock pins ("бүх scanner-ыг lock хувилбар руу", Doc #5 §5) and rewrites the
// file with what it actually installed. Checksums are keyed by platform: the
// copy shipped with the repo is read on every platform, so one value cannot
// serve them all.
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
	b.WriteString("# version / sha256 pin one scanner release. sha256 is keyed by platform and\n")
	b.WriteString("# is the checksum of the DOWNLOADED ARTEFACT (archive or bare binary) as the\n")
	b.WriteString("# upstream project publishes it. `update` refuses to install a scanner with\n")
	b.WriteString("# no pin for the platform it is running on.\n")
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
		if plats := e.SHA256.platforms(); len(plats) > 0 {
			fmt.Fprintf(&b, "    sha256:\n")
			for _, pl := range plats {
				fmt.Fprintf(&b, "      %-13s %q\n", pl+":", e.SHA256.ByPlatform[pl])
			}
		} else {
			// No pin at all (checkov today): an empty map and an empty string
			// are the same state, and both have to round-trip.
			fmt.Fprintf(&b, "    sha256:  %q\n", e.SHA256.Legacy)
		}
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
