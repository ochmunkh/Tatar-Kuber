package update

import (
	"runtime"
	"sort"
	"strings"
)

// Archive — the shape of the artefact a release publishes for one platform.
type Archive string

const (
	ArchiveRaw   Archive = "raw" // the asset IS the binary
	ArchiveTarGz Archive = "tar.gz"
	ArchiveZip   Archive = "zip"
)

// Platform — the os/arch a scanner binary is built for.
type Platform struct{ OS, Arch string }

// CurrentPlatform — the machine this binary is running on.
func CurrentPlatform() Platform { return Platform{OS: runtime.GOOS, Arch: runtime.GOARCH} }

func (p Platform) String() string { return p.OS + "/" + p.Arch }

func (p Platform) zero() bool { return p.OS == "" && p.Arch == "" }

// asset — one downloadable artefact. {v} is replaced by the version, without a
// leading "v" (the tag carries its own prefix inside the URL where one exists).
type asset struct {
	URL     string
	Archive Archive
}

// tool — one scanner in the built-in release catalogue.
//
// Version is the DEFAULT pin only: tools.lock.yaml wins whenever it carries an
// entry, because the lock is what makes an install reproducible and auditable.
type tool struct {
	Name    string
	Version string
	Assets  map[string]asset // keyed by Platform.String()
}

// catalogue — where each scanner's releases live and how they are packaged.
//
// This is deliberately URL shape + version only, and carries NO checksums. An
// expected checksum is a supply-chain assertion: it has to be produced by a
// human who checked it against what the upstream project published, and it
// belongs in tools.lock.yaml where it is reviewable and diffable. A checksum
// compiled into this binary would be a pin nobody ever reviews.
//
// The versions below were refreshed against each project's latest stable
// release on 2026-09-30, and tools.lock.yaml at the repo root carries the
// checksums that were cross-checked against what each project published.
// Nothing installs without a pinned checksum either way, so a stale default
// here can only ever produce a refusal, never a bad binary.
//
// A package-level var rather than a const so the tests can substitute a
// catalogue that points at a httptest server: no test ever reaches the network.
var catalogue = []tool{
	{
		Name:    "trivy",
		Version: "0.74.0",
		Assets: map[string]asset{
			"linux/amd64":  {URL: "https://github.com/aquasecurity/trivy/releases/download/v{v}/trivy_{v}_Linux-64bit.tar.gz", Archive: ArchiveTarGz},
			"linux/arm64":  {URL: "https://github.com/aquasecurity/trivy/releases/download/v{v}/trivy_{v}_Linux-ARM64.tar.gz", Archive: ArchiveTarGz},
			"darwin/amd64": {URL: "https://github.com/aquasecurity/trivy/releases/download/v{v}/trivy_{v}_macOS-64bit.tar.gz", Archive: ArchiveTarGz},
			"darwin/arm64": {URL: "https://github.com/aquasecurity/trivy/releases/download/v{v}/trivy_{v}_macOS-ARM64.tar.gz", Archive: ArchiveTarGz},
		},
	},
	{
		Name: "kubescape",
		// v4 renamed every asset: the v3 names (kubescape-ubuntu-latest,
		// kubescape-arm64-macos-latest) no longer exist on any release.
		Version: "4.0.15",
		Assets: map[string]asset{
			"linux/amd64":  {URL: "https://github.com/kubescape/kubescape/releases/download/v{v}/kubescape_{v}_linux_amd64", Archive: ArchiveRaw},
			"linux/arm64":  {URL: "https://github.com/kubescape/kubescape/releases/download/v{v}/kubescape_{v}_linux_arm64", Archive: ArchiveRaw},
			"darwin/amd64": {URL: "https://github.com/kubescape/kubescape/releases/download/v{v}/kubescape_{v}_darwin_amd64", Archive: ArchiveRaw},
			"darwin/arm64": {URL: "https://github.com/kubescape/kubescape/releases/download/v{v}/kubescape_{v}_darwin_arm64", Archive: ArchiveRaw},
		},
	},
	{
		Name: "checkov",
		// The version is in the TAG only; the asset filenames carry none.
		Version: "3.3.20",
		Assets: map[string]asset{
			"linux/amd64":  {URL: "https://github.com/bridgecrewio/checkov/releases/download/{v}/checkov_linux_X86_64.zip", Archive: ArchiveZip},
			"linux/arm64":  {URL: "https://github.com/bridgecrewio/checkov/releases/download/{v}/checkov_linux_arm64.zip", Archive: ArchiveZip},
			"darwin/amd64": {URL: "https://github.com/bridgecrewio/checkov/releases/download/{v}/checkov_darwin_X86_64.zip", Archive: ArchiveZip},
		},
	},
	{
		Name:    "popeye",
		Version: "0.22.1",
		Assets: map[string]asset{
			"linux/amd64":  {URL: "https://github.com/derailed/popeye/releases/download/v{v}/popeye_linux_amd64.tar.gz", Archive: ArchiveTarGz},
			"linux/arm64":  {URL: "https://github.com/derailed/popeye/releases/download/v{v}/popeye_linux_arm64.tar.gz", Archive: ArchiveTarGz},
			"darwin/amd64": {URL: "https://github.com/derailed/popeye/releases/download/v{v}/popeye_darwin_amd64.tar.gz", Archive: ArchiveTarGz},
			"darwin/arm64": {URL: "https://github.com/derailed/popeye/releases/download/v{v}/popeye_darwin_arm64.tar.gz", Archive: ArchiveTarGz},
		},
	},
}

// Scanners — every scanner the catalogue knows, in catalogue order (which is
// the pipeline order the rest of the CLI already prints things in).
func Scanners() []string {
	out := make([]string, 0, len(catalogue))
	for _, t := range catalogue {
		out = append(out, t.Name)
	}
	return out
}

// lookup — the catalogue entry for a scanner name.
func lookup(name string) (tool, bool) {
	for _, t := range catalogue {
		if t.Name == name {
			return t, true
		}
	}
	return tool{}, false
}

// platforms — the platforms a tool publishes an asset for, sorted, for the
// "no asset for this platform" message.
func (t tool) platforms() []string {
	out := make([]string, 0, len(t.Assets))
	for p := range t.Assets {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// expand — an asset URL with the version substituted in.
func expand(url, version string) string {
	return strings.ReplaceAll(url, "{v}", version)
}
